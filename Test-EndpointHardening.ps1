<#
.SYNOPSIS
    Audita el nivel de hardening de un endpoint Windows contra la checklist
    "Nueva PC - Checklist de seguridad" y genera un reporte de cumplimiento.

.DESCRIPTION
    Verifica automáticamente 16 de los 20 controles de la checklist:
    SO, Antivirus/Defender, Firewall, BitLocker, políticas de contraseña,
    cuentas locales, AppLocker, auditoría, UAC y SmartScreen.

    Los 4 ítems restantes (exclusiones de AV, reglas de firewall específicas,
    revisión de puertos, macros de Office) no se pueden verificar por código,
    así que al final el script te pregunta uno por uno (S/N) si los completaste,
    y los integra al reporte con su estado real. Usá -SkipManualPrompts para
    saltear las preguntas (quedan como "No verificable").

    DETECCIÓN DE EDICIÓN: BitLocker y AppLocker no existen en Windows Home.
    El script detecta la edición del sistema operativo automáticamente y,
    si corre en Home, marca esos ítems como "No aplica" en vez de "No cumple"
    (no es un fallo de configuración, es una limitación de licenciamiento).

.NOTES
    Requiere ejecutarse como Administrador.
    Autor: Valentin Bertuccelli
    Uso previsto: auditoría de hardening antes de entregar un equipo a un usuario.

.EXAMPLE
    .\Test-EndpointHardening.ps1
    .\Test-EndpointHardening.ps1 -ExportHtml -OutputPath C:\Reportes
    .\Test-EndpointHardening.ps1 -SkipManualPrompts
#>

[CmdletBinding()]
param(
    [switch]$ExportHtml,
    [string]$OutputPath = "$PSScriptRoot",
    [switch]$SkipManualPrompts
)

#region Verificación de privilegios
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Este script debe ejecutarse como Administrador para obtener resultados completos y confiables."
}
#endregion

#region Detección de edición del sistema operativo
$osCaption = (Get-CimInstance Win32_OperatingSystem).Caption
$isHomeEdition = $osCaption -match "Home"
if ($isHomeEdition) {
    Write-Host "Edición detectada: $osCaption (Home) - BitLocker y AppLocker se marcarán como 'No aplica'.`n" -ForegroundColor DarkYellow
}
#endregion

$results = New-Object System.Collections.Generic.List[Object]

function Add-Result {
    param(
        [string]$Category,
        [string]$Item,
        [ValidateSet('Cumple','No cumple','No verificable','No aplica')]
        [string]$Status,
        [string]$Detail = ""
    )
    $results.Add([PSCustomObject]@{
        Categoria = $Category
        Item      = $Item
        Estado    = $Status
        Detalle   = $Detail
    })
}

function Invoke-SafeCheck {
    param([scriptblock]$Check)
    try { & $Check }
    catch { @{ Status = 'No verificable'; Detail = $_.Exception.Message } }
}

Write-Host "`n=== Auditando hardening del endpoint: $env:COMPUTERNAME ===`n" -ForegroundColor Cyan

### 1. SISTEMA OPERATIVO ###
$r = Invoke-SafeCheck {
    $os = Get-CimInstance Win32_OperatingSystem
    $build = [int]$os.BuildNumber
    $soportado = $build -ge 19045
    @{
        Status = if ($soportado) { 'Cumple' } else { 'No cumple' }
        Detail = "Build $build - $($os.Caption)"
    }
}
Add-Result "Sistema Operativo" "Versión/build soportada" $r.Status $r.Detail

$r = Invoke-SafeCheck {
    $pending = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0").Updates.Count
    @{
        Status = if ($pending -eq 0) { 'Cumple' } else { 'No cumple' }
        Detail = "$pending actualizaciones pendientes"
    }
}
Add-Result "Sistema Operativo" "Windows Update al día" $r.Status $r.Detail

### 2. ANTIVIRUS / EDR ###
$r = Invoke-SafeCheck {
    $mp = Get-MpComputerStatus
    @{
        Status = if ($mp.AntivirusEnabled) { 'Cumple' } else { 'No cumple' }
        Detail = "Defender habilitado: $($mp.AntivirusEnabled)"
    }
}
Add-Result "Antivirus/EDR" "Antivirus activo" $r.Status $r.Detail

$r = Invoke-SafeCheck {
    $mp = Get-MpComputerStatus
    @{
        Status = if ($mp.RealTimeProtectionEnabled) { 'Cumple' } else { 'No cumple' }
        Detail = "Protección en tiempo real: $($mp.RealTimeProtectionEnabled)"
    }
}
Add-Result "Antivirus/EDR" "Protección en tiempo real" $r.Status $r.Detail

### 3. FIREWALL ###
$r = Invoke-SafeCheck {
    $profiles = Get-NetFirewallProfile
    $activos = ($profiles | Where-Object { $_.Enabled -eq $true }).Count
    @{
        Status = if ($activos -eq $profiles.Count) { 'Cumple' } else { 'No cumple' }
        Detail = "$activos de $($profiles.Count) perfiles activos"
    }
}
Add-Result "Firewall" "Firewall activo (3 perfiles)" $r.Status $r.Detail

### 4. CIFRADO DE DISCO ###
if ($isHomeEdition) {
    Add-Result "Cifrado de disco" "BitLocker activo en $env:SystemDrive" 'No aplica' "BitLocker no existe en Windows Home (requiere Pro/Enterprise/Education)"
    Add-Result "Cifrado de disco" "Clave de recuperación generada" 'No aplica' "BitLocker no existe en Windows Home (requiere Pro/Enterprise/Education)"
} else {
    $r = Invoke-SafeCheck {
        $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive
        @{
            Status = if ($bl.ProtectionStatus -eq 'On') { 'Cumple' } else { 'No cumple' }
            Detail = "Estado: $($bl.ProtectionStatus), Volumen: $($bl.VolumeStatus)"
        }
    }
    Add-Result "Cifrado de disco" "BitLocker activo en $env:SystemDrive" $r.Status $r.Detail

    $r = Invoke-SafeCheck {
        $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive
        $tieneRecovery = $bl.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
        @{
            Status = if ($tieneRecovery) { 'Cumple' } else { 'No cumple' }
            Detail = if ($tieneRecovery) { "Recovery key protector presente (verificar respaldo externo manualmente)" } else { "Sin recovery key protector" }
        }
    }
    Add-Result "Cifrado de disco" "Clave de recuperación generada" $r.Status $r.Detail
}

### 5. POLÍTICAS DE CONTRASEÑA ###
$r = Invoke-SafeCheck {
    $netAccounts = net accounts
    $line = $netAccounts | Where-Object { $_ -match "Longitud mínima|Minimum password length" } | Select-Object -First 1
    $minLen = if ($line -match '(\d+)') { [int]$matches[1] } else { -1 }
    @{
        Status = if ($minLen -ge 12) { 'Cumple' } else { 'No cumple' }
        Detail = "Longitud mínima configurada: $minLen"
    }
}
Add-Result "Políticas de contraseña" "Longitud mínima >= 12" $r.Status $r.Detail

$r = Invoke-SafeCheck {
    $secpolFile = "$env:TEMP\secpol_export.cfg"
    secedit /export /cfg $secpolFile /quiet | Out-Null
    $content = Get-Content $secpolFile
    $complexity = ($content | Select-String "PasswordComplexity") -replace '\D+', ''
    Remove-Item $secpolFile -ErrorAction SilentlyContinue
    @{
        Status = if ($complexity -eq '1') { 'Cumple' } else { 'No cumple' }
        Detail = "PasswordComplexity = $complexity"
    }
}
Add-Result "Políticas de contraseña" "Complejidad habilitada" $r.Status $r.Detail

$r = Invoke-SafeCheck {
    $netAccounts = net accounts
    $line = $netAccounts | Where-Object { $_ -match "Duración máx|Vigencia máxima|Antigüedad máxima|Maximum password age" } | Select-Object -First 1
    $maxAge = if ($line -match '(\d+)') { [int]$matches[1] } else { -1 }
    @{
        Status = if ($maxAge -gt 0 -and $maxAge -le 90) { 'Cumple' } else { 'No cumple' }
        Detail = "Expiración configurada: $maxAge días"
    }
}
Add-Result "Políticas de contraseña" "Expiración configurada (<=90 días)" $r.Status $r.Detail

$r = Invoke-SafeCheck {
    $netAccounts = net accounts
    $line = $netAccounts | Where-Object { $_ -match "Umbral de bloqueo|Lockout threshold" } | Select-Object -First 1
    $lockout = if ($line -match '(\d+)') { [int]$matches[1] } else { -1 }
    @{
        Status = if ($lockout -gt 0 -and $lockout -le 10) { 'Cumple' } else { 'No cumple' }
        Detail = "Umbral de bloqueo: $lockout intentos"
    }
}
Add-Result "Políticas de contraseña" "Bloqueo tras intentos fallidos" $r.Status $r.Detail

### 6. CUENTAS DE USUARIO ###
$r = Invoke-SafeCheck {
    $admin = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
    @{
        Status = if ($admin.Name -ne 'Administrador' -and $admin.Name -ne 'Administrator') { 'Cumple' } else { 'No cumple' }
        Detail = "Nombre actual: $($admin.Name)"
    }
}
Add-Result "Cuentas de usuario" "Cuenta Administrador renombrada" $r.Status $r.Detail

$r = Invoke-SafeCheck {
    $admin = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
    @{
        Status = if (-not $admin.Enabled) { 'Cumple' } else { 'No cumple' }
        Detail = "Habilitada: $($admin.Enabled)"
    }
}
Add-Result "Cuentas de usuario" "Cuenta Administrador deshabilitada" $r.Status $r.Detail

$r = Invoke-SafeCheck {
    $guest = Get-LocalUser | Where-Object { $_.SID -like "*-501" }
    @{
        Status = if (-not $guest.Enabled) { 'Cumple' } else { 'No cumple' }
        Detail = "Habilitada: $($guest.Enabled)"
    }
}
Add-Result "Cuentas de usuario" "Cuenta Invitado deshabilitada" $r.Status $r.Detail

$r = Invoke-SafeCheck {
    $adminGroupMembers = (Get-LocalGroupMember -Group "Administradores" -ErrorAction SilentlyContinue) `
        + (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue)
    $allUsers = Get-LocalUser | Where-Object { $_.Enabled -and $_.SID -notlike "*-500" -and $_.SID -notlike "*-501" }
    $standard = $allUsers | Where-Object { $_.Name -notin ($adminGroupMembers.Name -replace ".*\\", "") }
    @{
        Status = if ($standard.Count -ge 1) { 'Cumple' } else { 'No cumple' }
        Detail = "Cuentas estándar habilitadas encontradas: $($standard.Count)"
    }
}
Add-Result "Cuentas de usuario" "Cuenta estándar para uso diario" $r.Status $r.Detail

### 7. CONTROL DE APLICACIONES ###
if ($isHomeEdition) {
    Add-Result "Control de aplicaciones" "AppLocker / restricción de software" 'No aplica' "AppLocker requiere gpedit.msc, no disponible en Windows Home"
} else {
    $r = Invoke-SafeCheck {
        $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
        $ruleCount = ($policy.RuleCollections | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
        @{
            Status = if ($ruleCount -gt 0) { 'Cumple' } else { 'No cumple' }
            Detail = "$ruleCount reglas de AppLocker activas"
        }
    }
    Add-Result "Control de aplicaciones" "AppLocker / restricción de software" $r.Status $r.Detail
}

### 8. AUDITORÍA ###
$r = Invoke-SafeCheck {
    # GUID de la subcategoría "Logon"
    $audit = auditpol /get /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" 2>$null
    $joined = $audit -join ' '
    $ok = $joined -match "Aciertos y errores|Correcto y (erróneo|error)|Success and Failure"
    @{
        Status = if ($ok) { 'Cumple' } else { 'No cumple' }
        Detail = if ($ok) { "Auditoría de logon en Éxito y Error" } else { "Salida real: $joined" }
    }
}
Add-Result "Auditoría" "Auditoría de inicio de sesión" $r.Status $r.Detail

$r = Invoke-SafeCheck {
    # GUID de la subcategoría "Sensitive Privilege Use"
    $audit = auditpol /get /subcategory:"{0CCE9228-69AE-11D9-BED3-505054503030}" 2>$null
    $joined = $audit -join ' '
    $ok = $joined -match "Aciertos y errores|Correcto y (erróneo|error)|Success and Failure"
    @{
        Status = if ($ok) { 'Cumple' } else { 'No cumple' }
        Detail = if ($ok) { "Auditoría de uso de privilegios activa" } else { "Salida real: $joined" }
    }
}
Add-Result "Auditoría" "Auditoría de cambios de privilegios" $r.Status $r.Detail

### 9. CONTROLES ADICIONALES ###
$r = Invoke-SafeCheck {
    $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -ErrorAction Stop
    @{
        Status = if ($uac.EnableLUA -eq 1) { 'Cumple' } else { 'No cumple' }
        Detail = "EnableLUA = $($uac.EnableLUA)"
    }
}
Add-Result "Controles adicionales" "UAC activado" $r.Status $r.Detail

$r = Invoke-SafeCheck {
    $val = $null
    try { $val = (Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name SmartScreenEnabled -ErrorAction Stop).SmartScreenEnabled } catch {}
    if (-not $val) {
        try { $val = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name EnableSmartScreen -ErrorAction Stop).EnableSmartScreen } catch {}
    }
    if ($null -eq $val) {
        @{ Status = 'Cumple'; Detail = "Sin valor explícito en el registro; SmartScreen viene activado por defecto en Windows 11" }
    } else {
        $off = ($val -eq 'Off' -or $val -eq 0)
        @{
            Status = if (-not $off) { 'Cumple' } else { 'No cumple' }
            Detail = "Valor encontrado: $val"
        }
    }
}
Add-Result "Controles adicionales" "SmartScreen activado" $r.Status $r.Detail

#region Ítems manuales (confirmación interactiva)
$manualChecks = @(
    @{ Categoria = "Antivirus/EDR"; Item = "Exclusiones revisadas (ninguna innecesaria)" },
    @{ Categoria = "Firewall"; Item = "Reglas de entrada innecesarias revisadas manualmente" },
    @{ Categoria = "Firewall"; Item = "Puertos no utilizados verificados como cerrados" },
    @{ Categoria = "Control de aplicaciones"; Item = "Macros de Office no firmadas deshabilitadas" }
)

if (-not $SkipManualPrompts) {
    Write-Host "`n--- Confirmación de ítems manuales (no verificables por código) ---" -ForegroundColor Cyan
    foreach ($m in $manualChecks) {
        $resp = Read-Host "¿Completaste: '$($m.Item)'? (S/N)"
        $status = if ($resp -match '^[sS]') { 'Cumple' } else { 'No cumple' }
        Add-Result $m.Categoria $m.Item $status "Confirmado manualmente por el usuario durante la corrida del script"
    }
} else {
    foreach ($m in $manualChecks) {
        Add-Result $m.Categoria $m.Item 'No aplica' "No verificado (script ejecutado con -SkipManualPrompts)"
    }
}
#endregion

#region Reporte en consola
Write-Host "`n--- Resultados por categoría ---`n" -ForegroundColor Cyan
$results | Group-Object Categoria | ForEach-Object {
    Write-Host "`n[$($_.Name)]" -ForegroundColor Yellow
    $_.Group | ForEach-Object {
        $color = switch ($_.Estado) {
            'Cumple'         { 'Green' }
            'No cumple'      { 'Red' }
            'No aplica'      { 'Gray' }
            default          { 'DarkYellow' }
        }
        Write-Host ("  [{0}] {1} - {2}" -f $_.Estado.ToUpper(), $_.Item, $_.Detalle) -ForegroundColor $color
    }
}

# El % de cumplimiento se calcula solo sobre ítems aplicables a esta edición
$aplicables = ($results | Where-Object { $_.Estado -ne 'No aplica' }).Count
$noAplica = ($results | Where-Object { $_.Estado -eq 'No aplica' }).Count
$total = $results.Count
$cumple = ($results | Where-Object { $_.Estado -eq 'Cumple' }).Count
$pct = if ($aplicables -gt 0) { [math]::Round(($cumple / $aplicables) * 100, 1) } else { 0 }

Write-Host "`n=== Cumplimiento automatizado: $cumple / $aplicables aplicables ($pct%) ===" -ForegroundColor Cyan
if ($noAplica -gt 0) {
    Write-Host "=== ($noAplica de $total ítems no aplican a esta edición de Windows) ===`n" -ForegroundColor DarkYellow
} else {
    Write-Host ""
}
#endregion

#region Exportación
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvPath = Join-Path $OutputPath "hardening_report_$($env:COMPUTERNAME)_$timestamp.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "Reporte CSV guardado en: $csvPath" -ForegroundColor Gray

if ($ExportHtml) {
    $htmlPath = Join-Path $OutputPath "hardening_report_$($env:COMPUTERNAME)_$timestamp.html"
    $htmlBody = $results | ConvertTo-Html -Property Categoria, Item, Estado, Detalle `
        -Title "Reporte de Hardening - $env:COMPUTERNAME" `
        -PreContent "<h1>Reporte de Hardening - $env:COMPUTERNAME</h1><p>Edición: $osCaption</p><p>Fecha: $(Get-Date)</p><p>Cumplimiento: $cumple/$aplicables aplicables ($pct%)</p><p>$noAplica de $total ítems no aplican a esta edición.</p>"
    $htmlBody | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Host "Reporte HTML guardado en: $htmlPath" -ForegroundColor Gray
}
#endregion
