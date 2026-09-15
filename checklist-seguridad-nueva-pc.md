# Checklist de Seguridad — Nueva PC (Endpoint Hardening)

> Uso: aplicar antes de entregar un equipo Windows a un usuario final.
> Marcar cada ítem al completarlo. El script `Test-EndpointHardening.ps1` verifica automáticamente los ítems marcados con un script=(S).
> Los ítems marcados con 🏠 no están disponibles en Windows **Home** (requieren Pro/Enterprise/Education). El script los detecta automáticamente y los marca como "No aplica" en vez de "No cumple".

## 1. Sistema Operativo
- [ ] (S) Windows Update instalado por completo, sin actualizaciones pendientes
- [ ] 🤖 Versión y build de Windows verificada (soportada / no EOL)

## 2. Antivirus / EDR
- [ ] 🤖 Windows Defender (u otra solución) activo y actualizado
- [ ] 🤖 Protección en tiempo real habilitada
- [ ] Exclusiones revisadas (ninguna innecesaria configurada)

## 3. Firewall
- [ ] 🤖 Firewall activo en los 3 perfiles (Dominio / Privado / Público)
- [ ] Reglas de entrada innecesarias deshabilitadas o eliminadas
- [ ] Puertos no utilizados verificados como cerrados

## 4. Cifrado de disco 🏠
- [ ] 🤖 BitLocker activado en la unidad del sistema (C:)
- [ ] 🤖 Clave de recuperación respaldada (Azure AD / AD / cuenta Microsoft / archivo seguro fuera del equipo)

## 5. Políticas de contraseña local
> En Home, `secpol.msc` no existe: usar `net accounts` por línea de comandos (misma función, sin GUI).
- [ ] 🤖 Longitud mínima de contraseña ≥ 12 caracteres
- [ ] 🤖 Complejidad de contraseña habilitada *(no configurable por comando en Home; requiere Pro o GPO)*
- [ ] 🤖 Expiración de contraseña configurada (ej. 90 días)
- [ ] 🤖 Bloqueo de cuenta tras intentos fallidos configurado (ej. 5 intentos)

## 6. Cuentas de usuario
> En Home, `lusrmgr.msc` no existe: usar los cmdlets de PowerShell (`Rename-LocalUser`, `Disable-LocalUser`, `New-LocalUser`), que dan el mismo resultado.
- [ ] 🤖 Cuenta "Administrador" local renombrada
- [ ] 🤖 Cuenta "Administrador" local deshabilitada
- [ ] 🤖 Cuenta "Invitado" deshabilitada
- [ ] 🤖 Cuenta estándar creada para uso diario (sin privilegios de admin)

## 7. Control de aplicaciones
- [ ] Macros de Office no firmadas deshabilitadas *(depende de Office, no de la edición de Windows)*
- [ ] 🤖 🏠 AppLocker o política de restricción de software configurada

## 8. Auditoría
> En Home, `secpol.msc` no existe: usar `auditpol` por línea de comandos (misma función, sin GUI).
- [ ] 🤖 Auditoría de inicio de sesión (éxito/fallo) activada
- [ ] 🤖 Auditoría de cambios de privilegios activada

## 9. Controles adicionales
- [ ] 🤖 UAC (Control de cuentas de usuario) activado
- [ ] 🤖 SmartScreen activado

---
**Total de ítems: 20** | Automatizables con script: 16 | Manuales: 4

**Notas del técnico:**
- La clave de recuperación de BitLocker es el ítem que más se olvida — sin ella, un fallo de hardware = pérdida total de datos.
- Documentar fecha, técnico responsable y equipo (hostname/serial) al completar la checklist.
