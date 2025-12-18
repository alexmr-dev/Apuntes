## Auditoría de Seguridad en Windows Server 2025 + Active Directory

**Objetivo:** Comandos detallados para auditoría de caja blanca (White Box) con acceso administrativo  
**Entorno:** Windows Server 2025, Active Directory, entorno multisitio  
**Nota:** Ejecutar PowerShell como Administrador

---

## 📋 ÍNDICE RÁPIDO

1. [Información del Sistema](https://claude.ai/chat/955e0599-4b9d-43e0-907c-875c1165fe2d#1-informaci%C3%B3n-del-sistema)
2. [Auditoría de Active Directory](https://claude.ai/chat/955e0599-4b9d-43e0-907c-875c1165fe2d#2-auditor%C3%ADa-de-active-directory)
3. [Políticas de Seguridad](https://claude.ai/chat/955e0599-4b9d-43e0-907c-875c1165fe2d#3-pol%C3%ADticas-de-seguridad)
4. [Análisis de Red y Firewall](https://claude.ai/chat/955e0599-4b9d-43e0-907c-875c1165fe2d#4-an%C3%A1lisis-de-red-y-firewall)
5. [Servicios y Procesos](https://claude.ai/chat/955e0599-4b9d-43e0-907c-875c1165fe2d#5-servicios-y-procesos)
6. [Análisis de Permisos](https://claude.ai/chat/955e0599-4b9d-43e0-907c-875c1165fe2d#6-an%C3%A1lisis-de-permisos)
7. [Certificados y PKI](https://claude.ai/chat/955e0599-4b9d-43e0-907c-875c1165fe2d#7-certificados-y-pki)
8. [Logs y Eventos](https://claude.ai/chat/955e0599-4b9d-43e0-907c-875c1165fe2d#8-logs-y-eventos)
9. [Tareas Programadas](https://claude.ai/chat/955e0599-4b9d-43e0-907c-875c1165fe2d#9-tareas-programadas)
10. [Backup y Recuperación](https://claude.ai/chat/955e0599-4b9d-43e0-907c-875c1165fe2d#10-backup-y-recuperaci%C3%B3n)
11. [Detección de Amenazas](https://claude.ai/chat/955e0599-4b9d-43e0-907c-875c1165fe2d#11-detecci%C3%B3n-de-amenazas)
12. [Software Instalado](https://claude.ai/chat/955e0599-4b9d-43e0-907c-875c1165fe2d#12-software-instalado)
13. [IIS y Aplicaciones Web](https://claude.ai/chat/955e0599-4b9d-43e0-907c-875c1165fe2d#13-iis-y-aplicaciones-web)
14. [Bases de Datos](https://claude.ai/chat/955e0599-4b9d-43e0-907c-875c1165fe2d#14-bases-de-datos)
15. [Scripts de Auditoría Completos](https://claude.ai/chat/955e0599-4b9d-43e0-907c-875c1165fe2d#15-scripts-de-auditor%C3%ADa-completos)

---

## 1. INFORMACIÓN DEL SISTEMA

### 1.1. Información Básica del Servidor

```powershell
# Información general del sistema
Get-ComputerInfo | Select-Object CsName, OsName, OsVersion, OsArchitecture, WindowsVersion

# Versión detallada del SO
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" | Select-Object ProductName, ReleaseId, CurrentBuild

# Información del hardware
Get-CimInstance Win32_ComputerSystem | Select-Object Name, Domain, Model, Manufacturer, TotalPhysicalMemory

# Verificar si es Controlador de Dominio
Get-Service NTDS -ErrorAction SilentlyContinue
Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction SilentlyContinue

# Uptime del servidor
(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

# Variables de entorno críticas
Get-ChildItem Env: | Where-Object {$_.Name -match "PATH|TEMP|WINDIR|SYSTEMROOT"}
```

### 1.2. Estado de Parcheo

```powershell
# Listar todos los hotfixes instalados
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID, Description, InstalledOn

# Exportar a CSV para análisis
Get-HotFix | Export-Csv -Path "C:\Audit\Hotfixes.csv" -NoTypeInformation

# Verificar último parche instalado
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1

# Comprobar actualizaciones pendientes (requiere módulo PSWindowsUpdate)
# Install-Module PSWindowsUpdate -Force
Get-WindowsUpdate -MicrosoftUpdate
```

### 1.3. Usuarios Locales Conectados

```powershell
# Usuarios actualmente logueados
query user

# Sesiones remotas RDP activas
qwinsta

# Historial de logons (últimas 24h)
Get-EventLog -LogName Security -InstanceId 4624 -After (Get-Date).AddHours(-24) | Select-Object TimeGenerated, ReplacementStrings

# Último logon de cada usuario local
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet
```

---

## 2. AUDITORÍA DE ACTIVE DIRECTORY

### 2.1. Información del Dominio

```powershell
# Información básica del dominio
Get-ADDomain | Select-Object Name, Forest, DomainMode, PDCEmulator, InfrastructureMaster

# Nivel funcional del dominio y bosque
Get-ADDomain | Select-Object DomainMode
Get-ADForest | Select-Object ForestMode

# Controladores de dominio
Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, IsGlobalCatalog, OperatingSystem

# Verificar replicación de AD
Get-ADReplicationPartnerMetadata -Target $env:COMPUTERNAME -Scope Domain

# Verificar salud de SYSVOL
dcdiag /test:sysvolcheck /test:advertising
```

### 2.2. Enumeración de Usuarios

```powershell
# Todos los usuarios del dominio
Get-ADUser -Filter * -Properties * | Select-Object Name, SamAccountName, Enabled, Created, LastLogonDate, PasswordLastSet, PasswordNeverExpires

# Usuarios con contraseñas que nunca expiran ⚠️
Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires | Select-Object Name, SamAccountName, Enabled

# Usuarios con contraseñas expiradas
Search-ADAccount -PasswordExpired | Select-Object Name, SamAccountName, PasswordExpired

# Usuarios inactivos (más de 90 días sin login)
$inactiveDays = 90
$inactiveDate = (Get-Date).AddDays(-$inactiveDays)
Get-ADUser -Filter {LastLogonDate -lt $inactiveDate -and Enabled -eq $true} -Properties LastLogonDate | Select-Object Name, SamAccountName, LastLogonDate

# Usuarios con SPN configurado (potencial Kerberoasting) ⚠️⚠️
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | Select-Object Name, SamAccountName, ServicePrincipalName

# Usuarios con privilegios administrativos
Get-ADGroupMember "Domain Admins" | Select-Object Name, SamAccountName
Get-ADGroupMember "Enterprise Admins" | Select-Object Name, SamAccountName
Get-ADGroupMember "Schema Admins" | Select-Object Name, SamAccountName

# Usuarios con delegación sin restricciones (muy peligroso) ⚠️⚠️⚠️
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select-Object Name, SamAccountName

# Usuarios con preautenticación Kerberos deshabilitada (ASREPRoasting) ⚠️⚠️
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth | Select-Object Name, SamAccountName

# Cuentas de servicio
Get-ADUser -Filter {SamAccountName -like "svc*" -or SamAccountName -like "service*"} | Select-Object Name, SamAccountName, Enabled

# Exportar todos los usuarios a CSV
Get-ADUser -Filter * -Properties * | Export-Csv -Path "C:\Audit\AD_Users.csv" -NoTypeInformation
```

### 2.3. Enumeración de Grupos

```powershell
# Todos los grupos del dominio
Get-ADGroup -Filter * | Select-Object Name, GroupScope, GroupCategory

# Grupos privilegiados críticos
$privilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Server Operators",
    "Backup Operators",
    "Print Operators",
    "DNSAdmins",
    "Group Policy Creator Owners"
)

foreach ($group in $privilegedGroups) {
    Write-Host "`n=== $group ===" -ForegroundColor Cyan
    Get-ADGroupMember $group -Recursive -ErrorAction SilentlyContinue | Select-Object Name, SamAccountName, objectClass
}

# Grupos vacíos (posible limpieza)
Get-ADGroup -Filter * -Properties Members | Where-Object {$_.Members.Count -eq 0} | Select-Object Name

# Miembros anidados de Domain Admins
Get-ADGroupMember "Domain Admins" -Recursive | Select-Object Name, SamAccountName

# Exportar estructura de grupos
Get-ADGroup -Filter * -Properties Members | Select-Object Name, GroupScope, @{Name="MemberCount";Expression={$_.Members.Count}} | Export-Csv -Path "C:\Audit\AD_Groups.csv" -NoTypeInformation
```

### 2.4. Enumeración de Equipos

```powershell
# Todos los equipos del dominio
Get-ADComputer -Filter * -Properties * | Select-Object Name, OperatingSystem, OperatingSystemVersion, IPv4Address, LastLogonDate, Enabled

# Servidores
Get-ADComputer -Filter {OperatingSystem -like "*Server*"} -Properties OperatingSystem | Select-Object Name, OperatingSystem, IPv4Address

# Estaciones de trabajo
Get-ADComputer -Filter {OperatingSystem -like "*Windows 10*" -or OperatingSystem -like "*Windows 11*"} -Properties OperatingSystem | Select-Object Name, OperatingSystem

# Equipos inactivos (más de 90 días)
$inactiveDate = (Get-Date).AddDays(-90)
Get-ADComputer -Filter {LastLogonDate -lt $inactiveDate} -Properties LastLogonDate | Select-Object Name, LastLogonDate

# Equipos con delegación sin restricciones ⚠️⚠️
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select-Object Name, OperatingSystem
```

### 2.5. Políticas de Contraseñas (GPO)

```powershell
# Política de contraseñas del dominio
Get-ADDefaultDomainPasswordPolicy | Select-Object ComplexityEnabled, LockoutThreshold, LockoutDuration, MaxPasswordAge, MinPasswordAge, MinPasswordLength, PasswordHistoryCount

# Políticas de contraseñas granulares (Fine-Grained Password Policy)
Get-ADFineGrainedPasswordPolicy -Filter * | Select-Object Name, Precedence, ComplexityEnabled, MinPasswordLength, MaxPasswordAge

# Verificar política actual aplicada a un usuario específico
Get-ADUserResultantPasswordPolicy -Identity "usuario"

# Auditar configuración insegura ⚠️
$policy = Get-ADDefaultDomainPasswordPolicy
if ($policy.MinPasswordLength -lt 12) { Write-Host "⚠️ ALERTA: Longitud mínima de contraseña < 12 caracteres" -ForegroundColor Red }
if ($policy.ComplexityEnabled -eq $false) { Write-Host "⚠️ ALERTA: Complejidad de contraseña deshabilitada" -ForegroundColor Red }
if ($policy.MaxPasswordAge.Days -gt 90) { Write-Host "⚠️ ALERTA: Contraseñas expiran en más de 90 días" -ForegroundColor Red }
```

### 2.6. Group Policy Objects (GPO)

```powershell
# Listar todas las GPO
Get-GPO -All | Select-Object DisplayName, GpoStatus, CreationTime, ModificationTime

# GPO con configuraciones de seguridad
Get-GPO -All | ForEach-Object {
    $gpo = $_
    Get-GPOReport -Name $gpo.DisplayName -ReportType Xml | Out-File "C:\Audit\GPO_$($gpo.DisplayName).xml"
}

# GPO aplicadas a un equipo específico
gpresult /R /Scope Computer

# GPO aplicadas a un usuario específico
gpresult /R /Scope User

# Generar reporte HTML completo de GPO
Get-GPOReport -All -ReportType Html -Path "C:\Audit\GPO_Report.html"

# Verificar herencia de GPO
Get-GPInheritance -Target "OU=Servidores,DC=fenoy,DC=local"
```

### 2.7. Análisis de Confianzas (Trusts)

```powershell
# Listar todas las confianzas del dominio
Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType, IntraForest

# Verificar confianzas bidireccionales externas ⚠️
Get-ADTrust -Filter {Direction -eq "Bidirectional" -and IntraForest -eq $false}

# Detalles de una confianza específica
Get-ADTrust -Identity "dominio_confiado"
```

---

## 3. POLÍTICAS DE SEGURIDAD

### 3.1. Políticas Locales de Seguridad

```powershell
# Exportar configuración completa de seguridad local
secedit /export /cfg "C:\Audit\SecPol.inf"

# Revisar configuración de UAC
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop

# Política de auditoría avanzada
auditpol /get /category:*

# Exportar política de auditoría
auditpol /backup /file:"C:\Audit\AuditPol.csv"

# Verificar si auditoría de comandos PowerShell está activada
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue
```

### 3.2. Windows Defender y Antivirus

```powershell
# Estado de Windows Defender
Get-MpComputerStatus

# Exclusiones configuradas ⚠️
Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess

# Historial de detecciones
Get-MpThreatDetection

# Última actualización de definiciones
Get-MpComputerStatus | Select-Object AntivirusSignatureLastUpdated, AntispywareSignatureLastUpdated

# Verificar ESET (si está instalado)
Get-Service -Name "ekrn" -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType
Get-Process -Name "egui" -ErrorAction SilentlyContinue
```

### 3.3. BitLocker y Cifrado

```powershell
# Estado de BitLocker en todos los volúmenes
Get-BitLockerVolume | Select-Object MountPoint, EncryptionMethod, VolumeStatus, ProtectionStatus

# Verificar métodos de protección
Get-BitLockerVolume | Select-Object MountPoint, KeyProtector

# Verificar si hay recovery keys guardadas en AD
Get-ADObject -Filter {objectClass -eq "msFVE-RecoveryInformation"} -Properties msFVE-RecoveryPassword
```

---

## 4. ANÁLISIS DE RED Y FIREWALL

### 4.1. Configuración de Red

```powershell
# Adaptadores de red y direcciones IP
Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, PrefixLength, AddressFamily

# Configuración de DNS
Get-DnsClientServerAddress

# Tabla de enrutamiento
Get-NetRoute | Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric

# Verificar si el servidor es DHCP
Get-Service DHCPServer -ErrorAction SilentlyContinue

# Configuración de adaptadores
Get-NetAdapter | Select-Object Name, Status, LinkSpeed, MacAddress

# Configuración avanzada de TCP/IP
Get-NetTCPSetting

# Verificar SMBv1 (debe estar deshabilitado) ⚠️
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
```

### 4.2. Puertos y Conexiones Activas

```powershell
# Puertos TCP en escucha
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess, @{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess).Name}}

# Puertos UDP abiertos
Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess, @{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}}

# Conexiones establecidas
Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, @{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess).Name}}

# Identificar RDP expuesto (puerto 3389 o custom)
Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue
Get-NetTCPConnection -LocalPort 29100 -State Listen -ErrorAction SilentlyContinue  # Puerto custom FENOY
Get-NetTCPConnection -LocalPort 32200 -State Listen -ErrorAction SilentlyContinue  # Puerto custom FENOY

# Exportar conexiones activas
Get-NetTCPConnection | Export-Csv -Path "C:\Audit\ActiveConnections.csv" -NoTypeInformation

# Script para monitorear puertos sospechosos
$suspiciousPorts = @(4444, 5555, 6666, 7777, 8888, 31337, 12345)  # Puertos comunes de malware
foreach ($port in $suspiciousPorts) {
    $connection = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    if ($connection) {
        Write-Host "⚠️ Puerto sospechoso abierto: $port" -ForegroundColor Red
        $connection | Select-Object LocalAddress, LocalPort, RemoteAddress, State
    }
}
```

### 4.3. Firewall de Windows

```powershell
# Estado del firewall en todos los perfiles
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

# Reglas de firewall activas (entrantes)
Get-NetFirewallRule -Direction Inbound -Enabled True | Select-Object DisplayName, Direction, Action, Profile | Sort-Object DisplayName

# Reglas de firewall que permiten conexiones (posibles riesgos)
Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Select-Object DisplayName, Profile

# Reglas de RDP
Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*Remote Desktop*"} | Select-Object DisplayName, Enabled, Direction, Action

# Exportar todas las reglas de firewall
Get-NetFirewallRule | Export-Csv -Path "C:\Audit\FirewallRules.csv" -NoTypeInformation

# Verificar reglas con puertos específicos
Get-NetFirewallPortFilter | Where-Object {$_.LocalPort -eq "3389" -or $_.LocalPort -eq "29100"} | Get-NetFirewallRule | Select-Object DisplayName, Enabled, Direction, Action

# Reglas creadas por aplicaciones de terceros ⚠️
Get-NetFirewallRule | Where-Object {$_.DisplayName -notlike "*Microsoft*" -and $_.DisplayName -notlike "*Windows*"} | Select-Object DisplayName, Enabled, Direction, Action
```

### 4.4. Comparticiones de Red (SMB)

```powershell
# Comparticiones activas
Get-SmbShare | Select-Object Name, Path, Description, CurrentUsers

# Comparticiones administrativas ocultas ⚠️
Get-SmbShare | Where-Object {$_.Name -like "*$"}

# Sesiones SMB activas
Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens

# Archivos abiertos remotamente
Get-SmbOpenFile | Select-Object ClientComputerName, ClientUserName, Path

# Permisos de comparticiones
Get-SmbShare | ForEach-Object {
    $share = $_
    Write-Host "`n=== $($share.Name) ===" -ForegroundColor Cyan
    Get-SmbShareAccess -Name $share.Name | Select-Object AccountName, AccessControlType, AccessRight
}

# Verificar si hay null sessions habilitadas ⚠️⚠️
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object RestrictAnonymous, RestrictAnonymousSAM

# Configuración de SMB
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature, EncryptData
```

---

## 5. SERVICIOS Y PROCESOS

### 5.1. Servicios en Ejecución

```powershell
# Todos los servicios
Get-Service | Select-Object Name, DisplayName, Status, StartType | Sort-Object Status -Descending

# Servicios en ejecución
Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, DisplayName, StartType

# Servicios con inicio automático
Get-Service | Where-Object {$_.StartType -eq "Automatic"} | Select-Object Name, DisplayName, Status

# Servicios de terceros (no Microsoft) ⚠️
Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike "*Windows*" -and $_.PathName -notlike "*Microsoft*"} | Select-Object Name, DisplayName, PathName, StartMode, State

# Servicios ejecutándose como SYSTEM ⚠️
Get-WmiObject Win32_Service | Where-Object {$_.StartName -eq "LocalSystem"} | Select-Object Name, DisplayName, PathName, State

# Servicios con rutas sin comillas (potencial privilege escalation) ⚠️⚠️
Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike "*`"*" -and $_.PathName -like "* *"} | Select-Object Name, DisplayName, PathName, StartMode

# Verificar servicios críticos de seguridad
$criticalServices = @("wuauserv", "wscsvc", "WinDefend", "MpsSvc", "NTDS", "DNS", "Netlogon")
foreach ($service in $criticalServices) {
    Get-Service $service -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType
}

# Exportar servicios
Get-Service | Export-Csv -Path "C:\Audit\Services.csv" -NoTypeInformation
```

### 5.2. Procesos en Ejecución

```powershell
# Todos los procesos
Get-Process | Select-Object Name, Id, CPU, WorkingSet, Path | Sort-Object CPU -Descending

# Procesos consumiendo más recursos
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name, Id, CPU, @{Name="MemoryMB";Expression={[math]::Round($_.WorkingSet/1MB,2)}}

# Procesos sin firma digital ⚠️
Get-Process | Where-Object {$_.Path} | ForEach-Object {
    $signature = Get-AuthenticodeSignature $_.Path
    if ($signature.Status -ne "Valid") {
        [PSCustomObject]@{
            ProcessName = $_.Name
            Path = $_.Path
            SignatureStatus = $signature.Status
        }
    }
}

# Procesos ejecutándose desde ubicaciones sospechosas ⚠️⚠️
$suspiciousLocations = @("C:\Users\*\AppData\Roaming\*", "C:\Users\*\AppData\Local\Temp\*", "C:\Windows\Temp\*")
Get-Process | Where-Object {$_.Path} | Where-Object {
    $path = $_.Path
    $suspiciousLocations | Where-Object {$path -like $_}
} | Select-Object Name, Id, Path

# Procesos con conexiones de red activas
Get-NetTCPConnection -State Established | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object {
    Get-Process -Id $_ -ErrorAction SilentlyContinue | Select-Object Name, Id, Path
}

# DLLs cargadas por un proceso específico
Get-Process -Name "nombre_proceso" | Select-Object -ExpandProperty Modules | Select-Object ModuleName, FileName
```

---

## 6. ANÁLISIS DE PERMISOS

### 6.1. Permisos de Archivos y Carpetas

```powershell
# Permisos de carpetas críticas del sistema
$criticalFolders = @("C:\Windows\System32", "C:\Program Files", "C:\Windows\Temp", "C:\inetpub\wwwroot")
foreach ($folder in $criticalFolders) {
    Write-Host "`n=== Permisos de $folder ===" -ForegroundColor Cyan
    Get-Acl $folder | Select-Object -ExpandProperty Access | Select-Object IdentityReference, FileSystemRights, AccessControlType
}

# Buscar archivos world-writable (Everyone con permisos de escritura) ⚠️⚠️
Get-ChildItem "C:\Program Files" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $acl = Get-Acl $_.FullName -ErrorAction SilentlyContinue
    if ($acl.Access | Where-Object {$_.IdentityReference -eq "Everyone" -and $_.FileSystemRights -match "Write"}) {
        [PSCustomObject]@{
            Path = $_.FullName
            Owner = $acl.Owner
        }
    }
}

# Buscar archivos con permisos heredados rotos
Get-ChildItem "C:\inetpub" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $acl = Get-Acl $_.FullName -ErrorAction SilentlyContinue
    if ($acl.AreAccessRulesProtected -eq $true) {
        Write-Host "Herencia rota en: $($_.FullName)" -ForegroundColor Yellow
    }
}

# Permisos del directorio SYSVOL ⚠️
Get-Acl "C:\Windows\SYSVOL" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Access

# Buscar certificados .p12 / .pfx con permisos débiles ⚠️⚠️⚠️
Get-ChildItem -Path C:\ -Include *.p12,*.pfx -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "`n⚠️ Certificado encontrado: $($_.FullName)" -ForegroundColor Red
    Get-Acl $_.FullName | Select-Object -ExpandProperty Access | Select-Object IdentityReference, FileSystemRights
}
```

### 6.2. Permisos del Registro

```powershell
# Permisos de claves críticas del registro
$criticalKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SYSTEM\CurrentControlSet\Services"
)

foreach ($key in $criticalKeys) {
    Write-Host "`n=== Permisos de $key ===" -ForegroundColor Cyan
    Get-Acl $key | Select-Object -ExpandProperty Access | Select-Object IdentityReference, RegistryRights, AccessControlType
}

# Buscar claves con permisos de escritura para usuarios estándar ⚠️
Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Select-Object -ExpandProperty Access | Where-Object {$_.IdentityReference -eq "BUILTIN\Users" -and $_.RegistryRights -match "Write"}
```

---

## 7. CERTIFICADOS Y PKI

### 7.1. Certificados del Sistema

```powershell
# Certificados en el almacén personal del equipo
Get-ChildItem Cert:\LocalMachine\My | Select-Object Subject, Issuer, NotBefore, NotAfter, Thumbprint

# Certificados expirados o por expirar ⚠️
$today = Get-Date
Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.NotAfter -lt $today.AddDays(30)} | Select-Object Subject, NotAfter, @{Name="DaysUntilExpiration";Expression={($_.NotAfter - $today).Days}}

# Certificados autofirmados ⚠️
Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -eq $_.Issuer} | Select-Object Subject, Issuer, NotAfter

# Certificados raíz de confianza
Get-ChildItem Cert:\LocalMachine\Root | Select-Object Subject, Issuer, NotAfter

# Exportar información de certificados
Get-ChildItem Cert:\LocalMachine\My | Export-Csv -Path "C:\Audit\Certificates.csv" -NoTypeInformation

# Verificar servicios de certificados de AD (si es CA)
Get-Service CertSvc -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType

# Plantillas de certificados (si es CA)
certutil -CATemplates
```

### 7.2. Certificados en Archivos

```powershell
# Buscar archivos de certificados en el servidor ⚠️⚠️⚠️
$certExtensions = @("*.pfx", "*.p12", "*.cer", "*.crt", "*.pem", "*.key")
foreach ($ext in $certExtensions) {
    Write-Host "`nBuscando archivos $ext..." -ForegroundColor Cyan
    Get-ChildItem -Path C:\ -Include $ext -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime
}

# Buscar claves privadas ⚠️⚠️⚠️
Get-ChildItem -Path C:\ -Include *.key,*private*.pem -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime
```

---

## 8. LOGS Y EVENTOS

### 8.1. Configuración de Logs

```powershell
# Tamaño y retención de logs
Get-WinEvent -ListLog * | Where-Object {$_.RecordCount -gt 0} | Select-Object LogName, RecordCount, MaximumSizeInBytes, IsEnabled | Sort-Object RecordCount -Descending

# Verificar si logs críticos están habilitados
$criticalLogs = @("Security", "System", "Application", "Microsoft-Windows-PowerShell/Operational")
foreach ($log in $criticalLogs) {
    $logConfig = Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue
    if ($logConfig.IsEnabled) {
        Write-Host "✓ $log habilitado" -ForegroundColor Green
    } else {
        Write-Host "⚠️ $log deshabilitado" -ForegroundColor Red
    }
}

# Exportar configuración de logs
Get-WinEvent -ListLog * | Export-Csv -Path "C:\Audit\EventLogConfig.csv" -NoTypeInformation
```

### 8.2. Análisis de Eventos de Seguridad

```powershell
# Logons exitosos (Event ID 4624) - Últimas 24h
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddHours(-24)} | Select-Object TimeCreated, @{Name="User";Expression={$_.Properties[5].Value}}, @{Name="LogonType";Expression={$_.Properties[8].Value}}

# Logons fallidos (Event ID 4625) - Últimas 24h ⚠️
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddHours(-24)} | Select-Object TimeCreated, @{Name="User";Expression={$_.Properties[5].Value}}, @{Name="FailureReason";Expression={$_.Properties[8].Value}}

# Cambios en cuentas de usuario (Event ID 4720, 4722, 4724, 4738)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4720,4722,4724,4738; StartTime=(Get-Date).AddDays(-7)} | Select-Object TimeCreated, Id, Message

# Cambios en grupos (Event ID 4728, 4732, 4756)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4728,4732,4756; StartTime=(Get-Date).AddDays(-7)} | Select-Object TimeCreated, Id, Message

# Uso de privilegios especiales (Event ID 4672)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672; StartTime=(Get-Date).AddHours(-24)} | Select-Object TimeCreated, Message

# Creación de servicios (Event ID 4697) ⚠️
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4697; StartTime=(Get-Date).AddDays(-7)} | Select-Object TimeCreated, Message

# Creación de tareas programadas (Event ID 4698) ⚠️
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4698; StartTime=(Get-Date).AddDays(-7)} | Select-Object TimeCreated, Message

# Acceso a objetos sensibles (Event ID 4663)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663; StartTime=(Get-Date).AddHours(-24)} | Select-Object TimeCreated, Message

# Cambios en políticas de auditoría (Event ID 4719)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4719; StartTime=(Get-Date).AddDays(-30)} | Select-Object TimeCreated, Message

# Exportar eventos críticos
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625,4720,4732,4697,4698; StartTime=(Get-Date).AddDays(-7)} | Export-Csv -Path "C:\Audit\CriticalSecurityEvents.csv" -NoTypeInformation
```

### 8.3. Eventos de PowerShell

```powershell
# Comandos PowerShell ejecutados (Event ID 4104 - ScriptBlock Logging)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message

# Comandos sospechosos de PowerShell ⚠️⚠️
$suspiciousKeywords = @("Invoke-Mimikatz", "Invoke-Expression", "IEX", "DownloadString", "EncodedCommand", "bypass", "-nop", "-w hidden")
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue | Where-Object {
    $message = $_.Message
    $suspiciousKeywords | Where-Object {$message -match $_}
} | Select-Object TimeCreated, Message
```

### 8.4. Eventos de Sistema

```powershell
# Errores críticos del sistema
Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddDays(-7)} | Select-Object TimeCreated, LevelDisplayName, ProviderName, Message

# Reinicios del sistema
Get-WinEvent -FilterHashtable @{LogName='System'; ID=1074,6005,6006,6008; StartTime=(Get-Date).AddDays(-30)} | Select-Object TimeCreated, Id, Message

# Cambios en servicios
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7034,7035,7036,7040; StartTime=(Get-Date).AddDays(-7)} | Select-Object TimeCreated, Id, Message
```

---

## 9. TAREAS PROGRAMADAS

### 9.1. Enumeración de Tareas

```powershell
# Todas las tareas programadas
Get-ScheduledTask | Select-Object TaskName, TaskPath, State, @{Name="User";Expression={$_.Principal.UserId}}

# Tareas habilitadas
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | Select-Object TaskName, TaskPath, @{Name="User";Expression={$_.Principal.UserId}}

# Tareas ejecutándose como SYSTEM ⚠️
Get-ScheduledTask | Where-Object {$_.Principal.UserId -eq "SYSTEM"} | Select-Object TaskName, TaskPath, State

# Tareas con acciones sospechosas ⚠️⚠️
Get-ScheduledTask | ForEach-Object {
    $task = $_
    $actions = $task.Actions.Execute
    if ($actions -match "powershell|cmd|wscript|cscript") {
        [PSCustomObject]@{
            TaskName = $task.TaskName
            TaskPath = $task.TaskPath
            Action = $actions
            User = $task.Principal.UserId
        }
    }
}

# Tareas creadas recientemente (últimos 30 días) ⚠️
$recentDate = (Get-Date).AddDays(-30)
Get-ScheduledTask | Where-Object {$_.Date -gt $recentDate} | Select-Object TaskName, TaskPath, Date, @{Name="User";Expression={$_.Principal.UserId}}

# Exportar detalles de una tarea específica (XML)
Export-ScheduledTask -TaskName "nombre_tarea" | Out-File "C:\Audit\Task_nombre_tarea.xml"

# Exportar todas las tareas
Get-ScheduledTask | Export-Csv -Path "C:\Audit\ScheduledTasks.csv" -NoTypeInformation
```

---

## 10. BACKUP Y RECUPERACIÓN

### 10.1. Configuración de Windows Server Backup

```powershell
# Estado de Windows Server Backup
Get-WBSummary -ErrorAction SilentlyContinue

# Política de backup configurada
Get-WBPolicy -ErrorAction SilentlyContinue

# Último backup realizado
Get-WBJob -Previous 1 -ErrorAction SilentlyContinue

# Discos de backup
Get-WBDisk -ErrorAction SilentlyContinue

# Verificar Volume Shadow Copy Service
Get-Service VSS | Select-Object Name, Status, StartType
vssadmin list shadows
vssadmin list writers
```

### 10.2. Configuración de Backup de Terceros

```powershell
# Buscar software de backup instalado
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -match "backup|veeam|acronis|veritas|commvault"} | Select-Object DisplayName, DisplayVersion, Publisher

# Verificar servicios de backup comunes
$backupServices = @("Veeam*", "AcronisCyberProtect*", "Backup Exec*")
foreach ($service in $backupServices) {
    Get-Service -Name $service -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType
}
```

### 10.3. Análisis de Snapshots y Restauración

```powershell
# Listar puntos de restauración
Get-ComputerRestorePoint | Select-Object SequenceNumber, CreationTime, Description

# Verificar si System Restore está habilitado
Get-ComputerRestorePoint -ErrorAction SilentlyContinue
```

---

## 11. DETECCIÓN DE AMENAZAS

### 11.1. Indicadores de Compromiso (IoC)

```powershell
# Buscar archivos ejecutables en ubicaciones sospechosas ⚠️⚠️
$suspiciousLocations = @(
    "C:\Users\*\AppData\Roaming",
    "C:\Users\*\AppData\Local\Temp",
    "C:\Windows\Temp",
    "C:\ProgramData"
)

foreach ($location in $suspiciousLocations) {
    Write-Host "`nBuscando ejecutables en $location..." -ForegroundColor Cyan
    Get-ChildItem -Path $location -Include *.exe,*.dll,*.bat,*.ps1 -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, CreationTime, LastWriteTime
}

# Buscar archivos con doble extensión ⚠️⚠️
Get-ChildItem -Path C:\Users -Include *.pdf.exe,*.doc.exe,*.xls.exe -Recurse -ErrorAction SilentlyContinue

# Buscar scripts ofuscados
Get-ChildItem -Path C:\ -Include *.ps1,*.vbs,*.js -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
    if ($content -match "frombase64|invoke-expression|iex|downloadstring") {
        Write-Host "⚠️ Script potencialmente malicioso: $($_.FullName)" -ForegroundColor Red
    }
}
```

### 11.2. Persistencia

```powershell
# Claves de Registro de autoarranque ⚠️⚠️
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $runKeys) {
    Write-Host "`n=== $key ===" -ForegroundColor Cyan
    Get-ItemProperty $key -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider
}

# Servicios sospechosos creados recientemente
Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike "*Windows*"} | Select-Object Name, DisplayName, PathName, StartMode, State, @{Name="CreationDate";Expression={$_.ConvertToDateTime($_.InstallDate)}}

# WMI Event Consumers (persistencia avanzada) ⚠️⚠️⚠️
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding

# Startup folder
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" -Recurse -ErrorAction SilentlyContinue
```

### 11.3. Movimiento Lateral

```powershell
# Sesiones remotas activas (RDP/PSRemoting)
qwinsta
Get-PSSession

# Credenciales en memoria (requiere Mimikatz - solo en entorno de pruebas autorizado)
# ⚠️ NO ejecutar en producción sin autorización explícita

# Tickets Kerberos en caché
klist

# Conexiones remotas recientes (últimos 7 días)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddDays(-7)} | Where-Object {$_.Properties[8].Value -eq 10} | Select-Object TimeCreated, @{Name="User";Expression={$_.Properties[5].Value}}, @{Name="SourceIP";Expression={$_.Properties[18].Value}}
```

### 11.4. Exfiltración de Datos

```powershell
# Conexiones salientes sospechosas
Get-NetTCPConnection -State Established | Where-Object {$_.RemotePort -in @(21,22,23,25,53,80,443,3389)} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, @{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess).Name}}

# Uso de FTP (protocolo inseguro) ⚠️
Get-NetTCPConnection -RemotePort 21 -ErrorAction SilentlyContinue

# Archivos grandes modificados recientemente (posible staging para exfiltración)
Get-ChildItem -Path C:\Users -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Length -gt 100MB -and $_.LastWriteTime -gt (Get-Date).AddDays(-7)} | Select-Object FullName, Length, LastWriteTime
```

---

## 12. SOFTWARE INSTALADO

### 12.1. Enumeración de Software

```powershell
# Software instalado (Registry 64-bit)
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName

# Software instalado (Registry 32-bit en sistema 64-bit)
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName

# Combinar ambas listas y exportar
$software = @()
$software += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
$software += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
$software | Where-Object {$_.DisplayName} | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | Export-Csv -Path "C:\Audit\InstalledSoftware.csv" -NoTypeInformation

# Software desactualizado (buscar versiones antiguas) ⚠️
# Este comando requiere conocimiento previo de versiones actuales
```

### 12.2. Software de Desarrollo/Administración

```powershell
# Herramientas de desarrollo potencialmente riesgosas ⚠️
$devTools = @("Visual Studio Code", "Python", "Git", "Node.js", "PuTTY", "WinSCP", "FileZilla", "Wireshark")
foreach ($tool in $devTools) {
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "*$tool*"} | Select-Object DisplayName, DisplayVersion
}

# Verificar si PowerShell está actualizado
$PSVersionTable
```

---

## 13. IIS Y APLICACIONES WEB

### 13.1. Configuración de IIS

```powershell
# Verificar si IIS está instalado
Get-Service W3SVC -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType

# Importar módulo de IIS
Import-Module WebAdministration -ErrorAction SilentlyContinue

# Listar sitios web
Get-Website | Select-Object Name, Id, State, PhysicalPath, @{Name="Bindings";Expression={$_.bindings.Collection.bindingInformation}}

# Application Pools
Get-IISAppPool | Select-Object Name, State, ManagedRuntimeVersion, ManagedPipelineMode

# Configuración de autenticación por sitio
Get-Website | ForEach-Object {
    $siteName = $_.Name
    Write-Host "`n=== $siteName ===" -ForegroundColor Cyan
    Get-WebConfigurationProperty -Filter "/system.webServer/security/authentication/*" -PSPath "IIS:\Sites\$siteName" -Name enabled | Select-Object PSPath, Value
}

# Verificar si hay directorios con browsing habilitado ⚠️
Get-WebConfigurationProperty -Filter "/system.webServer/directoryBrowse" -PSPath "IIS:\Sites\*" -Name enabled | Where-Object {$_.Value -eq $true}

# Módulos IIS cargados
Get-WebConfiguration -Filter "/system.webServer/modules/add" -PSPath "IIS:\" | Select-Object Name

# Logs de IIS
Get-WebConfiguration -Filter "/system.applicationHost/sites/siteDefaults/logFile" | Select-Object directory, logFormat

# Certificados SSL en IIS
Get-ChildItem IIS:SslBindings | Select-Object IPAddress, Port, Host, @{Name="Thumbprint";Expression={$_.Thumbprint}}
```

### 13.2. Archivos de Configuración Web

```powershell
# Buscar archivos web.config ⚠️
Get-ChildItem -Path C:\inetpub -Include web.config -Recurse -ErrorAction SilentlyContinue | Select-Object FullName

# Buscar connection strings en web.config (posibles credenciales) ⚠️⚠️⚠️
Get-ChildItem -Path C:\inetpub -Include web.config -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $content = Get-Content $_.FullName -Raw
    if ($content -match "connectionString|password|uid=") {
        Write-Host "`n⚠️ Posibles credenciales en: $($_.FullName)" -ForegroundColor Red
        $content | Select-String -Pattern "connectionString|password" -Context 0,2
    }
}

# Buscar archivos de configuración de aplicaciones
Get-ChildItem -Path C:\inetpub -Include *.config,appsettings.json,.env -Recurse -ErrorAction SilentlyContinue
```

---

## 14. BASES DE DATOS

### 14.1. SQL Server (si está instalado)

```powershell
# Verificar servicios de SQL Server
Get-Service -Name "MSSQL*" -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, Status, StartType

# Instancias de SQL Server
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL" -ErrorAction SilentlyContinue

# Puertos SQL Server en escucha
Get-NetTCPConnection -LocalPort 1433 -State Listen -ErrorAction SilentlyContinue
```

### 14.2. PostgreSQL / MySQL (Odoo)

```powershell
# Verificar servicios de PostgreSQL
Get-Service -Name "postgresql*" -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType

# Puerto PostgreSQL (5432)
Get-NetTCPConnection -LocalPort 5432 -State Listen -ErrorAction SilentlyContinue

# Verificar MySQL
Get-Service -Name "MySQL*" -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType
Get-NetTCPConnection -LocalPort 3306 -State Listen -ErrorAction SilentlyContinue

# Buscar archivos de configuración de bases de datos ⚠️⚠️
Get-ChildItem -Path C:\ -Include postgresql.conf,my.ini,my.cnf -Recurse -ErrorAction SilentlyContinue

# Buscar archivos con credenciales de DB ⚠️⚠️⚠️
Get-ChildItem -Path C:\ -Include *.conf,*.ini,*.config -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password|dbuser|dbpass" -List
```

---

## 15. SCRIPTS DE AUDITORÍA COMPLETOS

### 15.1. Script de Auditoría Rápida

```powershell
# Script: Quick Security Audit
# Descripción: Auditoría rápida de seguridad en 5 minutos

$outputDir = "C:\Audit"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

Write-Host "=== INICIANDO AUDITORÍA RÁPIDA DE SEGURIDAD ===" -ForegroundColor Green
Write-Host "Directorio de salida: $outputDir`n" -ForegroundColor Yellow

# 1. Información del sistema
Write-Host "[1/10] Recopilando información del sistema..." -ForegroundColor Cyan
Get-ComputerInfo | Select-Object CsName, OsName, OsVersion, WindowsVersion | Out-File "$outputDir\01_SystemInfo.txt"
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 | Out-File "$outputDir\01_RecentPatches.txt"

# 2. Usuarios y grupos críticos
Write-Host "[2/10] Analizando usuarios y grupos..." -ForegroundColor Cyan
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet | Out-File "$outputDir\02_LocalUsers.txt"
Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties * -ErrorAction SilentlyContinue | Select-Object Name, Enabled | Out-File "$outputDir\02_UsersNoExpiry.txt"
Get-ADGroupMember "Domain Admins" -ErrorAction SilentlyContinue | Out-File "$outputDir\02_DomainAdmins.txt"

# 3. Servicios y procesos
Write-Host "[3/10] Revisando servicios y procesos..." -ForegroundColor Cyan
Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, DisplayName, StartType | Out-File "$outputDir\03_RunningServices.txt"
Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 Name, CPU, WorkingSet, Path | Out-File "$outputDir\03_TopProcesses.txt"

# 4. Red y firewall
Write-Host "[4/10] Analizando configuración de red..." -ForegroundColor Cyan
Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress | Out-File "$outputDir\04_IPAddresses.txt"
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} | Out-File "$outputDir\04_ListeningPorts.txt"
Get-NetFirewallProfile | Select-Object Name, Enabled | Out-File "$outputDir\04_FirewallStatus.txt"

# 5. Comparticiones SMB
Write-Host "[5/10] Revisando comparticiones de red..." -ForegroundColor Cyan
Get-SmbShare | Select-Object Name, Path, Description | Out-File "$outputDir\05_SMBShares.txt"
Get-SmbSession | Out-File "$outputDir\05_SMBSessions.txt"

# 6. Tareas programadas
Write-Host "[6/10] Enumerando tareas programadas..." -ForegroundColor Cyan
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | Select-Object TaskName, TaskPath, @{Name="User";Expression={$_.Principal.UserId}} | Out-File "$outputDir\06_ScheduledTasks.txt"

# 7. Software instalado
Write-Host "[7/10] Listando software instalado..." -ForegroundColor Cyan
$software = @()
$software += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
$software += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
$software | Where-Object {$_.DisplayName} | Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName | Out-File "$outputDir\07_InstalledSoftware.txt"

# 8. Certificados
Write-Host "[8/10] Revisando certificados..." -ForegroundColor Cyan
Get-ChildItem Cert:\LocalMachine\My | Select-Object Subject, Issuer, NotAfter | Out-File "$outputDir\08_Certificates.txt"

# 9. Logs críticos
Write-Host "[9/10] Analizando eventos de seguridad..." -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | Out-File "$outputDir\09_FailedLogins.txt"
Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated, LevelDisplayName, Message | Out-File "$outputDir\09_SystemErrors.txt"

# 10. Configuración de seguridad
Write-Host "[10/10] Exportando políticas de seguridad..." -ForegroundColor Cyan
secedit /export /cfg "$outputDir\10_SecurityPolicy.inf" | Out-Null
auditpol /get /category:* | Out-File "$outputDir\10_AuditPolicy.txt"

Write-Host "`n=== AUDITORÍA COMPLETADA ===" -ForegroundColor Green
Write-Host "Revisa los archivos en: $outputDir" -ForegroundColor Yellow
```

### 15.2. Script de Búsqueda de Vulnerabilidades

```powershell
# Script: Vulnerability Scanner
# Descripción: Busca configuraciones inseguras y vulnerabilidades conocidas

$outputDir = "C:\Audit"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

Write-Host "=== ESCANEO DE VULNERABILIDADES ===" -ForegroundColor Red
$findings = @()

# 1. SMBv1 habilitado ⚠️⚠️⚠️
Write-Host "`n[CRÍTICO] Verificando SMBv1..." -ForegroundColor Red
$smbv1 = Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol
if ($smbv1 -eq $true) {
    $findings += "[CRÍTICO] SMBv1 está habilitado - Vector de ransomware WannaCry/NotPetya"
    Write-Host "⚠️ SMBv1 HABILITADO - ALTO RIESGO" -ForegroundColor Red
}

# 2. LLMNR/NBT-NS habilitado ⚠️⚠️
Write-Host "`n[ALTO] Verificando LLMNR/NBT-NS..." -ForegroundColor Yellow
$llmnr = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -ErrorAction SilentlyContinue
if ($llmnr.EnableMulticast -ne 0) {
    $findings += "[ALTO] LLMNR habilitado - Vulnerable a NTLM relay"
}

# 3. Usuarios con contraseñas que nunca expiran ⚠️⚠️
Write-Host "`n[ALTO] Buscando usuarios con contraseñas sin expiración..." -ForegroundColor Yellow
$noExpiry = Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires -ErrorAction SilentlyContinue
if ($noExpiry) {
    $findings += "[ALTO] $($noExpiry.Count) usuarios con PasswordNeverExpires=True"
    $noExpiry | Select-Object Name | Out-File "$outputDir\VULN_UsersNoPasswordExpiry.txt"
}

# 4. Usuarios con Kerberos PreAuth deshabilitado ⚠️⚠️⚠️
Write-Host "`n[CRÍTICO] Buscando usuarios vulnerables a ASREPRoasting..." -ForegroundColor Red
$asreproast = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth -ErrorAction SilentlyContinue
if ($asreproast) {
    $findings += "[CRÍTICO] $($asreproast.Count) usuarios vulnerables a ASREPRoasting"
    $asreproast | Select-Object Name | Out-File "$outputDir\VULN_ASREPRoastable.txt"
}

# 5. Usuarios con SPN (Kerberoastable) ⚠️⚠️
Write-Host "`n[ALTO] Buscando usuarios con SPN (Kerberoasting)..." -ForegroundColor Yellow
$kerberoast = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName -ErrorAction SilentlyContinue
if ($kerberoast) {
    $findings += "[ALTO] $($kerberoast.Count) usuarios con SPN configurado - Kerberoastable"
    $kerberoast | Select-Object Name, ServicePrincipalName | Out-File "$outputDir\VULN_Kerberoastable.txt"
}

# 6. Delegación sin restricciones ⚠️⚠️⚠️
Write-Host "`n[CRÍTICO] Buscando delegación sin restricciones..." -ForegroundColor Red
$unconstrained = Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation -ErrorAction SilentlyContinue
if ($unconstrained) {
    $findings += "[CRÍTICO] $($unconstrained.Count) equipos con delegación sin restricciones"
    $unconstrained | Select-Object Name | Out-File "$outputDir\VULN_UnconstrainedDelegation.txt"
}

# 7. RDP expuesto a Internet ⚠️⚠️⚠️
Write-Host "`n[CRÍTICO] Verificando exposición de RDP..." -ForegroundColor Red
$rdp = Get-NetTCPConnection -LocalPort 3389,29100,32200 -State Listen -ErrorAction SilentlyContinue
if ($rdp) {
    $findings += "[CRÍTICO] RDP en escucha en puertos: $($rdp.LocalPort -join ', ')"
}

# 8. Certificados en claro ⚠️⚠️⚠️
Write-Host "`n[CRÍTICO] Buscando certificados .p12/.pfx..." -ForegroundColor Red
$certs = Get-ChildItem -Path C:\ -Include *.p12,*.pfx -Recurse -ErrorAction SilentlyContinue | Select-Object -First 10 FullName
if ($certs) {
    $findings += "[CRÍTICO] Certificados .p12/.pfx encontrados en el sistema"
    $certs | Out-File "$outputDir\VULN_Certificates.txt"
}

# 9. Servicios con rutas sin comillas ⚠️⚠️
Write-Host "`n[ALTO] Buscando servicios con rutas sin comillas..." -ForegroundColor Yellow
$unquoted = Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike "*`"*" -and $_.PathName -like "* *" -and $_.State -eq "Running"}
if ($unquoted) {
    $findings += "[ALTO] $($unquoted.Count) servicios con rutas sin comillas"
    $unquoted | Select-Object Name, PathName | Out-File "$outputDir\VULN_UnquotedServicePaths.txt"
}

# 10. Archivos world-writable en Program Files ⚠️⚠️
Write-Host "`n[ALTO] Buscando archivos world-writable..." -ForegroundColor Yellow
$writable = Get-ChildItem "C:\Program Files" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 100 | ForEach-Object {
    $acl = Get-Acl $_.FullName -ErrorAction SilentlyContinue
    if ($acl.Access | Where-Object {$_.IdentityReference -eq "Everyone" -and $_.FileSystemRights -match "Write"}) {
        $_
    }
}
if ($writable) {
    $findings += "[ALTO] Archivos con permisos Everyone-Write encontrados"
    $writable | Select-Object FullName | Out-File "$outputDir\VULN_WorldWritableFiles.txt"
}

# Generar reporte resumen
Write-Host "`n=== RESUMEN DE VULNERABILIDADES ===" -ForegroundColor Red
$findings | ForEach-Object {
    Write-Host $_ -ForegroundColor Yellow
}
$findings | Out-File "$outputDir\VULN_Summary.txt"

Write-Host "`nReporte generado en: $outputDir\VULN_Summary.txt" -ForegroundColor Green
```

### 15.3. Script de Hardening Check

```powershell
# Script: Windows Server Hardening Check
# Descripción: Verifica cumplimiento con mejores prácticas de seguridad

$outputDir = "C:\Audit"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

Write-Host "=== VERIFICACIÓN DE HARDENING ===" -ForegroundColor Cyan
$score = 0
$maxScore = 20

# 1. UAC habilitado
Write-Host "`n[1/20] UAC..." -NoNewline
$uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -ExpandProperty EnableLUA
if ($uac -eq 1) { Write-Host " ✓ PASS" -ForegroundColor Green; $score++ } else { Write-Host " ✗ FAIL" -ForegroundColor Red }

# 2. Windows Defender activo
Write-Host "[2/20] Windows Defender..." -NoNewline
$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($defender.RealTimeProtectionEnabled) { Write-Host " ✓ PASS" -ForegroundColor Green; $score++ } else { Write-Host " ✗ FAIL" -ForegroundColor Red }

# 3. Firewall habilitado
Write-Host "[3/20] Firewall..." -NoNewline
$fw = Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $false}
if ($fw.Count -eq 0) { Write-Host " ✓ PASS" -ForegroundColor Green; $score++ } else { Write-Host " ✗ FAIL" -ForegroundColor Red }

# 4. SMBv1 deshabilitado
Write-Host "[4/20] SMBv1 deshabilitado..." -NoNewline
$smbv1 = Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol
if ($smbv1 -eq $false) { Write-Host " ✓ PASS" -ForegroundColor Green; $score++ } else { Write-Host " ✗ FAIL" -ForegroundColor Red }

# 5. Política de contraseñas compleja
Write-Host "[5/20] Política de contraseñas..." -NoNewline
$pwdpolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
if ($pwdpolicy.ComplexityEnabled -and $pwdpolicy.MinPasswordLength -ge 12) { Write-Host " ✓ PASS" -ForegroundColor Green; $score++ } else { Write-Host " ✗ FAIL" -ForegroundColor Red }

# 6. Auditoría activada
Write-Host "[6/20] Auditoría de eventos..." -NoNewline
$audit = auditpol /get /category:"Account Logon" | Select-String "Success and Failure"
if ($audit) { Write-Host " ✓ PASS" -ForegroundColor Green; $score++ } else { Write-Host " ✗ FAIL" -ForegroundColor Red }

# 7. PowerShell logging
Write-Host "[7/20] PowerShell logging..." -NoNewline
$pslog = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
if ($pslog.EnableScriptBlockLogging -eq 1) { Write-Host " ✓ PASS" -ForegroundColor Green; $score++ } else { Write-Host " ✗ FAIL" -ForegroundColor Red }

# 8. BitLocker activo
Write-Host "[8/20] BitLocker..." -NoNewline
$bitlocker = Get-BitLockerVolume -ErrorAction SilentlyContinue | Where-Object {$_.VolumeStatus -eq "FullyEncrypted"}
if ($bitlocker) { Write-Host " ✓ PASS" -ForegroundColor Green; $score++ } else { Write-Host " ✗ FAIL" -ForegroundColor Red }

# 9. Guest account deshabilitado
Write-Host "[9/20] Guest account..." -NoNewline
$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
if ($guest.Enabled -eq $false) { Write-Host " ✓ PASS" -ForegroundColor Green; $score++ } else { Write-Host " ✗ FAIL" -ForegroundColor Red }

# 10. RDP con NLA
Write-Host "[10/20] RDP NLA..." -NoNewline
$nla = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" | Select-Object -ExpandProperty UserAuthentication
if ($nla -eq 1) { Write-Host " ✓ PASS" -ForegroundColor Green; $score++ } else { Write-Host " ✗ FAIL" -ForegroundColor Red }

# 11. Autorun deshabilitado
Write-Host "[11/20] Autorun deshabilitado..." -NoNewline
$autorun = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue
if ($autorun.NoDriveTypeAutoRun -eq 255) { Write-Host " ✓ PASS" -ForegroundColor Green; $score++ } else { Write-Host " ✗ FAIL" -ForegroundColor Red }

# 12. LLMNR deshabilitado
Write-Host "[12/20] LLMNR deshabilitado..." -NoNewline
$llmnr = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ErrorAction SilentlyContinue
if ($llmnr.EnableMulticast -eq 0) { Write-Host " ✓ PASS" -ForegroundColor Green; $score++ } else { Write-Host " ✗ FAIL" -ForegroundColor Red }

# 13. LSA Protection
Write-Host "[13/20] LSA Protection..." -NoNewline
$lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
if ($lsa.RunAsPPL -eq 1) { Write-Host " ✓ PASS" -ForegroundColor Green; $score++ } else { Write-Host " ✗ FAIL" -ForegroundColor Red }

# 14. Credential Guard
Write-Host "[14/20] Credential Guard..." -NoNewline
$credguard = Get-ComputerInfo | Select-Object -ExpandProperty DeviceGuardSecurityServicesRunning -ErrorAction SilentlyContinue
if ($credguard -match "CredentialGuard") { Write-Host " ✓ PASS" -ForegroundColor Green; $score++ } else { Write-Host " ✗ FAIL" -ForegroundColor Red }

# 15. Usuarios admin limitados
Write-Host "[15/20] Domain Admins..." -NoNewline
$admins = Get-ADGroupMember "Domain Admins" -ErrorAction SilentlyContinue
if ($admins.Count -le 5) { Write-Host " ✓ PASS" -ForegroundColor Green; $score++ } else { Write-Host " ✗ FAIL" -ForegroundColor Red }

# 16. Backups configurados
Write-Host "[16/20] Windows Server Backup..." -NoNewline
$backup = Get-WBPolicy -ErrorAction SilentlyContinue
if ($backup) { Write-Host " ✓ PASS" -ForegroundColor Green; $score++ } else { Write-Host " ✗ FAIL" -ForegroundColor Red }

# 17. Actualización automática
Write-Host "[17/20] Windows Update..." -NoNewline
$wu = Get-Service wuauserv
if ($wu.Status -eq "Running") { Write-Host " ✓ PASS" -ForegroundColor Green; $score++ } else { Write-Host " ✗ FAIL" -ForegroundColor Red }

# 18. Logs de seguridad con retención adecuada
Write-Host "[18/20] Retención de logs..." -NoNewline
$seclog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
if ($seclog.MaximumSizeInBytes -ge 512MB) { Write-Host " ✓ PASS" -ForegroundColor Green; $score++ } else { Write-Host " ✗ FAIL" -ForegroundColor Red }

# 19. TLS 1.2 habilitado
Write-Host "[19/20] TLS 1.2..." -NoNewline
$tls = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -ErrorAction SilentlyContinue
if ($tls.Enabled -eq 1) { Write-Host " ✓ PASS" -ForegroundColor Green; $score++ } else { Write-Host " ✗ FAIL" -ForegroundColor Red }

# 20. No hay cuentas sin contraseña
Write-Host "[20/20] Cuentas sin contraseña..." -NoNewline
$nopwd = Get-LocalUser | Where-Object {$_.PasswordRequired -eq $false}
if ($nopwd.Count -eq 0) { Write-Host " ✓ PASS" -ForegroundColor Green; $score++ } else { Write-Host " ✗ FAIL" -ForegroundColor Red }

# Calcular porcentaje
$percentage = [math]::Round(($score / $maxScore) * 100, 2)

Write-Host "`n=== PUNTUACIÓN FINAL ===" -ForegroundColor Cyan
Write-Host "Controles aprobados: $score / $maxScore ($percentage%)" -ForegroundColor $(if ($percentage -ge 80) {"Green"} elseif ($percentage -ge 60) {"Yellow"} else {"Red"})

if ($percentage -ge 80) {
    Write-Host "Estado: BUENO - Configuración de seguridad robusta" -ForegroundColor Green
} elseif ($percentage -ge 60) {
    Write-Host "Estado: ACEPTABLE - Requiere mejoras" -ForegroundColor Yellow
} else {
    Write-Host "Estado: DEFICIENTE - Requiere hardening urgente" -ForegroundColor Red
}

# Guardar resultado
"Hardening Score: $score / $maxScore ($percentage%)" | Out-File "$outputDir\HardeningScore.txt"
```

---

## 📌 NOTAS IMPORTANTES

### Mejores Prácticas

1. **Siempre ejecutar PowerShell como Administrador**
2. **Crear carpeta de auditoría:** `New-Item -ItemType Directory -Path C:\Audit -Force`
3. **Documentar cada comando ejecutado**
4. **Exportar resultados a CSV/TXT para análisis posterior**
5. **NO ejecutar comandos destructivos en producción**

### Comandos que requieren precaución ⚠️

- `Remove-*` - Eliminación de objetos
- `Set-*` - Modificación de configuraciones
- `New-*` - Creación de objetos
- `Enable-*` / `Disable-*` - Cambios de estado

### Comandos de solo lectura (seguros)

- `Get-*` - Obtención de información
- `Select-Object` - Filtrado de propiedades
- `Where-Object` - Filtrado de objetos
- `Export-Csv` - Exportación de datos

---

## 🔗 RECURSOS ADICIONALES

**Módulos útiles:**

```powershell
# Instalar módulos de auditoría
Install-Module -Name PowerShellGet -Force
Install-Module -Name PSWindowsUpdate -Force
Install-Module -Name ActiveDirectory -Force

# Listar módulos instalados
Get-Module -ListAvailable
```

**Referencias:**

- [Microsoft Docs - PowerShell](https://docs.microsoft.com/powershell)
- [Active Directory PowerShell](https://docs.microsoft.com/powershell/module/activedirectory)
- [Windows Security Baseline](https://docs.microsoft.com/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines)
