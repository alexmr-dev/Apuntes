> Los servidores Windows pueden gestionarse localmente mediante las tareas de administración del Administrador del Servidor en servidores remotos. La administración remota está habilitada por defecto a partir de Windows Server 2016. Esta característica forma parte de las funciones de administración de hardware de Windows que gestionan el hardware del servidor de manera local y remota. Estas funciones incluyen un servicio que implementa el protocolo WS-Management, diagnóstico y control de hardware a través de controladores de gestión de placa base, así como una API COM y objetos de script que permiten escribir aplicaciones que se comunican de manera remota mediante el protocolo WS-Management.

Los principales componentes utilizados para la administración remota de Windows y servidores Windows son:

- **Remote Desktop Protocol (RDP)**
- **Windows Remote Management (WinRM)**
- **Windows Management Instrumentation (WMI)**

### RDP

El **Remote Desktop Protocol (RDP)** es un protocolo desarrollado por Microsoft para el acceso remoto a una computadora con el sistema operativo Windows. Este protocolo permite transmitir comandos de visualización y control a través de la interfaz gráfica de usuario (GUI) de forma cifrada sobre redes IP. RDP trabaja en la capa de aplicación del modelo de referencia TCP/IP, utilizando típicamente el puerto TCP 3389 como protocolo de transporte. Sin embargo, el protocolo UDP sin conexión también puede utilizar el puerto 3389 para administración remota.

Para establecer una sesión RDP, tanto el firewall de la red como el firewall del servidor deben permitir conexiones externas. Si se usa **Network Address Translation (NAT)** entre el cliente y el servidor, el equipo remoto necesita la dirección IP pública para acceder al servidor, y además se debe configurar el **port forwarding** en el router NAT hacia el servidor.

RDP ha manejado la **Seguridad en la Capa de Transporte (TLS/SSL)** desde Windows Vista, lo que garantiza que todos los datos, especialmente el proceso de inicio de sesión, estén protegidos en la red mediante un buen cifrado. Sin embargo, muchos sistemas Windows no exigen este cifrado y siguen aceptando cifrado inadecuado a través de la seguridad RDP. A pesar de esto, un atacante aún no está completamente bloqueado, ya que los certificados que proporcionan la identidad son auto-firmados por defecto, lo que significa que el cliente no puede distinguir entre un certificado genuino y uno falsificado, lo que genera una advertencia de certificado al usuario.

El servicio de **Escritorio Remoto** está instalado por defecto en los servidores Windows y no requiere aplicaciones externas adicionales. Este servicio puede ser activado mediante el Administrador del Servidor y tiene la configuración predeterminada para permitir conexiones solo a los hosts con **Autenticación a Nivel de Red (NLA)**.

### Footprinting a RDP

Escaneando el servicio RDP puede darnos mucha información sobre el host. Por ejemplo, podemos determinar si NLA está habilitado en el servidor o no, la versión de producto y el hostname.

#### Usando nmap

```shell-session
amr251@htb[/htb]$ nmap -sV -sC 10.129.201.248 -p3389 --script rdp*

Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-06 15:45 CET
Nmap scan report for 10.129.201.248
Host is up (0.036s latency).

PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-enum-encryption: 
|   Security layer
|     CredSSP (NLA): SUCCESS
|     CredSSP with Early User Auth: SUCCESS
|_    RDSTLS: SUCCESS
| rdp-ntlm-info: 
|   Target_Name: ILF-SQL-01
|   NetBIOS_Domain_Name: ILF-SQL-01
|   NetBIOS_Computer_Name: ILF-SQL-01
|   DNS_Domain_Name: ILF-SQL-01
|   DNS_Computer_Name: ILF-SQL-01
|   Product_Version: 10.0.17763
|_  System_Time: 2021-11-06T13:46:00+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.26 seconds
```

Además, podemos usar `--packet-trace` para seguir los paquetes individuales e inspeccionar su contenido de forma manual. Podemos ver que `RDP cookies` (`mstshash=nmap`) usado por nmap para interactuar con el servidor RDP puede ser identificado por cazadores de amenazas y varios servicios de seguridad como EDR, y pueden echarnos como pentesters en redes reforzadas. Un script denominado [rdp-sec-check.pl](https://github.com/CiscoCXSecurity/rdp-sec-check) ha sido desarrollado por Cisco y puede identificar las configuraciones de servidores RDP sin autenticarse mediante handshakes.

La autenticación a dichos servidores RDP puede realizarse de muchas formas. Por ejemplo, podemos conectarnos a servidores RDP desde Linux usando `xfreerdp`, `rdesktop`, o `Remmina` e interactuar con la GUI del servidor:

```bash
xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248
```

### WinRM

**Windows Remote Management (WinRM)** es un protocolo de administración remota integrado en Windows, basado en la línea de comandos. WinRM utiliza el **Simple Object Access Protocol (SOAP)** para establecer conexiones con hosts remotos y sus aplicaciones. Debido a esto, WinRM debe ser habilitado y configurado explícitamente desde Windows 10. WinRM usa los puertos TCP 5985 y 5986 para la comunicación, siendo el puerto 5986 utilizado para **HTTPS**. Los puertos 80 y 443 fueron previamente usados para esta tarea, pero el puerto 80 se bloqueó por razones de seguridad, por lo que actualmente se utilizan los puertos 5985 y 5986. Con WinRM, es posible ejecutar comandos remotos en otro servidor.

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

