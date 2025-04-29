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