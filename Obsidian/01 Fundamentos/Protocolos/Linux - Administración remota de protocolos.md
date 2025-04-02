### SSH

> Secure Shell (SSH) permite que dos computadoras establezcan una conexión cifrada y directa dentro de una red potencialmente insegura, utilizando el puerto estándar TCP 22. Esto es esencial para evitar que terceros intercepten el flujo de datos y accedan a información sensible. Además, el servidor SSH puede configurarse para permitir conexiones solo desde clientes específicos.

Una ventaja de SSH es que el protocolo es compatible con todos los sistemas operativos comunes. Aunque originalmente fue una aplicación para Unix, está implementado de forma nativa en todas las distribuciones de Linux y en macOS. En Windows, SSH también se puede utilizar instalando un programa adecuado.

El conocido servidor OpenBSD SSH (OpenSSH), presente en las distribuciones de Linux, es una bifurcación de código abierto del servidor SSH original y comercial de SSH Communication Security. En consecuencia, existen dos protocolos en competencia: **SSH-1 y SSH-2**.

SSH-2, también conocido como **SSH versión 2**, es un protocolo más avanzado que SSH versión 1 en términos de cifrado, velocidad, estabilidad y seguridad. Por ejemplo, **SSH-1 es vulnerable a ataques MITM (Man-in-the-Middle), mientras que SSH-2 no lo es**. OpenSSH tiene 6 formas diferentes de autenticarse:

1. Por contraseña
2. Por clave pública
3. Basado en host
4. Autenticación por teclado
5. Desafío-respuesta
6. Autenticación GSSAPI

### Autenticación por clave pública

El servidor SSH se autentica enviando un certificado cifrado al cliente para verificar su identidad, evitando suplantaciones. Luego, el cliente debe demostrar que tiene acceso autorizado, lo que puede hacerse con contraseña o mediante un par de claves (pública y privada). La clave privada se almacena de forma segura en el cliente y solo se desbloquea con una passphrase, mientras que la clave pública se guarda en el servidor. Durante la conexión, el servidor envía un desafío cifrado con la clave pública del cliente, quien lo resuelve con su clave privada y envía la respuesta para validar la autenticación. Una vez iniciada la sesión, la passphrase solo se introduce una vez, y al cerrar sesión, se evita el acceso no autorizado.

### Configuración por defecto

El archivo `sshd_config`, responsable del servidor OpenSSH, solo tiene unas pocas de configuraciones por defecto. Sin embargo, por defecto incluye X11 forwarding, que contenía una vulnerabilidad en la versión 7.2p1 de OpenSSH. No necesitamos un GUI para administrar nuestros servidores

```shell-session
amr251@htb[/htb]$ cat /etc/ssh/sshd_config  | grep -v "#" | sed -r '/^\s*$/d'
```

### Configuración peligrosa

A pesar de que SSH es de los más seguros que existen, algunas configuraciones pueden hacer que el servidor sea vulnerable a ataques fáciles de realizar.

| Configuración               | Descripción                                        |
|-----------------------------|----------------------------------------------------|
| PasswordAuthentication yes  | Permite la autenticación basada en contraseña.   |
| PermitEmptyPasswords yes    | Permite el uso de contraseñas vacías.            |
| PermitRootLogin yes         | Permite iniciar sesión como usuario root.        |
| Protocol 1                 | Usa una versión obsoleta de cifrado.             |
| X11Forwarding yes          | Permite el reenvío de X11 para aplicaciones GUI. |
| AllowTcpForwarding yes     | Permite el reenvío de puertos TCP.               |
| PermitTunnel               | Permite la creación de túneles.                  |
| DebianBanner yes           | Muestra un banner específico al iniciar sesión.  |

### Footprinting al servicio

Una de las herramientas que podemos usar para hacer fingerprinting al servidor SSH es [ssh-audit](https://github.com/jtesta/ssh-audit). Comprueba en el lado del cliente y del servidor configuración y muestra información general y qué algoritmos de cifrado se están utilizando. 

```shell-session
amr251@htb[/htb]$ git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
amr251@htb[/htb]$ ./ssh-audit.py 10.129.14.132
```

### Cambiar forma de autenticarse

```shell-session
amr251@htb[/htb]$ ssh -v cry0l1t3@10.129.14.132

OpenSSH_8.2p1 Ubuntu-4ubuntu0.3, OpenSSL 1.1.1f  31 Mar 2020
debug1: Reading configuration data /etc/ssh/ssh_config 
...SNIP...
debug1: Authentications that can continue: publickey,password,keyboard-interactive
```

Para ataques de fuerza bruta, podemos especificar el método de autenticación con la opción de cliente SSH `PreferredAuthentications`, sirviéndonos de lo que hemos mencionado arriba, ya que existen 6 formas de autenticarse.

```shell-session
amr251@htb[/htb]$ ssh -v cry0l1t3@10.129.14.132 -o PreferredAuthentications=password

OpenSSH_8.2p1 Ubuntu-4ubuntu0.3, OpenSSL 1.1.1f  31 Mar 2020
debug1: Reading configuration data /etc/ssh/ssh_config
...SNIP...
debug1: Authentications that can continue: publickey,password,keyboard-interactive
debug1: Next authentication method: password

cry0l1t3@10.129.14.132's password:
```

### Rsync

Rsync es una herramienta rápida y eficiente para copiar archivos localmente o en hosts remotos. Su algoritmo de transferencia delta minimiza la cantidad de datos enviados al transferir solo las diferencias entre los archivos origen y destino. Es ampliamente usado para copias de seguridad y replicación, identificando archivos modificados según su tamaño o fecha de modificación. Usa el puerto `873` por defecto y puede utilizar SSH para transferencias seguras.

Rsync puede ser explotado para listar y descargar archivos de carpetas compartidas, a veces sin autenticación. Si se encuentran credenciales en una prueba de penetración, vale la pena revisar su reutilización, ya que podrían permitir el acceso a archivos sensibles y facilitar el acceso remoto al sistema objetivo.

#### Escaneando por Rsync

```shell-session
amr251@htb[/htb]$ sudo nmap -sV -p 873 127.0.0.1

Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-19 09:31 EDT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.0058s latency).

PORT    STATE SERVICE VERSION
873/tcp open  rsync   (protocol version 31)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.13 seconds
```

#### Probando shares accesibles

```shell-session
amr251@htb[/htb]$ nc -nv 127.0.0.1 873

(UNKNOWN) [127.0.0.1] 873 (rsync) open
@RSYNCD: 31.0
@RSYNCD: 31.0
#list
dev            	Dev Tools
@RSYNCD: EXIT
```

#### Enumerando un Open Share

En el siguiente ejemplo podemos ver un share llamado `dev`, que podemos enumerar más

```shell-session
amr251@htb[/htb]$ rsync -av --list-only rsync://127.0.0.1/dev

receiving incremental file list
drwxr-xr-x             48 2022/09/19 09:43:10 .
-rw-r--r--              0 2022/09/19 09:34:50 build.sh
-rw-r--r--              0 2022/09/19 09:36:02 secrets.yaml
drwx------             54 2022/09/19 09:43:10 .ssh

sent 25 bytes  received 221 bytes  492.00 bytes/sec
total size is 0  speedup is 0.00
```

Si identificamos archivos interesantes o directorios accesibles (como los que contienen claves SSH), podemos sincronizar todos los archivos en nuestro host de ataque con:

```
rsync -av rsync://127.0.0.1/dev
```

Si Rsync está configurado para usar SSH, debemos agregar el parámetro `-e ssh`, o especificar un puerto no estándar con:

```
rsync -av -e "ssh -p2222" usuario@host:/ruta/destino
```

### R-Services

Los R-Services son un conjunto de servicios para el acceso remoto entre sistemas Unix a través de TCP/IP. Fueron desarrollados en la Universidad de California, Berkeley, y fueron el estándar hasta que fueron reemplazados por SSH debido a sus vulnerabilidades de seguridad. Al igual que Telnet, transmiten datos sin cifrar, lo que los hace vulnerables a ataques MITM (Man-in-the-Middle).

Operan en los puertos 512, 513 y 514 y requieren programas específicos (r-commands) para su uso. Aunque han caído en desuso, siguen apareciendo en sistemas como Solaris, HP-UX y AIX, por lo que es importante conocerlos en pruebas de penetración.

| Comando  | Servicio Daemon | Puerto | Protocolo de Transporte | Descripción |
|----------|----------------|--------|-------------------------|-------------|
| rcp      | rshd           | 514    | TCP                     | Copia un archivo o directorio de forma bidireccional entre el sistema local y un sistema remoto (o entre dos sistemas remotos). Funciona como el comando `cp` en Linux, pero no advierte al usuario si sobrescribe archivos existentes. |
| rsh      | rshd           | 514    | TCP                     | Abre un shell en una máquina remota sin necesidad de un procedimiento de inicio de sesión. Se basa en las entradas de confianza en los archivos `/etc/hosts.equiv` y `.rhosts` para la validación. |
| rexec    | rexecd         | 512    | TCP                     | Permite a un usuario ejecutar comandos en una máquina remota. Requiere autenticación mediante un nombre de usuario y contraseña a través de un socket de red sin cifrar. La autenticación puede ser omitida por las entradas de confianza en los archivos `/etc/hosts.equiv` y `.rhosts`. |
| rlogin   | rlogind        | 513    | TCP                     | Permite a un usuario iniciar sesión en un host remoto a través de la red. Funciona de manera similar a `telnet`, pero solo puede conectarse a sistemas Unix-like. La autenticación puede ser omitida por las entradas de confianza en los archivos `/etc/hosts.equiv` y `.rhosts`. |

### /etc/hosts.equiv

```shell-session
amr251@htb[/htb]$ cat /etc/hosts.equiv

# <hostname> <local username>
pwnbox cry0l1t3
```

### Escaneando R-Services

```shell-session
amr251@htb[/htb]$ sudo nmap -sV -p 512,513,514 10.0.17.2

Starting Nmap 7.80 ( https://nmap.org ) at 2022-12-02 15:02 EST
Nmap scan report for 10.0.17.2
Host is up (0.11s latency).

PORT    STATE SERVICE    VERSION
512/tcp open  exec?
513/tcp open  login?
514/tcp open  tcpwrapped

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 145.54 seconds
```

### Archivo .rhosts de ejemplo

```shell-session
amr251@htb[/htb]$ cat .rhosts

htb-student     10.0.17.5
+               10.0.17.10
+               +
```

Los archivos de configuración siguen la sintaxis `<usuario> <dirección IP>` o `<usuario> <nombre de host>`. Además, el modificador `+` actúa como un comodín, permitiendo acceso a cualquier usuario externo. Por ejemplo, si se usa `+`, cualquier usuario externo podría acceder a los comandos remotos (`r-commands`) desde la cuenta `htb-student` a través del host con la IP `10.0.17.10`.

Si estos archivos están mal configurados, un atacante podría autenticarse como otro usuario sin necesidad de credenciales, lo que podría permitirle ejecutar código en el sistema objetivo. Ahora que comprendemos este posible abuso, podemos intentar iniciar sesión en un host de destino usando `rlogin`.
### Iniciando sesión usando Rlogin

```shell-session
amr251@htb[/htb]$ rlogin 10.0.17.2 -l htb-student

Last login: Fri Dec  2 16:11:21 from localhost

[htb-student@localhost ~]$
```

A partir de la información obtenida, vemos que el usuario `htb-student` está autenticado en el host `workstn01`, mientras que el usuario `root` está autenticado en el host `web01`. Esto puede ser útil al buscar posibles nombres de usuario para ataques adicionales en los hosts de la red. Sin embargo, el demonio `rwho` transmite periódicamente información sobre los usuarios autenticados, por lo que podría ser beneficioso observar el tráfico de la red.

### Listado de Usuarios Autenticados Usando Rusers

Para obtener más información en conjunto con `rwho`, podemos utilizar el comando `rusers`. Este comando nos proporcionará un registro detallado de todos los usuarios autenticados en la red, incluyendo detalles como el nombre de usuario, el nombre del host al que se accedió, el TTY en el que el usuario está conectado, la fecha y hora en que se inició sesión, el tiempo desde la última interacción del usuario con el teclado y el host remoto desde el cual inició sesión (si aplica).

```shell-session
amr251@htb[/htb]$ rusers -al 10.0.17.5

htb-student     10.0.17.5:console          Dec 2 19:57     2:25
```
