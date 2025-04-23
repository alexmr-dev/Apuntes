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

## Caza de credenciales con Linux

Resumen de las principales fuentes que pueden proporcionarnos credenciales:
### 1. Archivos

Uno de los principios de Linux es que todo es un archivo. Por tanto, teniendo esto en mente, podemos buscar, encontrar y filtrar los archivos apropiados para lo que necesitemos. 
##### 1.1 Archivos de configuración

```bash
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

File extension:  .conf
...SNIP...
```

Otra opción es escanear directamente cada archivo con la extensión de archivo específica y mostrar los contenidos. En el siguiente ejemplo, buscamos `user`,`password`,`pass` en cada archivo con extensión `.cnf`:

```bash
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done

File:  /snap/core18/2128/etc/ssl/openssl.cnf
challengePassword		= A challenge password

File:  /usr/share/ssl-cert/ssleay.cnf
...SNIP...
```
##### 1.2 Bases de datos

```bash
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done

DB File extension:  .sql

DB File extension:  .db
...SNIP...

DB File extension:  .*db
...SNIP...

DB File extension:  .db*
...SNIP...
```
##### 1.3 Notas

```bash
find /home/* -type f -name "*.txt" -o ! -name "*.*"

/home/cry0l1t3/.config/caja/desktop-metadata
/home/cry0l1t3/.config/clipit/clipitrc
/home/cry0l1t3/.config/dconf/user
/home/cry0l1t3/.mozilla/firefox/bh4w5vd0.default-esr/pkcs11.txt
/home/cry0l1t3/.mozilla/firefox/bh4w5vd0.default-esr/serviceworker.txt
...SNIP...
```
##### 1.4 Scripts

```bash
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done

File extension:  .py

File extension:  .pyc

File extension:  .pl

File extension:  .go

File extension:  .jar

File extension:  .c
```
##### 1.5 Tareas cron

Las tareas programadas, conocidas como _cron jobs_, son procesos automatizados que se ejecutan de forma independiente en sistemas Linux. Estas tareas pueden ser comandos, programas o scripts que se ejecutan en momentos específicos según la configuración establecida.​

- **/etc/crontab:** Archivo principal de configuración del sistema, donde se definen las tareas programadas globales.
- **/etc/cron.d/:** Directorio que contiene archivos adicionales de configuración de cron, permitiendo una gestión modular de las tareas programadas.
- **/etc/cron.daily/, /etc/cron.hourly/, /etc/cron.monthly/, /etc/cron.weekly/:** Directorios que contienen scripts que se ejecutan diariamente, cada hora, mensualmente o semanalmente, respectivamente.

```bash
cat /etc/crontab 
```

```bash
ls -la /etc/cron.*/

/etc/cron.d/:
total 28
drwxr-xr-x 1 root root  106  3. Jan 20:27 .
drwxr-xr-x 1 root root 5728  1. Feb 00:06 ..
-rw-r--r-- 1 root root  201  1. Mär 2021  e2scrub_all
-rw-r--r-- 1 root root  331  9. Jan 2021  geoipupdate
-rw-r--r-- 1 root root  607 25. Jan 2021  john
-rw-r--r-- 1 root root  589 14. Sep 2020  mdadm
-rw-r--r-- 1 root root  712 11. Mai 2020  php
-rw-r--r-- 1 root root  102 22. Feb 2021  .placeholder
-rw-r--r-- 1 root root  396  2. Feb 2021  sysstat

/etc/cron.daily/:
total 68
drwxr-xr-x 1 root root  252  6. Jan 16:24 .
drwxr-xr-x 1 root root 5728  1. Feb 00:06 ..
...SNIP...
```
##### 1.6 Claves SSH

Las claves SSH funcionan como "tarjetas de acceso" en el protocolo SSH, permitiendo la autenticación sin necesidad de contraseñas. Consisten en dos archivos:​

- **Clave privada**: almacenada de forma segura en el cliente.
- **Clave pública**: copiada al servidor para autenticar al cliente.​

Aunque ambas claves están relacionadas, conocer la clave pública no permite derivar la clave privada, ya que están diseñadas criptográficamente para ser unidireccionales. Este sistema permite inicios de sesión automáticos y seguros sin contraseñas.​

**Claves privadas**

```bash
grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"

/home/cry0l1t3/.ssh/internal_db:1:-----BEGIN OPENSSH PRIVATE KEY-----
```

**Claves públicas**

```bash
grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"

/home/cry0l1t3/.ssh/internal_db.pub:1:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCraK
```
### 2. Historial

**Todos los archivos de historial proporcionan información crucial sobre el curso actual y pasado/histórico de los procesos. Nos interesan los archivos que almacenan el historial de comandos de los usuarios y los registros que contienen información sobre los procesos del sistema.**​

##### 2.1 Logs

| Archivo de Log             | Descripción                                                                                         |
|----------------------------|-----------------------------------------------------------------------------------------------------|
| `/var/log/messages`        | Registros generales del sistema, incluyendo mensajes del kernel y eventos de servicios.             |
| `/var/log/syslog`          | Similar a `/var/log/messages`, pero con un enfoque en eventos del sistema y servicios.              |
| `/var/log/auth.log`        | Registros de autenticación, incluyendo inicios de sesión y eventos relacionados con la seguridad.    |
| `/var/log/secure`          | Similar a `/var/log/auth.log`, pero utilizado en sistemas basados en RedHat/CentOS.                  |
| `/var/log/boot.log`        | Información relacionada con el proceso de arranque del sistema.                                      |
| `/var/log/dmesg`           | Mensajes del kernel relacionados con la detección de hardware y controladores.                      |
| `/var/log/kern.log`        | Registros del kernel, incluyendo advertencias y errores relacionados con el núcleo del sistema.     |
| `/var/log/faillog`         | Información sobre intentos fallidos de inicio de sesión.                                             |
| `/var/log/cron`            | Información relacionada con la ejecución de trabajos programados por cron.                          |
| `/var/log/mail.log`        | Registros del servidor de correo, incluyendo envíos y recepción de correos electrónicos.             |
| `/var/log/httpd/`          | Directorio que contiene los registros de Apache, incluyendo `access_log` y `error_log`.              |
| `/var/log/mysqld.log`      | Registros del servidor MySQL, incluyendo información sobre el inicio, detención y errores.          |

##### 2.2 Historial de comandos

**En el historial de los comandos ingresados en distribuciones de Linux que utilizan Bash como shell estándar, encontramos los archivos asociados en `.bash_history`. Sin embargo, otros archivos como `.bashrc` o `.bash_profile` pueden contener información importante.**

```bash
tail -n5 /home/*/.bash*

==> /home/cry0l1t3/.bash_history <==
vim ~/testing.txt
vim ~/testing.txt
chmod 755 /tmp/api.py
su
/tmp/api.py cry0l1t3 6mX4UP1eWH3HXK

==> /home/cry0l1t3/.bashrc <==
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi
```
### 3. Memoria

Para recuperar este tipo de información en distribuciones Linux, existe una herramienta llamada [mimipenguin](https://github.com/huntergregal/mimipenguin), que facilita todo el proceso. Sin embargo, esta herramienta requiere permisos de administrador (root) para funcionar correctamente. 

```shell-session
cry0l1t3@unixclient:~$ sudo python3 mimipenguin.py
[sudo] password for cry0l1t3: 

[SYSTEM - GNOME]	cry0l1t3:WLpAEXFa0SbqOHY


cry0l1t3@unixclient:~$ sudo bash mimipenguin.sh 
[sudo] password for cry0l1t3: 

MimiPenguin Results:
[SYSTEM - GNOME]          cry0l1t3:WLpAEXFa0SbqOHY
```

También podemos usar `LaZagne`, que nos permite acceder a más recursos y extraer credenciales. 

```shell-session
cry0l1t3@unixclient:~$ sudo python2.7 laZagne.py all

|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|

------------------- Shadow passwords -----------------

[+] Hash found !!!
Login: systemd-coredump
Hash: !!:18858::::::

[+] Hash found !!!
Login: sambauser
Hash: $6$wgK4tGq7Jepa.V0g$QkxvseL.xkC3jo682xhSGoXXOGcBwPLc2CrAPugD6PYXWQlBkiwwFs7x/fhI.8negiUSPqaWyv7wC8uwsWPrx1:18862:0:99999:7:::

[+] Password found !!!
Login: cry0l1t3
Password: WLpAEXFa0SbqOHY


[+] 3 passwords have been found.
For more information launch it again with the -v option

elapsed time = 3.50091600418
```

### 4. Llaveros
##### 4.1 Credenciales almacenadas en los navegadores

Por ejemplo, cuando almacenamos credenciales para una página web en el navegador Firefox, se cifran y se guardan en el archivo `logins.json` en el sistema. Sin embargo, esto no significa que estén completamente seguras allí. Muchos empleados almacenan estos datos de inicio de sesión en su navegador sin sospechar que pueden ser fácilmente descifrados y utilizados en contra de la empresa.​

```shell-session
cry0l1t3@unixclient:~$ ls -l .mozilla/firefox/ | grep default 

drwx------ 11 cry0l1t3 cry0l1t3 4096 Jan 28 16:02 1bplpd86.default-release
drwx------  2 cry0l1t3 cry0l1t3 4096 Jan 28 13:30 lfx3lvhb.default
```

```shell-session
cry0l1t3@unixclient:~$ cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .

{
  "nextId": 2,
  "logins": [
    {
      "id": 1,
      "hostname": "https://www.inlanefreight.com",
      "httpRealm": null,
      "formSubmitURL": "https://www.inlanefreight.com",
      "usernameField": "username",
      "passwordField": "password",
      "encryptedUsername": "MDoEEPgAAAA...SNIP...1liQiqBBAG/8/UpqwNlEPScm0uecyr",
      "encryptedPassword": "MEIEEPgAAAA...SNIP...FrESc4A3OOBBiyS2HR98xsmlrMCRcX2T9Pm14PMp3bpmE=",
      "guid": "{412629aa-4113-4ff9-befe-dd9b4ca388e2}",
      "encType": 1,
      "timeCreated": 1643373110869,
      "timeLastUsed": 1643373110869,
      "timePasswordChanged": 1643373110869,
      "timesUsed": 1
    }
  ],
  "potentiallyVulnerablePasswords": [],
  "dismissedBreachAlertsByLoginGUID": {},
  "version": 3
}
```

Podemos hacer uso de [Firefox Decrypt](https://github.com/unode/firefox_decrypt) para desencriptar credenciales. Eso sí, necesitamos tener Python 3.9 instslado para correrlo con la última versión, de lo contrario, podemos usar `Firefox Decrypt 0.7.0` con Python2

```shell-session
amr251@htb[/htb]$ python3.9 firefox_decrypt.py

Select the Mozilla profile you wish to decrypt
1 -> lfx3lvhb.default
2 -> 1bplpd86.default-release

2

Website:   https://testing.dev.inlanefreight.com
Username: 'test'
Password: 'test'

Website:   https://www.inlanefreight.com
Username: 'cry0l1t3'
Password: 'FzXUxJemKm6g2lGh'
```

Con LaZagne, si añadimos `browsers` al final también podemos recuperar información del navegador.

```shell-session
cry0l1t3@unixclient:~$ python3 laZagne.py browsers
```

### Archivo passwd

El archivo `/etc/passwd` contiene información sobre cada usuario existente en el sistema y puede ser leído por todos los usuarios y servicios. Cada entrada en el archivo `/etc/passwd` identifica a un usuario en el sistema. Cada entrada tiene siete campos que contienen una especie de base de datos con información sobre el usuario en particular, donde un colon (`:`) separa la información.

| `cry0l1t3` | `:` | `x`              | `:` | `1000` | `:` | `1000` | `:` | `cry0l1t3,,,`   | `:` | `/home/cry0l1t3` | `:` | `/bin/bash` |
| ---------- | --- | ---------------- | --- | ------ | --- | ------ | --- | --------------- | --- | ---------------- | --- | ----------- |
| Usuario    |     | Info. contraseña |     | UID    |     | GUID   |     | Nombre completo |     | Home             |     | Shell       |
Normalmente, lo que encontramos en este campo es una **"x"**, lo que indica que la contraseña está almacenada (en forma cifrada) en el archivo `/etc/shadow`.  
No obstante, si el archivo `/etc/passwd` **es escribible por error**, un atacante podría **vaciar este campo** para el usuario `root`. Esto provocaría que el sistema **no solicite una contraseña** al intentar iniciar sesión como `root`, permitiendo así el acceso sin autenticación.

##### Editando /etc/passw - Antes

```shell-session
root:x:0:0:root:/root:/bin/bash
```

##### Editando /etc/passwd - Después

```shell-session
root::0:0:root:/root:/bin/bash
```

##### Root sin contraseña

```bash
head -n 1 /etc/passwd

root::0:0:root:/root:/bin/bash

su

[root@parrot]─[/home/cry0l1t3]#
```

### Archivo shadow

Dado que la lectura de los valores hash de las contraseñas puede poner en peligro todo el sistema, se desarrolló el archivo **`/etc/shadow`**, que tiene un formato similar a `/etc/passwd` pero está dedicado exclusivamente al almacenamiento y gestión de contraseñas.

Este archivo contiene toda la información relacionada con las contraseñas de los usuarios creados en el sistema.  
Por ejemplo, **si un usuario aparece en `/etc/passwd` pero no tiene entrada en `/etc/shadow`, se considera un usuario inválido**.

Además, el archivo **`/etc/shadow` solo puede ser leído por usuarios con privilegios de administrador (root)**, lo que lo hace mucho más seguro.

| `cry0l1t3` | `:` | `$6$wBRzy$...SNIP...x9cDWUxW1` | `:` | `18937`          | `:` | `0`            | `:` | `99999`        | `:` | `7`              | `:`                    | `:`                 | `:`      |
| ---------- | --- | ------------------------------ | --- | ---------------- | --- | -------------- | --- | -------------- | --- | ---------------- | ---------------------- | ------------------- | -------- |
| Usuario    |     | Contraseña encriptada          |     | Último cambio PW |     | Min. PW tiempo |     | Max. PW tiempo |     | Período de aviso | Período de inactividad | Fecha de expiración | No usado |
```shell-session
[cry0l1t3@parrot]─[~]$ sudo cat /etc/shadow

root:*:18747:0:99999:7:::
sys:!:18747:0:99999:7:::
...SNIP...
cry0l1t3:$6$wBRzy$...SNIP...x9cDWUxW1:18937:0:99999:7:::
```

Si el campo de la contraseña contiene un carácter como **`!`** o **`*`**, el usuario **no puede iniciar sesión** utilizando una contraseña de Unix. Sin embargo, **otros métodos de autenticación**, como **Kerberos** o **autenticación basada en claves**, aún pueden utilizarse.

La contraseña cifrada también tiene un formato particular, a partir del cual podemos obtener cierta información: `$<tipo>$<salt>$<hash>`

##### Tipos de algoritmos

- `$1$` – **MD5**
- `$2a$` – **Blowfish**
- `$2y$` – **Eksblowfish**
- `$5$` – **SHA-256**
- `$6$` – **SHA-512**

### Opasswd

La biblioteca **PAM** (_Pluggable Authentication Module_), específicamente **`pam_unix.so`**, puede evitar que se reutilicen contraseñas antiguas.  
El archivo donde se almacenan estas contraseñas anteriores es **`/etc/security/opasswd`**.

También se requieren **permisos de administrador (root)** para leer este archivo, siempre que sus permisos no hayan sido modificados manualmente.

```shell-session
amr251@htb[/htb]$ sudo cat /etc/security/opasswd

cry0l1t3:1000:2:$1$HjFAfYTG$qNDkF0zJ3v8ylCOrKB0kt0,$1$kcUjWZJX$E9uMSmiQeRh4pAAgzuvkq1
```

### Rompiendo credenciales Linux

##### Unshadow

```shell-session
amr251@htb[/htb]$ sudo cp /etc/passwd /tmp/passwd.bak 
amr251@htb[/htb]$ sudo cp /etc/shadow /tmp/shadow.bak 
amr251@htb[/htb]$ unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

```shell-session
amr251@htb[/htb]$ hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

##### MD5

```shell-session
amr251@htb[/htb]$ cat md5-hashes.list

qNDkF0zJ3v8ylCOrKB0kt0
E9uMSmiQeRh4pAAgzuvkq1
```

```shell-session
amr251@htb[/htb]$ hashcat -m 500 -a 0 md5-hashes.list rockyou.txt
```