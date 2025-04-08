---

---
-----
- Tags: #bash #CTF #linux 
--------
## ¿En qué consiste?

> En este documento vamos a ver diferentes formas de escalar los privilegios, es decir, pasar de ser un usuario sin apenas permisos a convertirnos en root. Existen muchas maneras de escalar privilegios, por lo que en este documento se intentará listar las más famosas. Una web muy interesante para comprobar formas de escalar privilegios es [GTFOBins](https://gtfobins.github.io)

### Abusando de privilegios SUID

Un privilegio **SUID** (**Set User ID**) es un permiso especial que se puede establecer en un archivo binario en sistemas Unix/Linux. Este permiso le da al usuario que ejecuta el archivo los **mismos privilegios** que el **propietario** del archivo.

Podemos detectar binarios que sean SUID de la siguiente manera:

```bash
find / -perm -4000
```

Para prevenir el abuso de privilegios SUID, se recomienda limitar el número de archivos con permisos SUID y asegurarse de que solo se otorguen a archivos que requieran este permiso para funcionar correctamente. Además, es importante monitorear regularmente el sistema para detectar cambios inesperados en los permisos de los archivos y para buscar posibles brechas de seguridad.

### Detección de tareas Cron

Una tarea **cron** es una tarea programada en sistemas Unix/Linux que se ejecuta en un momento determinado o en intervalos regulares de tiempo. Estas tareas se definen en un archivo **crontab** que especifica qué comandos deben ejecutarse y cuándo deben ejecutarse.

La detección y explotación de tareas cron es una técnica utilizada por los atacantes para elevar su nivel de acceso en un sistema comprometido. Por ejemplo, si un atacante detecta que un archivo está siendo ejecutado por el usuario “root” a través de una tarea cron que se ejecuta a intervalos regulares de tiempo, y se da cuenta de que los permisos definidos en el archivo están mal configurados, podría manipular el contenido del mismo para incluir instrucciones maliciosas las cuales serían ejecutadas de forma privilegiada como el usuario ‘root’, dado que corresponde al usuario que está ejecutando dicho archivo.

Para detectar tareas cron, los atacantes pueden utilizar herramientas como **[Pspy]**([https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)). Pspy es una herramienta de línea de comandos que monitorea las tareas que se ejecutan en segundo plano en un sistema Unix/Linux y muestra las nuevas tareas que se inician.

En Linux y Windows existen métodos para ejecutar scripts a intervalos específicos para realizar una tarea. Algunos ejemplos son tener un análisis antivirus que se ejecute cada hora o un script de respaldo que se ejecute cada 30 minutos. Por lo general, existen dos formas de aprovechar las tareas programadas (en Windows) o los cron jobs (en Linux) para escalar privilegios:

- Agregar nuevas tareas programadas/cron jobs.
- Engañar al sistema para que ejecute un software malicioso.

La forma más sencilla es verificar si se nos permite agregar nuevas tareas programadas. En Linux, una forma común de mantener tareas programadas es mediante Cron Jobs. Existen directorios específicos que podemos utilizar para agregar nuevos cron jobs si tenemos permisos de escritura sobre ellos. Estos incluyen:

- `/etc/crontab`
- `/etc/cron.d`
- `/var/spool/cron/crontabs/root`

Si podemos escribir en un directorio que es llamado por un cron job, podemos escribir un script bash con un comando de reverse shell, lo que debería enviarnos una reverse shell cuando se ejecute.

### PATH Hijacking

Esta técnica permite manipular la variable de entorno PATH para ejecutar nuestros propios comandos. Es muy útil si por ejemplo, se están ejecutando comandos que confían en el PATH establecido y no en la ruta absoluta. Imaginemos que existe un binario con permisos SUID que confía en el PATH, como por ejemplo, el binario `cat`. Podemos crear un archivo a nuestro antojo en la carpeta `/tmp`, que probablemente permita escritura dentro. 

Imaginemos que hemos visto que existe un binario con permisos SUID mal configurado, como `/usr/bin/bugtracker`. Que tenga permisos SUID significa que se ejecutará como el usuario que ha creado el binario (probablemente root), aunque no seamos el creador. Si por ejemplo, dicho binario llama a alguna tarea como `cat` que confía en el PATH, podemos crear nuestro propio "cat" dentro de `/tmp` y agregarle el siguiente código:

```bash
bash -p
```

Le damos permisos de ejecución con `chmod +x`. Después, modificamos el PATH para incluir `/tmp` y así que cuando llamemos al binario con permisos SUID, ejecute nuetrso `cat` malicioso. La modificación del PATH la podemos hacer así:

```bash
export PATH=/tmp:$PATH
```

Ahora, dado que el binario con permisos SUID se ejecutará como root (el creador de dicho binario), buscará en el PATH el binario `cat` antes que la ruta verdadera (`/bin/cat`), es decir, el binario malicioso por nosotros. Al ejecutarlo, nos convertiremos en root.

### Exploits de Kernel

Siempre que nos encontremos con un servidor que ejecute un sistema operativo antiguo, debemos comenzar buscando posibles vulnerabilidades en el kernel que puedan existir. Supongamos que el servidor no se mantiene con las últimas actualizaciones y parches. En ese caso, es probable que sea vulnerable a ciertos exploits del kernel encontrados en versiones sin parchear de Linux y Windows.

Por ejemplo, el script [linPEAS.sh](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) nos permite buscar vulnerabilidades en sistemas Linux y mostrarlas en un reporte. Por ejemplo, supongamos que encontramos que en un sistema, al ejecutar el script, la versión 3.9.0-73-generic que se está usando es vulnerable a exploits. Podemos usar `searchsploit` para listar vulnerabilidades, encontrando el CVE-2016-5195, conocido también como DirtyCow. Podemos buscar y descargar el exploit de [DirtyCow](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs) y ejecutarlo en el servidor para obtener acceso root.

El mismo concepto se aplica a Windows, ya que existen muchas vulnerabilidades en versiones sin parchear o antiguas de Windows, con diversas vulnerabilidades que pueden usarse para escalar privilegios. Debemos tener en cuenta que los exploits del kernel pueden causar inestabilidad en el sistema, por lo que debemos actuar con mucho cuidado antes de ejecutarlos en sistemas de producción. Es mejor probarlos en un entorno de laboratorio y solo ejecutarlos en sistemas de producción con aprobación explícita y coordinación con nuestro cliente.

### Credenciales expuestas

Podemos buscar archivos que podamos leer (por permisos de 'read') y comprobar si tienen credenciales expuestas. Esto es habitual en archivos de configuración, archivos de log, e historial como `bash_history` en Linux y `PSReadLine` en Windows. Imaginemos que lanzamos un script de enumeración para buscar contraseñas en archivos y obtenerlas:

```bash
...SNIP...
[+] Searching passwords in config PHP files
[+] Finding passwords inside logs (limit 70)
...SNIP...
/var/www/html/config.php: $conn = new mysqli(localhost, 'db_user', 'password123');
```

También podemos comprobar la reutilización de contraseñas, pues el usuario puede haber usado su contraseña para la BBDD, lo que puede permitirnos usar la misma password para cambiar a dicho usuario:

```bash
amr251@htb[/htb]$ su -

Password: password123
whoami

root
```

Recordar que, si vemos una terminal así, podemos escribir `script /dev/null` para tener una shell algo más funcional.

### Claves SSH

Si tenemos acceso al directorio `.ssh` para un usuario específico,  podemos leer su clave privada encontrada en `/home/user/.ssh/id_rsa` o `/root/.ssh/id_rsa` y usarlo para acceder al servidor. Si podemos acceder a `/root/.ssh` y leer el archivo `id_rsa`, lo podemos copiar y usar el parámetro `-i` para iniciar sesión con el mismo, haciéndolo desde nuestra máquina local:

```bash
amr251@htb[/htb]$ nvim id_rsa
amr251@htb[/htb]$ chmod 600 id_rsa
amr251@htb[/htb]$ ssh root@10.10.10.10 -i id_rsa

root@10.10.10.10#
```

Si nos encontramos con acceso de escritura al directorio `.ssh` de un usuario, podemos colocar nuestra clave pública en el directorio SSH del usuario en `/home/user/.ssh/authorized_keys`. Esta técnica se utiliza normalmente para obtener acceso SSH después de haber conseguido una shell como ese usuario. La configuración actual de SSH no aceptará claves escritas por otros usuarios, por lo que solo funcionará si ya hemos tomado control de ese usuario. Primero debemos crear una nueva clave con `ssh-keygen` y usar la opción `-f` para especificar el archivo de salida:

```shell-session
amr251@htb[/htb]$ ssh-keygen -f key

Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): *******
Enter same passphrase again: *******

Your identification has been saved in key
Your public key has been saved in key.pub
The key fingerprint is:
SHA256:...SNIP... user@parrot
The key's randomart image is:
+---[RSA 3072]----+
|   ..o.++.+      |
...SNIP...
|     . ..oo+.    |
+----[SHA256]-----+
```

Esto nos dará dos archivos: `key` (que usaremos con `ssh -i`) y el archivo `key.pub`, que copiaremos a la máquina remota. Después de copiarlo en la máquina remota, lo añadiremos a `/root/.ssh/authorized_keys`:

```shell-session
user@remotehost$ echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys
```

Ahora, el servidor remoto debería permitirnos iniciar sesión usando nuestra clave privada:

```shell-session
amr251@htb[/htb]$ ssh root@10.10.10.10 -i key

root@remotehost# 
```
