> Para proteger datos personales, el Reglamento General de Protección de Datos (RGPD) exige cifrado tanto para el almacenamiento como para la transmisión de estos datos dentro de la Unión Europea. En cuanto al cifrado de archivos, existen dos tipos principales: el cifrado simétrico (como AES-256), que usa una única clave para cifrar y descifrar, y el cifrado asimétrico, que emplea un par de claves (pública y privada) para garantizar que solo el destinatario pueda descifrar el archivo. Es recomendable utilizar este último para el envío de archivos sensibles.

Por lo tanto, para enviar archivos, se utiliza cifrado asimétrico, en el que se requieren dos claves separadas. El remitente cifra el archivo con la clave pública del destinatario. A su vez, el destinatario puede descifrar el archivo utilizando una clave privada.
### Caza de archivos codificados

Muchas extensiones de archivo pueden identificar estos tipos de archivos codificados/encriptados. Por ejemplo, una lista se puede ver en [FileInfo](https://fileinfo.com/filetypes/encoded)

```shell-session
cry0l1t3@unixclient:~$ for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

File extension:  .xls

File extension:  .xls*

File extension:  .xltx
```

Si encontramos extensiones de archivo en el sistema con los que no somos familiares, podemos usar buscadores para encontrar la tecnología detrás. Después de todo, hay cientos de extensiones de archivo. Sin embargo, deberíamos saber cómo encontrar información relevante que nos va a ayudar. Podemos repetir los pasos de búsqueda de credenciales para encontrar claves SSH:

```shell-session
cry0l1t3@unixclient:~$ grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"

/home/cry0l1t3/.ssh/internal_db:1:-----BEGIN OPENSSH PRIVATE KEY-----
/home/cry0l1t3/.ssh/SSH.private:1:-----BEGIN OPENSSH PRIVATE KEY-----
/home/cry0l1t3/Mgmt/ceil.key:1:-----BEGIN OPENSSH PRIVATE KEY-----
```

##### Claves SSH encriptadas

```shell-session
cry0l1t3@unixclient:~$ cat /home/kira/.ssh/SSH.private

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2109D25CC91F8DBFCEB0F7589066B2CC

8Uboy0afrTahejVGmB7kgvxkqJLOczb1I0/hEzPU1leCqhCKBlxYldM2s65jhflD
4/OH4ENhU7qpJ62KlrnZhFX8UwYBmebNDvG12oE7i21hB/9UqZmmHktjD3+OYTsD
...SNIP...
```

Si vemos un encabezado de este tipo en una clave SSH, en la mayoría de los casos no podremos usarla de inmediato sin una acción adicional. Esto se debe a que las claves SSH cifradas están protegidas con una frase de contraseña que debe ingresarse antes de su uso. Sin embargo, muchas veces las personas son descuidadas al seleccionar la contraseña y su complejidad, ya que SSH se considera un protocolo seguro, y muchos no saben que incluso un AES-128-CBC ligero puede ser descifrado.

### Rompiendo con John

Podemos convertir muchos formatos diferentes en hashes únicos e intentar descifrar las contraseñas con esto. Luego, si tenemos éxito, podremos abrir, leer y usar el archivo. Existe un script en Python llamado `ssh2john.py` para claves SSH, que genera los hashes correspondientes para las claves SSH cifradas, los cuales luego podemos almacenar en archivos. 

```shell-session
amr251@htb[/htb]$ ssh2john.py SSH.private > ssh.hash
amr251@htb[/htb]$ cat ssh.hash 

ssh.private:$sshng$0$8$1C258238FD2D6EB0$2352$f7b...SNIP...
```

Después, necesitamos adaptar los comandos de acuerdo a la lista de contraseñas y especificar nuestro archivo con los hashes como el objetivo a romper.

```shell-session
amr251@htb[/htb]$ john --wordlist=rockyou.txt ssh.hash
```

```shell-session
amr251@htb[/htb]$ john ssh.hash --show

SSH.private:1234

1 password hash cracked, 0 left
```

### Rompiendo documentos

Casi todos los informes, documentación y hojas informativas se encuentran en forma de documentos de Office y PDFs. Esto se debe a que ofrecen la mejor representación visual de la información. John proporciona un script en Python llamado `office2john.py` para extraer hashes de todos los documentos de Office comunes, que luego pueden ser utilizados en John o Hashcat para descifrado offline. El procedimiento para descifrar sigue siendo el mismo.

##### Documentos Office

```shell-session
amr251@htb[/htb]$ office2john.py Protected.docx > protected-docx.hash
amr251@htb[/htb]$ cat protected-docx.hash

Protected.docx:$office$*2007*20*128*16*7240...SNIP...8a69cf1*98242f4da37d916305d8e2821360773b7edc481b
```

```shell-session
amr251@htb[/htb]$ john --wordlist=rockyou.txt protected-docx.hash

Loaded 1 password hash (Office, 2007/2010/2013 [SHA1 256/256 AVX2 8x / SHA512 256/256 AVX2 4x AES])
Cost 1 (MS Office version) is 2007 for all loaded hashes
Cost 2 (iteration count) is 50000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1234             (Protected.docx)
1g 0:00:00:00 DONE (2022-02-08 01:25) 2.083g/s 2266p/s 2266c/s 2266C/s trisha..heart
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

```shell-session
amr251@htb[/htb]$ john protected-docx.hash --show

Protected.docx:1234
```

##### PDFs

```shell-session
amr251@htb[/htb]$ pdf2john.py PDF.pdf > pdf.hash
amr251@htb[/htb]$ cat pdf.hash 

PDF.pdf:$pdf$2*3*128*-1028*1*16*7e88...SNIP...bd2*32*a72092...SNIP...0000*32*c48f001fdc79a030d718df5dbbdaad81d1f6fedec4a7b5cd980d64139edfcb7e
```

```shell-session
amr251@htb[/htb]$ john --wordlist=rockyou.txt pdf.hash

Using default input encoding: UTF-8
Loaded 1 password hash (PDF [MD5 SHA2 RC4/AES 32/64])
Cost 1 (revision) is 3 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1234             (PDF.pdf)
1g 0:00:00:00 DONE (2022-02-08 02:16) 25.00g/s 27200p/s 27200c/s 27200C/s bulldogs..heart
Use the "--show --format=PDF" options to display all of the cracked passwords reliably
Session completed
```

```shell-session
amr251@htb[/htb]$ john pdf.hash --show

PDF.pdf:1234

1 password hash cracked, 0 left
```

##### ZIPs

```shell-session
amr251@htb[/htb]$ zip2john ZIP.zip > zip.hash
```

Una vez tenemos extraído el hash, podemos usar `john` otra vez para romperlo con la lista de contraseñas que queramos. 

```bash
john --wordlist=rockyou.txt zip.hash
...SNIP...
john zip.hash --show
```

##### Rompiendo archivos encriptados de OpenSSL

Además, no siempre es evidente de forma directa si un archivo comprimido (archivo de tipo "archive") está protegido por contraseña, especialmente cuando se utiliza una extensión de archivo que no admite protección por contraseña. Como ya hemos comentado anteriormente, _openssl_ puede utilizarse, por ejemplo, para cifrar archivos en formato gzip.

```shell-session
amr251@htb[/htb]$ file GZIP.gzip 

GZIP.gzip: openssl enc'd data with salted password
```

Al intentar descifrar archivos y archivos comprimidos cifrados con OpenSSL, podemos encontrarnos con muchas dificultades que generarán falsos positivos o incluso harán que no se adivine la contraseña correcta. Por ello, la opción más segura para tener éxito es utilizar la herramienta _openssl_ dentro de un bucle `for`, que intente extraer los archivos directamente del archivo comprimido si se adivina la contraseña correctamente.

El siguiente _one-liner_ (línea de comando) mostrará muchos errores relacionados con el formato GZIP, los cuales podemos ignorar. Si hemos utilizado la lista de contraseñas correcta, como en este ejemplo, veremos que hemos logrado extraer correctamente otro archivo del archivo comprimido.

```shell-session
amr251@htb[/htb]$ for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done

gzip: stdin: not in gzip format
tar: Child returned status 1
tar: Error is not recoverable: exiting now

gzip: stdin: not in gzip format
tar: Child returned status 1
tar: Error is not recoverable: exiting now

<SNIP>
```

Una vez que el bucle ha finalizado, podemos comprobar si el cracking ha sido exitoso

```shell-session
amr251@htb[/htb]$ ls

customers.csv  GZIP.gzip  rockyou.txt
```

##### Descifrando drives encriptados de BitLocker

**BitLocker** es un programa de cifrado para particiones completas y unidades externas, desarrollado por Microsoft para el sistema operativo Windows. Está disponible desde Windows Vista y utiliza el algoritmo de cifrado AES con una longitud de 128 o 256 bits. Si se olvida la contraseña o el PIN de BitLocker, se puede usar una clave de recuperación para descifrar la partición o unidad. Esta clave de recuperación es una cadena de 48 dígitos numéricos que se genera durante la configuración de BitLocker y que también puede ser objeto de ataques por fuerza bruta.

A menudo se crean unidades virtuales donde se almacena información personal, notas y documentos en el equipo o portátil proporcionado por la empresa, con el fin de evitar el acceso por parte de terceros. Para estos casos, se puede usar un script llamado **bitlocker2john** para extraer el hash necesario para intentar descifrar la clave. Se extraen cuatro tipos distintos de hash, los cuales pueden utilizarse con diferentes modos de Hashcat. En nuestro ejemplo, trabajaremos con el primero, que hace referencia a la contraseña de BitLocker.

```shell-session
amr251@htb[/htb]$ bitlocker2john -i Backup.vhd > backup.hashes
amr251@htb[/htb]$ grep "bitlocker\$0" backup.hashes > backup.hash
amr251@htb[/htb]$ cat backup.hash
```

##### Usando hashcat descifrar romper el backup.hash

```shell-session
amr251@htb[/htb]$ hashcat -m 22100 backup.hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt -o backup.cracked

hashcat (v6.1.1) starting...

<SNIP>
```

Una vez que hayamos descifrado la contraseña, podremos abrir las unidades cifradas. La forma más sencilla de montar una unidad virtual cifrada con BitLocker es transferirla a un sistema Windows y montarla. Para ello, basta con hacer doble clic en la unidad virtual. Dado que está protegida por contraseña, Windows mostrará un error inicialmente. Tras montar la unidad, podremos hacer doble clic nuevamente sobre ella y BitLocker nos pedirá la contraseña.

![[Pasted image 20250429180552.png]]