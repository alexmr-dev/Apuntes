***
> John the Ripper es una herramienta que nos permite comprobar la fuerza de contraseñas y romper contraseñas encriptadas o hasheadas mediante fuerza bruta o ataques de diccionario.

### 🗂️ Ataques de Diccionario (Dictionary Attacks)

Ataque que prueba contraseñas comunes desde un diccionario. Es eficaz si las contraseñas no son complejas. Se mitiga usando contraseñas únicas, complejas y 2FA. 

### 🛠️ Ataques de Fuerza Bruta (Brute Force Attacks)

Los ataques de fuerza bruta prueban todas las combinaciones posibles de caracteres para encontrar una contraseña. Este proceso es muy lento y se usa solo cuando no hay otra opción. Cuanto más larga y compleja sea una contraseña, más difícil será romperla. Se recomienda usar contraseñas de al menos 8 caracteres que incluyan letras, números y símbolos.

### 🌈 Ataques con Tablas Rainbow (Rainbow Table Attacks)

Los ataques con tablas rainbow utilizan tablas precalculadas que relacionan hashes con sus contraseñas originales. Son más rápidos que la fuerza bruta, pero limitados por el tamaño de la tabla: solo funcionan si el hash está incluido en la tabla. Mientras más grande sea la tabla, más efectividad tiene el ataque.

### Rompiendo contraseñas

El uso de la herramienta sigue la siguiente estructura:

```bash
john --format=<hash_type> <hash or hash_file>
```

Los formatos de hash disponibles son los siguientes:

| Formato de Hash         | Comando de Ejemplo                             | Descripción                                                                 |
|-------------------------|-----------------------------------------------|-----------------------------------------------------------------------------|
| afs                     | `john --format=afs hashes_to_crack.txt`       | Hashes de contraseñas de AFS (Andrew File System)                          |
| bfegg                   | `john --format=bfegg hashes_to_crack.txt`     | Hashes bfegg usados en bots IRC Eggdrop                                    |
| bf                      | `john --format=bf hashes_to_crack.txt`        | Hashes Blowfish basados en crypt(3)                                        |
| bsdi                    | `john --format=bsdi hashes_to_crack.txt`      | Hashes BSDi crypt(3)                                                        |
| crypt(3)                | `john --format=crypt hashes_to_crack.txt`     | Hashes tradicionales Unix crypt(3)                                         |
| des                     | `john --format=des hashes_to_crack.txt`       | Hashes tradicionales basados en DES crypt(3)                               |
| dmd5                    | `john --format=dmd5 hashes_to_crack.txt`      | Hashes DMD5 (Dragonfly BSD MD5)                                            |
| dominosec               | `john --format=dominosec hashes_to_crack.txt` | Hashes IBM Lotus Domino 6/7                                                |
| episerver               | `john --format=episerver hashes_to_crack.txt` | Hashes SID (Security Identifier) de EPiServer                              |
| hdaa                    | `john --format=hdaa hashes_to_crack.txt`      | Hashes hdaa usados en Openwall GNU/Linux                                   |
| hmac-md5                | `john --format=hmac-md5 hashes_to_crack.txt`  | Hashes hmac-md5                                                             |
| hmailserver             | `john --format=hmailserver hashes_to_crack.txt` | Hashes de contraseñas de hMailServer                                     |
| ipb2                    | `john --format=ipb2 hashes_to_crack.txt`      | Hashes de Invision Power Board 2                                           |
| krb4                    | `john --format=krb4 hashes_to_crack.txt`      | Hashes de contraseñas Kerberos 4                                           |
| krb5                    | `john --format=krb5 hashes_to_crack.txt`      | Hashes de contraseñas Kerberos 5                                           |
| LM                      | `john --format=LM hashes_to_crack.txt`        | Hashes de contraseñas Lan Manager (LM)                                     |
| lotus5                  | `john --format=lotus5 hashes_to_crack.txt`    | Hashes de Lotus Notes/Domino 5                                             |
| mscash                  | `john --format=mscash hashes_to_crack.txt`    | Hashes MS Cache                                                             |
| mscash2                 | `john --format=mscash2 hashes_to_crack.txt`   | Hashes MS Cache v2                                                          |
| mschapv2                | `john --format=mschapv2 hashes_to_crack.txt`  | Hashes MS CHAP v2                                                           |
| mskr5                   | `john --format=mskrb5 hashes_to_crack.txt`    | Hashes de MS Kerberos 5                                                    |
| mssql05                 | `john --format=mssql05 hashes_to_crack.txt`   | Hashes de MS SQL 2005                                                       |
| mssql                   | `john --format=mssql hashes_to_crack.txt`     | Hashes de MS SQL                                                            |
| mysql-fast              | `john --format=mysql-fast hashes_to_crack.txt`| Hashes rápidos de MySQL                                                     |
| mysql                   | `john --format=mysql hashes_to_crack.txt`     | Hashes de contraseñas MySQL                                                |
| mysql-sha1              | `john --format=mysql-sha1 hashes_to_crack.txt`| Hashes MySQL SHA1                                                           |
| netlm                   | `john --format=netlm hashes_to_crack.txt`     | Hashes NETLM (NT LAN Manager)                                              |
| netlmv2                 | `john --format=netlmv2 hashes_to_crack.txt`   | Hashes NETLMv2 (versión 2 de NTLM)                                         |
| netntlm                 | `john --format=netntlm hashes_to_crack.txt`   | Hashes NETNTLM (NT LAN Manager)                                            |
| netntlmv2               | `john --format=netntlmv2 hashes_to_crack.txt` | Hashes NETNTLMv2 (versión 2 de NTLM)                                       |
| nethalflm               | `john --format=nethalflm hashes_to_crack.txt` | Hashes NEThalfLM (NT LAN Manager)                                          |
| md5ns                   | `john --format=md5ns hashes_to_crack.txt`     | Hashes md5ns (espacio de nombres MD5)                                      |
| nsldap                  | `john --format=nsldap hashes_to_crack.txt`    | Hashes nsldap (OpenLDAP SHA)                                               |
| ssha                    | `john --format=ssha hashes_to_crack.txt`      | Hashes SSHA (SHA con salt)                                                 |
| NT                      | `john --format=nt hashes_to_crack.txt`        | Hashes de contraseñas NT (Windows NT)                                      |
| openssha                | `john --format=openssha hashes_to_crack.txt`  | Hashes de contraseñas de claves privadas OPENSSH                           |
| oracle11                | `john --format=oracle11 hashes_to_crack.txt`  | Hashes de Oracle 11                                                         |
| oracle                  | `john --format=oracle hashes_to_crack.txt`    | Hashes de Oracle                                                            |
| pdf                     | `john --format=pdf hashes_to_crack.txt`       | Hashes de archivos PDF                                                     |
| phpass-md5              | `john --format=phpass-md5 hashes_to_crack.txt`| Hashes PHPass-MD5 (framework PHP portable)                                 |
| phps                    | `john --format=phps hashes_to_crack.txt`      | Hashes PHPS                                                                 |
| pix-md5                 | `john --format=pix-md5 hashes_to_crack.txt`   | Hashes Cisco PIX MD5                                                        |
| po                      | `john --format=po hashes_to_crack.txt`        | Hashes Po (Sybase SQL Anywhere)                                            |
| rar                     | `john --format=rar hashes_to_crack.txt`       | Hashes de archivos RAR                                                     |
| raw-md4                 | `john --format=raw-md4 hashes_to_crack.txt`   | Hashes MD4 sin procesar                                                     |
| raw-md5                 | `john --format=raw-md5 hashes_to_crack.txt`   | Hashes MD5 sin procesar                                                     |
| raw-md5-unicode         | `john --format=raw-md5-unicode hashes_to_crack.txt` | Hashes MD5 Unicode sin procesar                                       |
| raw-sha1                | `john --format=raw-sha1 hashes_to_crack.txt`  | Hashes SHA1 sin procesar                                                    |
| raw-sha224              | `john --format=raw-sha224 hashes_to_crack.txt`| Hashes SHA224 sin procesar                                                  |
| raw-sha256              | `john --format=raw-sha256 hashes_to_crack.txt`| Hashes SHA256 sin procesar                                                  |
| raw-sha384              | `john --format=raw-sha384 hashes_to_crack.txt`| Hashes SHA384 sin procesar                                                  |
| raw-sha512              | `john --format=raw-sha512 hashes_to_crack.txt`| Hashes SHA512 sin procesar                                                  |
| salted-sha              | `john --format=salted-sha hashes_to_crack.txt`| Hashes SHA con salt                                                         |
| sapb                    | `john --format=sapb hashes_to_crack.txt`      | Hashes SAP CODVN B (BCODE)                                                  |
| sapg                    | `john --format=sapg hashes_to_crack.txt`      | Hashes SAP CODVN G (PASSCODE)                                               |
| sha1-gen                | `john --format=sha1-gen hashes_to_crack.txt`  | Hashes SHA1 genéricos                                                       |
| skey                    | `john --format=skey hashes_to_crack.txt`      | Hashes S/Key (contraseñas de un solo uso)                                  |
| ssh                     | `john --format=ssh hashes_to_crack.txt`       | Hashes de contraseñas de claves SSH                                        |
| sybasease               | `john --format=sybasease hashes_to_crack.txt` | Hashes de Sybase ASE                                                        |
| xsha                    | `john --format=xsha hashes_to_crack.txt`      | Hashes SHA extendido                                                        |
| zip                     | `john --format=zip hashes_to_crack.txt`       | Hashes de archivos ZIP                                                      |
También podemos aplicar wordlists, generalmente usando los diccionarios de SecLists. 

```bash
john --wordlist=<wordlist_file> --rules <hash_file>
```

##### Modo incremental

El modo incremental es un modo avanzado de John the Ripper que se utiliza para descifrar contraseñas utilizando un conjunto de caracteres. Es un ataque híbrido, lo que significa que intentará coincidir con la contraseña probando todas las combinaciones posibles de caracteres del conjunto definido. Es el modo más efectivo, aunque también el más lento de todos los modos de John.

- Es un **modo avanzado** que genera combinaciones de contraseñas usando un **conjunto de caracteres**.
- Se trata de un ataque **híbrido**, más eficaz que la fuerza bruta y más lento que otros modos.
- Prueba todas las combinaciones posibles **de forma secuencial**, desde las más cortas.
- Útil cuando **sabemos o sospechamos parte de la contraseña**.
- Diferencias clave:
  - **Modo Incremental:** genera combinaciones en tiempo real.
  - **Modo Wordlist:** usa una lista predefinida de palabras.
  - **Modo Single Crack:** prueba una única contraseña contra un hash.
- Ideal para descifrar contraseñas **débiles o parcialmente conocidas**.

```shell-session
john --incremental <hash_file>
```

Adicionalmente, podemos usar diferentes modos con nuestros propios diccionarios y reglas. Aquí hay una lista de herramientas, aunque hay muchas más.

| Herramienta              | Descripción                                                      |
|--------------------------|------------------------------------------------------------------|
| `pdf2john`               | Convierte documentos PDF para John                              |
| `ssh2john`               | Convierte claves privadas SSH para John                         |
| `mscash2john`            | Convierte hashes MS Cache v2 para John                          |
| `keychain2john`          | Convierte archivos de llavero de macOS (Keychain) para John     |
| `rar2john`               | Convierte archivos RAR para John                                |
| `pfx2john`               | Convierte archivos PKCS#12 (.pfx) para John                     |
| `truecrypt_volume2john`  | Convierte volúmenes de TrueCrypt para John                      |
| `keepass2john`           | Convierte bases de datos KeePass para John                      |
| `vncpcap2john`           | Convierte archivos PCAP de VNC para John                        |
| `putty2john`             | Convierte claves privadas de PuTTY para John                    |
| `zip2john`               | Convierte archivos ZIP para John                                |
| `hccap2john`             | Convierte capturas de handshake WPA/WPA2 para John              |
| `office2john`            | Convierte documentos de Microsoft Office para John              |
| `wpa2john`               | Convierte handshakes WPA/WPA2 para John                         |
### Rompiendo contraseñas

| **Command**| **Description**|
|-|-|
| `hashcat -m 1000 dumpedhashes.txt /usr/share/wordlists/rockyou.txt` | Uses Hashcat to crack NTLM hashes using a specified wordlist. |
| `hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt --show` | Uses Hashcat to attempt to crack a single NTLM hash and display the results in the terminal output. |
| `unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes` | Uses unshadow to combine data from passwd.bak and shadow.bk into one single file to prepare for cracking. |
| `hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked` | Uses Hashcat in conjunction with a wordlist to crack the unshadowed hashes and outputs the cracked hashes to a file called unshadowed.cracked. |
| ` hashcat -m 500 -a 0 md5-hashes.list rockyou.txt`           | Uses Hashcat in conjunction with a word list to crack the md5 hashes in the md5-hashes.list file. |
| `hashcat -m 22100 backup.hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt -o backup.cracked` | Uses Hashcat to crack the extracted BitLocker hashes using a wordlist and outputs the cracked hashes into a file called backup.cracked. |
| `ssh2john.pl SSH.private > ssh.hash`         | Runs Ssh2john.pl script to generate hashes for the SSH keys in the SSH.private file, then redirects the hashes to a file called ssh.hash. |
| `john ssh.hash --show`                                       | Uses John to attempt to crack the hashes in the ssh.hash file, then outputs the results in the terminal. |
| `office2john.py Protected.docx > protected-docx.hash`        | Runs Office2john.py against a protected .docx file and converts it to a hash stored in a file called protected-docx.hash. |
| `john --wordlist=rockyou.txt protected-docx.hash`            | Uses John in conjunction with the wordlist rockyou.txt to crack the hash protected-docx.hash. |
| `pdf2john.pl PDF.pdf > pdf.hash`                       | Runs Pdf2john.pl script to convert a pdf file to a pdf has to be cracked. |
| `john --wordlist=rockyou.txt pdf.hash`                       | Runs John in conjunction with a wordlist to crack a pdf hash. |
| `zip2john ZIP.zip > zip.hash`                                | Runs Zip2john against a zip file to generate a hash, then adds that hash to a file called zip.hash. |
| `john --wordlist=rockyou.txt zip.hash`                       | Uses John in conjunction with a wordlist to crack the hashes contained in zip.hash. |
| `bitlocker2john -i Backup.vhd > backup.hashes`               | Uses Bitlocker2john script to extract hashes from a VHD file and directs the output to a file called backup.hashes. |
| `file GZIP.gzip`                                             | Uses the Linux-based file tool to gather file format information. |
| `for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null \| tar xz;done` | Script that runs a for-loop to extract files from an archive. |