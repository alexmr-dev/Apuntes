---

---
-----
- Tags: #FTP
-------
> ​El **Protocolo de Transferencia de Archivos (FTP)** es uno de los protocolos más antiguos de Internet, operando en la capa de aplicación del modelo TCP/IP, al igual que HTTP o POP. FTP permite la transferencia de archivos entre un cliente y un servidor, ofreciendo características como autenticación de usuarios y soporte para diversos comandos que facilitan la gestión de archivos y directorios. Por defecto, se encuentra en el puerto 21. 

##### TFTP

Por otro lado, el **Protocolo de Transferencia de Archivos Trivial (TFTP)** es una versión simplificada de FTP. Aunque también facilita la transferencia de archivos entre procesos cliente y servidor, carece de funcionalidades avanzadas como la autenticación de usuarios y el listado de directorios. Además, mientras que FTP utiliza el protocolo TCP, TFTP opera sobre UDP, lo que lo hace menos confiable debido a la ausencia de mecanismos de control de errores integrados. ​

Debido a su simplicidad y falta de medidas de seguridad, TFTP se utiliza comúnmente en redes locales y entornos controlados donde la seguridad no es una preocupación principal. Por ejemplo, es habitual emplearlo para transferir pequeños archivos entre computadoras en una red interna.

A continuación, se presentan algunos comandos básicos de TFTP:

|Comando|Descripción|
|---|---|
|`connect`|Establece el host remoto y, opcionalmente, el puerto para las transferencias de archivos.|
|`get`|Transfiere un archivo o conjunto de archivos desde el host remoto al host local.|
|`put`|Transfiere un archivo o conjunto de archivos desde el host local al host remoto.|
|`quit`|Sale de la sesión de TFTP.|
|`status`|Muestra el estado actual de TFTP, incluyendo el modo de transferencia, estado de conexión, etc.|
|`verbose`|Activa o desactiva el modo detallado, mostrando información adicional durante la transferencia.|

Para conectarnos vía FTP a un host, es tan sencillo como esto:

```bash
ftp -p <IP>
```

Si el servidor permite autenticación anónima, pondremos como usuario `anonymous` y la contraseña no será necesaria. 
##### Configuración de vsFTPd para Acceso Anónimo

El servidor vsFTPd (Very Secure FTP Daemon) permite la configuración de accesos anónimos mediante diversas directivas en su archivo de configuración (`/etc/vsftpd.conf`). A continuación, se describen algunas de las configuraciones más relevantes

|Configuración|Descripción|
|---|---|
|`anonymous_enable=YES`|¿Permitir inicio de sesión anónimo?|
|`anon_upload_enable=YES`|¿Permitir que los usuarios anónimos suban archivos?|
|`anon_mkdir_write_enable=YES`|¿Permitir que los usuarios anónimos creen nuevos directorios?|
|`no_anon_password=YES`|¿No pedir contraseña a los usuarios anónimos?|
|`anon_root=/home/usuario/ftp`|Directorio raíz para los usuarios anónimos.|
|`write_enable=YES`|¿Permitir el uso de comandos FTP: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE y SITE?|

##### Descargar todos los archivos

```bash
wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136
```

Después, podemos con el comando `tree .` ver todo el contenido de forma sencilla:

```shell-session
.
└── 10.129.14.136
    ├── Calendar.pptx
    ├── Clients
    │   └── Inlanefreight
    │       ├── appointments.xlsx
    │       ├── contract.docx
    │       ├── meetings.txt
    │       └── proposal.pptx
    ├── Documents
    │   ├── appointments-template.xlsx
    │   ├── contract-template.docx
    │   └── contract-template.pdf
    ├── Employees
    └── Important Notes.txt

5 directories, 9 files
```

##### Interacción con el servidor

```shell-session
amr251@htb[/htb]$ nc -nv 10.129.14.136 21
```

```shell-session
amr251@htb[/htb]$ telnet 10.129.14.136 21
```

​Cuando un servidor FTP utiliza cifrado TLS/SSL, es necesario emplear un cliente compatible con estos protocolos para establecer una conexión segura. Una herramienta útil para este propósito es `openssl`, que permite interactuar con el servidor FTP y, además, inspeccionar el certificado SSL proporcionado por el servidor.​

**Conectar a un servidor FTP con `openssl`:**

Para establecer una conexión segura y visualizar el certificado SSL del servidor FTP, puedes utilizar el siguiente comando:​

```
openssl s_client -connect [servidor_ftp]:21 -starttls ftp`
```

Donde `[servidor_ftp]` debe ser reemplazado por la dirección del servidor FTP al que deseas conectarte. Al ejecutar este comando, `openssl` mostrará detalles sobre la conexión SSL/TLS, incluyendo el certificado del servidor. Esta información puede ser útil para verificar la autenticidad del servidor y diagnosticar posibles problemas de conexión.