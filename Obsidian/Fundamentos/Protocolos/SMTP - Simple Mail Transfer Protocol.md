> ​El **Protocolo Simple de Transferencia de Correo** (SMTP, por sus siglas en inglés) es un protocolo utilizado para el envío de correos electrónicos en redes IP. Funciona en la capa de aplicación del modelo OSI y se emplea tanto entre un cliente de correo y un servidor de correo saliente como entre dos servidores SMTP. Generalmente, SMTP se combina con protocolos como IMAP o POP3, que se encargan de la recepción y gestión de los correos electrónicos

Por defecto, los servidores SMTP aceptan conexiones en el puerto 25, utilizado principalmente para la retransmisión de correos entre servidores. Sin embargo, para el envío de correos desde clientes autenticados, es común utilizar el puerto 587, que soporta el comando STARTTLS para establecer una conexión cifrada, protegiendo así los datos de autenticación y el contenido del correo durante la transmisión. El proceso de envío de un correo electrónico mediante SMTP implica que el cliente se autentique ante el servidor, proporcionando un nombre de usuario y una contraseña. Una vez autenticado, el cliente envía al servidor las direcciones del remitente y del destinatario, el contenido del correo y otros parámetros. Tras la transmisión del correo, la conexión se cierra, y el servidor SMTP procede a enviar el correo al servidor SMTP del destinatario, donde será entregado al buzón correspondiente.

Al llegar al servidor SMTP de destino, los paquetes de datos se reensamblan para formar un correo electrónico completo. Desde allí, el **Agente de Entrega de Correo** (_Mail Delivery Agent_ o MDA) lo transfiere al buzón del destinatario.​

El proceso de entrega de correo electrónico sigue esta secuencia:​

1. **Cliente (MUA)**: El usuario redacta y envía un correo electrónico utilizando un cliente de correo electrónico, conocido como **Agente de Usuario de Correo** (_Mail User Agent_ o MUA).​    
2. **Agente de Envío (MSA)**: El MUA se comunica con el **Agente de Envío de Correo** (_Mail Submission Agent_ o MSA), que recibe el correo y lo prepara para su transmisión.​
3. **Relé Abierto (MTA)**: El MSA entrega el correo al **Agente de Transferencia de Correo** (_Mail Transfer Agent_ o MTA), que retransmite el mensaje a través de la red hacia el servidor de correo del destinatario.​    
4. **Agente de Entrega de Correo (MDA)**: Una vez que el MTA del servidor de destino recibe el correo, lo pasa al **Agente de Entrega de Correo** (_Mail Delivery Agent_ o MDA), que lo coloca en el buzón del destinatario.​    
5. **Buzón (POP3/IMAP)**: Finalmente, el destinatario accede a su buzón para leer el correo utilizando protocolos como POP3 o IMAP.

Sin embargo, SMTP presenta dos desventajas inherentes al protocolo de red:​

1. **Falta de confirmación de entrega útil**: El envío de un correo electrónico mediante SMTP no garantiza una confirmación de entrega efectiva. Aunque las especificaciones del protocolo contemplan este tipo de notificaciones, su formato no está estandarizado, por lo que, generalmente, solo se recibe un mensaje de error en inglés, incluyendo el encabezado del mensaje no entregado.​
    
2. **Ausencia de autenticación de usuarios**: Cuando se establece una conexión, los usuarios no son autenticados, lo que hace que el remitente de un correo electrónico sea poco confiable. Como resultado, los **relés SMTP abiertos** suelen ser utilizados indebidamente para enviar spam en masa. Los emisores emplean direcciones de remitente falsas para evitar ser rastreados, una técnica conocida como **suplantación de correo** (_mail spoofing_).

### Configuración por defecto

Cada servidor SMTP puede ser configurado de muchas maneras, como pueden todos los otros servicios. Sin embargo, hay diferencias porque el servidor SMTP es sólamente responsable de enviar emails.

```shell-session
amr251@htb[/htb]$ cat /etc/postfix/main.cf | grep -v "#" | sed -r "/^\s*$/d"

smtpd_banner = ESMTP Server 
biff = no
append_dot_mydomain = no
readme_directory = no
...SNIP...
```

La comunicación y envío también son realizados por comandos especiales que hacen que el servidor SMTP haga lo que requiere el usuario

| Comando       | Descripción                                                                 |
|---------------|------------------------------------------------------------------------------|
| AUTH PLAIN    | AUTH es una extensión de servicio utilizada para autenticar al cliente.     |
| HELO          | El cliente se identifica con el nombre de su computadora e inicia la sesión.|
| MAIL FROM     | El cliente especifica el remitente del correo electrónico.                  |
| RCPT TO       | El cliente especifica el destinatario del correo electrónico.               |
| DATA          | El cliente inicia la transmisión del contenido del correo electrónico.      |
| RSET          | El cliente aborta la transmisión iniciada pero mantiene la conexión activa. |
| VRFY          | El cliente verifica si un buzón está disponible para la entrega de mensajes.|
| EXPN          | El cliente también verifica si un buzón está disponible para la mensajería. |
| NOOP          | El cliente solicita una respuesta del servidor para evitar la desconexión por inactividad.|
| QUIT          | El cliente termina la sesión.                                               |

Para interactuar con el servidor SMTP, podemos usar `telnet`  para iniciar una conexión TCP con el servidor. La inicialización de la sesión se realiza con el comando mencionado abajo, `HELO` o `EHLO`.

### Telnet - HELO/EHLO

```shell-session
amr251@htb[/htb]$ telnet 10.129.14.128 25

Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server 


HELO mail1.inlanefreight.htb

250 mail1.inlanefreight.htb
```

El comando `VRFY` puede ser utilizado para enumerar usuarios existentes en el sistema. Sin embargo, no siempre funciona. Dependiendo de cómo está configurado elo servidor SMTP, puede devolver un código de error 252 y confirmar la existencia de un usuario que no existe en el sistema.

### Telnet - VRFY

```shell-session
amr251@htb[/htb]$ telnet 10.129.14.128 25

Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server 

VRFY testuser

252 2.0.0 testuser


VRFY aaaaaaaaaaaaaaaaaaaaaaaaaaaa

252 2.0.0 aaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

Por tanto, uno nunca debería fiarse solo de los resultados de herramientas automáticas. Después de todo, ejecutan comandos preconfigurados, pero ninguna de las funciones declaran explícitamente cómo el administrador configura el servidor testeado.

A veces puede que tengamos que trabajar con un web proxy. Podemos hacer que éste se conecte al servidor SMTP, con el comando `CONNECT 10.129.14.128:25 HTTP/1.0`. Todos los comandos que ingresamos en la línea de comandos para enviar un correo electrónico los conocemos de cualquier cliente de correo como Thunderbird, Gmail, Outlook y muchos otros. Especificamos el asunto, el destinatario, CC, BCC y la información que queremos compartir con otros. Por supuesto, lo mismo funciona desde la línea de comandos.

### Enviando un email

```shell-session
amr251@htb[/htb]$ telnet 10.129.14.128 25

Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server


EHLO inlanefreight.htb

250-mail1.inlanefreight.htb
250-PIPELINING
250-SIZE 10240000
250-ETRN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING


MAIL FROM: <cry0l1t3@inlanefreight.htb>

250 2.1.0 Ok


RCPT TO: <mrb3n@inlanefreight.htb> NOTIFY=success,failure

250 2.1.5 Ok


DATA

354 End data with <CR><LF>.<CR><LF>

From: <cry0l1t3@inlanefreight.htb>
To: <mrb3n@inlanefreight.htb>
Subject: DB
Date: Tue, 28 Sept 2021 16:32:51 +0200
Hey man, I am trying to access our XY-DB but the creds don't work. 
Did you make any changes there?
.

250 2.0.0 Ok: queued as 6E1CF1681AB


QUIT

221 2.0.0 Bye
Connection closed by foreign host.
```

### Configuraciones peligrosas

Para evitar que los correos enviados sean filtrados por los filtros de spam y no lleguen al destinatario, el remitente puede utilizar un servidor de retransmisión en el que el destinatario confíe. Se trata de un servidor SMTP conocido y verificado por los demás. Por lo general, el remitente debe autenticarse en el servidor de retransmisión antes de utilizarlo. A menudo, los administradores no tienen una visión clara de qué rangos de IP deben permitir. Esto da lugar a una configuración incorrecta del servidor SMTP, algo que todavía encontramos con frecuencia en pruebas de penetración externas e internas. Para evitar problemas en el tráfico de correo electrónico y no interrumpir involuntariamente la comunicación con clientes potenciales y actuales, permiten todas las direcciones IP.

#### Configuración de Open Relay

```shell-session
mynetworks = 0.0.0.0/0
```

Con esta configuración, este servidor SMTP puede enviar correos falsificados e iniciar comunicación entre varias partes. Otra posible vulnerabilidad es la suplantación (spoofing) del correo electrónico y su lectura.

### Footprinting al servicio

Por defecto, los scripts nmap incluyen `smtp-commands`, que usa el comando `EHLO` para listar todos los posibles comandos que pueden ser ejecutados en el servidor SMTP objetivo. Sin embargo, también podemos usar el script NSE `smtp-open-relay` para identificar el servidor objetivo como un open relay usando 16 tests diferentes. Si además imprimimos el output en detalle, también podremos ver qué scripts están en ejecución.

```shell-session
amr251@htb[/htb]$ sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-30 02:29 CEST
NSE: Loaded 1 scripts for scanning.
...SNIP...
```

También podemos usar la herramienta Metasploit y utilizar el plugin para enumerar usuarios de un servicio SMTP.  

##### Enumeración Cloud

Existe una herramienta llamada [O365spray](https://github.com/0xZDH/o365spray) que permite enumerar usuarios y contraseñas apuntando a Microsoft Office 365.

```shell-session
amr251@htb[/htb]$ python3 o365spray.py --validate --domain msplaintext.xyz

            *** O365 Spray ***            

>----------------------------------------<

   > version        :  2.0.4
   > domain         :  msplaintext.xyz
   > validate       :  True
   > timeout        :  25 seconds
   > start          :  2022-04-13 09:46:40

>----------------------------------------<

[2022-04-13 09:46:40,344] INFO : Running O365 validation for: msplaintext.xyz
[2022-04-13 09:46:40,743] INFO : [VALID] The following domain is using O365: msplaintext.xyz
```

A partir de aquí, podemos identificar usuarios:

```shell-session
amr251@htb[/htb]$ python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz 
```

### Ataques con contraseña

Como ya se ha visto en [[Rompiendo contraseñas]], podemos usar spray password o fuerza bruta contra SMTP, POP3, IMAP4. Primero, necesitamos conseguir una lista de usuarios y contraseñas donde especificamos qué servicio queremos atacar. Por ejemplo, POP3:

```shell-session
amr251@htb[/htb]$ hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3

...

[110][pop3] host: 10.129.42.197   login: john   password: Company01!
1 of 1 target successfully completed, 1 valid password found
```

Si los servicios en la nube admiten los protocolos SMTP, POP3 o IMAP4, podríamos intentar realizar ataques de password spraying utilizando herramientas como Hydra; sin embargo, estas herramientas suelen ser bloqueadas. En su lugar, podemos utilizar herramientas personalizadas como o365spray o MailSniper para Microsoft Office 365, o CredKing para Gmail u Okta. Es importante tener en cuenta que estas herramientas deben estar actualizadas, ya que si el proveedor del servicio realiza cambios (lo cual ocurre con frecuencia), las herramientas podrían dejar de funcionar. Este es un ejemplo perfecto de por qué debemos comprender el funcionamiento de nuestras herramientas y tener la capacidad de modificarlas si, por alguna razón, no funcionan correctamente.

##### Password spraying con O365

```shell-session
amr251@htb[/htb]$ python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz
```

### Ataques específicos del protocolo

Un **open relay** es un servidor SMTP (Protocolo Simple de Transferencia de Correo) que está mal configurado y permite el reenvío de correos electrónicos sin autenticación. Los servidores de mensajería que están configurados accidental o intencionalmente como open relays permiten que el correo de cualquier fuente sea reenviado a través del servidor open relay. Este comportamiento oculta la fuente original de los mensajes y hace que parezca que el correo se originó desde el servidor open relay.

##### Open Relay

Desde el punto de vista de un atacante, podemos abusar de esto para realizar phishing enviando correos electrónicos como usuarios inexistentes o suplantando la dirección de correo de otra persona. Por ejemplo, imagina que estamos apuntando a una empresa con un servidor de correo open relay, y identificamos que utilizan una dirección de correo específica para enviar notificaciones a sus empleados. Podemos enviar un correo similar utilizando la misma dirección y añadir nuestro enlace de phishing con esta información. Con el script `smtp-open-relay` de Nmap, podemos identificar si un puerto SMTP permite un open relay.

```shell-session
amr251@htb[/htb]# nmap -p25 -Pn --script smtp-open-relay 10.10.11.213

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-28 23:59 EDT
Nmap scan report for 10.10.11.213
Host is up (0.28s latency).

PORT   STATE SERVICE
25/tcp open  smtp
|_smtp-open-relay: Server is an open relay (14/16 tests)
```

Después, podemos usar cualquier cliente para conectarnos al servidor y enviar nuestro email.

```shell-session
amr251@htb[/htb]# swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Company Notification' --body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' --server 10.10.11.213

=== Trying 10.10.11.213:25...
=== Connected to 10.10.11.213.
<-  220 mail.localdomain SMTP Mailer ready
 -> EHLO parrot
<-  250-mail.localdomain
<-  250-SIZE 33554432
<-  250-8BITMIME
<-  250-STARTTLS
<-  250-AUTH LOGIN PLAIN CRAM-MD5 CRAM-SHA1
<-  250 HELP
 -> MAIL FROM:<notifications@inlanefreight.com>
<-  250 OK
 -> RCPT TO:<employees@inlanefreight.com>
<-  250 OK
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
 -> Date: Thu, 29 Oct 2020 01:36:06 -0400
 -> To: employees@inlanefreight.com
 -> From: notifications@inlanefreight.com
 -> Subject: Company Notification
 -> Message-Id: <20201029013606.775675@parrot>
 -> X-Mailer: swaks v20190914.0 jetmore.org/john/code/swaks/
 -> 
 -> Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/
 -> 
 -> 
 -> .
<-  250 OK
 -> QUIT
<-  221 Bye
=== Connection closed with remote host.
```

##### Enumeración de usuarios con SMTP-enum

```bash
smtp-user-enum -M RCPT -U users.list -t 10.129.204.93 -D inlanefreight.htb
```

##### Adivinación de contraseñas con Hydra

```bash
hydra -l "marlin@inlanefreight.htb" -P ../resources/pws.list -f inlanefreight.htb pop3
```

> *Nota: Se usa el dominio inlanefreight.htb porque previamente lo hemos añadido a `/etc/hosts`*

