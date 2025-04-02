> El Protocolo de Acceso a Mensajes de Internet (IMAP) permite acceder a los correos electrónicos en un servidor de correo. A diferencia del Protocolo de Oficina Postal (POP3), IMAP permite gestionar los correos en línea directamente en el servidor, soportando estructuras de carpetas. Es un protocolo cliente-servidor que sincroniza un cliente de correo local con el buzón en el servidor, permitiendo una sincronización fluida entre varios clientes. POP3, en cambio, solo permite listar, recuperar y eliminar correos, sin funcionalidades avanzadas como la gestión de carpetas jerárquicas.

Con IMAP, los usuarios pueden acceder a las estructuras de carpetas en línea y crear copias locales de los correos. Los correos permanecen en el servidor hasta que se eliminan. IMAP es un protocolo basado en texto que permite explorar correos en el servidor y permite que varios usuarios accedan simultáneamente al servidor de correo. Sin conexión activa, no se pueden gestionar los correos, aunque algunos clientes permiten trabajar en modo offline, sincronizando los cambios cuando se reconecta.

La conexión al servidor se establece por el puerto 143, usando comandos en texto ASCII. Los usuarios se autentican mediante nombre de usuario y contraseña, y el acceso al buzón solo es posible tras una autenticación exitosa.

El protocolo SMTP se usa normalmente para enviar correos. Al copiar los correos enviados en una carpeta IMAP, todos los clientes tienen acceso a ellos. IMAP también permite crear carpetas y estructuras dentro del buzón, facilitando la gestión. Sin embargo, esto aumenta el uso de espacio en el servidor.

IMAP transmite datos sin cifrado de manera predeterminada, lo que podría comprometer la seguridad. Para proteger la privacidad, muchos servidores requieren sesiones IMAP cifradas mediante SSL/TLS, usando puertos alternativos como el 993 para mayor seguridad.

### Configuración por defecto

#### 1. Comandos IMAP

| Comando                                | Descripción                                                       |
|----------------------------------------|-------------------------------------------------------------------|
| 1 LOGIN username password              | Inicia sesión del usuario.                                        |
| 1 LIST "" *                            | Lista todos los directorios.                                      |
| 1 CREATE "INBOX"                       | Crea un buzón con el nombre especificado.                          |
| 1 DELETE "INBOX"                       | Elimina un buzón.                                                 |
| 1 RENAME "ToRead" "Important"          | Renombra un buzón.                                                |
| 1 LSUB "" *                            | Devuelve un subconjunto de nombres de los buzones activos o suscritos por el usuario. |
| 1 SELECT INBOX                         | Selecciona un buzón para que los mensajes en él puedan ser accesados. |
| 1 UNSELECT INBOX                       | Sale del buzón seleccionado.                                      |
| 1 FETCH <ID> all                       | Recupera los datos asociados con un mensaje en el buzón.          |
| 1 CLOSE                                | Elimina todos los mensajes con la etiqueta de Eliminado.          |
| 1 LOGOUT                               | Cierra la conexión con el servidor IMAP.                          |
#### 2. Comandos POP3

| Comando           | Descripción                                                     |
|-------------------|-----------------------------------------------------------------|
| USER username     | Identifica al usuario.                                          |
| PASS password     | Autenticación del usuario mediante su contraseña.               |
| STAT              | Solicita al servidor el número de correos guardados.            |
| LIST              | Solicita al servidor el número y tamaño de todos los correos.   |
| RETR id           | Solicita al servidor que entregue el correo solicitado por ID.  |
| DELE id           | Solicita al servidor que elimine el correo solicitado por ID.   |
| CAPA              | Solicita al servidor que muestre las capacidades del servidor.  |
| RSET              | Solicita al servidor que reinicie la información transmitida.   |
| QUIT              | Cierra la conexión con el servidor POP3.                        |
### Configuración peligrosa

Sin embargo, las opciones de configuración que se configuraron incorrectamente podrían permitirnos obtener más información, como depurar los comandos ejecutados en el servicio o iniciar sesión como usuario anónimo, similar al servicio FTP. La mayoría de las empresas utilizan proveedores de correo electrónicos de terceros, como Google, Microsoft y muchos otros. Sin embargo, algunas empresas todavía utilizan sus propios servidores de correo por diversas razones. Una de estas razones es mantener la privacidad que desean controlar por sí mismos. Los administradores pueden cometer muchos errores de configuración, que en los peores casos permitirán leer todos los correos electrónicos enviados y recibidos, lo cual podría contener información confidencial o sensible. Algunas de estas opciones de configuración incluyen:

| Ajuste                  | Descripción                                                                                           |
| ----------------------- | ----------------------------------------------------------------------------------------------------- |
| auth_debug              | Habilita todos los registros de depuración de autenticación.                                          |
| auth_debug_passwords    | Ajusta la verbosidad de los registros, se registran las contraseñas enviadas y el esquema.            |
| auth_verbose            | Registra los intentos de autenticación fallidos y sus razones.                                        |
| auth_verbose_passwords  | Las contraseñas usadas para la autenticación se registran y pueden ser truncadas.                     |
| auth_anonymous_username | Especifica el nombre de usuario que se usará cuando se inicie sesión con el mecanismo ANONYMOUS SASL. |
### Footprinting al servicio

Por defecto, POP3 usa los puertos `110` y `995`, y los puertos `143` y `993` se usan para IMAP. Los puertos más altos de ellos (`993` y `995`) usan SSL/TLS para encriptar la comunicación entre el cliente y el servidor. Usando nmap, podemos escanear el servicio para dichos puertos

#### nmap

```shell-session
amr251@htb[/htb]$ sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-19 22:09 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00026s latency).

PORT    STATE SERVICE  VERSION
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: AUTH-RESP-CODE SASL STLS TOP UIDL RESP-CODES CAPA PIPELINING
| ssl-cert: Subject: commonName=mail1.inlanefreight.htb/organizationName=Inlanefreight/stateOrProvinceName=California/countryName=US
| Not valid before: 2021-09-19T19:44:58
|_Not valid after:  2295-07-04T19:44:58
...SNIP...
```

Por ejemplo, podemos apreciar que el common name es mail1.inlanefreight.htb, y el servidor de mail le pertenece a la organización InlaneFreight, localizada en California. 

#### cURL

```shell-session
amr251@htb[/htb]$ curl -k 'imaps://10.129.14.128' --user user:p4ssw0rd

* LIST (\HasNoChildren) "." Important
* LIST (\HasNoChildren) "." INBOX
```

También podemos utilizar la opción `verbose (-v)` para ver como se hizo la conexión. A través de esto, podemos ver la versión de TLS usada para el encriptamiento, más detalles del certificado SSL, e incluso el banner, que normalmente incluye la versión del servidor mail.

Para interactuar con el servidor IMAP o POP3 sobre SSL, podemos usar `openssl` y `ncat`

#### OpenSSL - Interacción encriptada de POP3 TLS

```shell-session
amr251@htb[/htb]$ openssl s_client -connect 10.129.14.128:pop3s

CONNECTED(00000003)
Can't use SSL_get_servername
depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb
verify error:num=18:self signed certificate
verify return:1
depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb
verify return:1
---
Certificate chain
 0 s:C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb

...SNIP...

---
read R BLOCK
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 3CC39A7F2928B252EF2FFA5462140B1A0A74B29D4708AA8DE1515BB4033D92C2
    Session-ID-ctx:
    Resumption PSK: 68419D933B5FEBD878FF1BA399A926813BEA3652555E05F0EC75D65819A263AA25FA672F8974C37F6446446BB7EA83F9
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - d7 86 ac 7e f3 f4 95 35-88 40 a5 b5 d6 a6 41 e4   ...~...5.@....A.
    0010 - 96 6c e6 12 4f 50 ce 72-36 25 df e1 72 d9 23 94   .l..OP.r6%..r.#.
    0020 - cc 29 90 08 58 1b 57 ab-db a8 6b f7 8f 31 5b ad   .)..X.W...k..1[.
    0030 - 47 94 f4 67 58 1f 96 d9-ca ca 56 f9 7a 12 f6 6d   G..gX.....V.z..m
    0040 - 43 b9 b6 68 de db b2 47-4f 9f 48 14 40 45 8f 89   C..h...GO.H.@E..
    0050 - fa 19 35 9c 6d 3c a1 46-5c a2 65 ab 87 a4 fd 5e   ..5.m<.F\.e....^
    0060 - a2 95 25 d4 43 b8 71 70-40 6c fe 6f 0e d1 a0 38   ..%.C.qp@l.o...8
    0070 - 6e bd 73 91 ed 05 89 83-f5 3e d9 2a e0 2e 96 f8   n.s......>.*....
    0080 - 99 f0 50 15 e0 1b 66 db-7c 9f 10 80 4a a1 8b 24   ..P...f.|...J..$
    0090 - bb 00 03 d4 93 2b d9 95-64 44 5b c2 6b 2e 01 b5   .....+..dD[.k...
    00a0 - e8 1b f4 a4 98 a7 7a 7d-0a 80 cc 0a ad fe 6e b3   ......z}......n.
    00b0 - 0a d6 50 5d fd 9a b4 5c-28 a4 c9 36 e4 7d 2a 1e   ..P]...\(..6.}*.

    Start Time: 1632081313
    Timeout   : 7200 (sec)
    Verify return code: 18 (self signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
+OK HTB-Academy POP3 Server
```

#### OpenSSL - Interacción encriptada de IMAP POP3

```shell-session
amr251@htb[/htb]$ openssl s_client -connect 10.129.14.128:imaps

CONNECTED(00000003)
Can't use SSL_get_servername
depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb
verify error:num=18:self signed certificate
verify return:1
depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb
verify return:1
---
Certificate chain
 0 s:C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb

...SNIP...

---
read R BLOCK
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 2B7148CD1B7B92BA123E06E22831FCD3B365A5EA06B2CDEF1A5F397177130699
    Session-ID-ctx:
    Resumption PSK: 4D9F082C6660646C39135F9996DDA2C199C4F7E75D65FA5303F4A0B274D78CC5BD3416C8AF50B31A34EC022B619CC633
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 68 3b b6 68 ff 85 95 7c-8a 8a 16 b2 97 1c 72 24   h;.h...|......r$
    0010 - 62 a7 84 ff c3 24 ab 99-de 45 60 26 e7 04 4a 7d   b....$...E`&..J}
    0020 - bc 6e 06 a0 ff f7 d7 41-b5 1b 49 9c 9f 36 40 8d   .n.....A..I..6@.
    0030 - 93 35 ed d9 eb 1f 14 d7-a5 f6 3f c8 52 fb 9f 29   .5........?.R..)
    0040 - 89 8d de e6 46 95 b3 32-48 80 19 bc 46 36 cb eb   ....F..2H...F6..
    0050 - 35 79 54 4c 57 f8 ee 55-06 e3 59 7f 5e 64 85 b0   5yTLW..U..Y.^d..
    0060 - f3 a4 8c a6 b6 47 e4 59-ee c9 ab 54 a4 ab 8c 01   .....G.Y...T....
    0070 - 56 bb b9 bb 3b f6 96 74-16 c9 66 e2 6c 28 c6 12   V...;..t..f.l(..
    0080 - 34 c7 63 6b ff 71 16 7f-91 69 dc 38 7a 47 46 ec   4.ck.q...i.8zGF.
    0090 - 67 b7 a2 90 8b 31 58 a0-4f 57 30 6a b6 2e 3a 21   g....1X.OW0j..:!
    00a0 - 54 c7 ba f0 a9 74 13 11-d5 d1 ec cc ea f9 54 7d   T....t........T}
    00b0 - 46 a6 33 ed 5d 24 ed b0-20 63 43 d8 8f 14 4d 62   F.3.]$.. cC...Mb

    Start Time: 1632081604
    Timeout   : 7200 (sec)
    Verify return code: 18 (self signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN] HTB-Academy IMAP4 v.0.21.4
```

