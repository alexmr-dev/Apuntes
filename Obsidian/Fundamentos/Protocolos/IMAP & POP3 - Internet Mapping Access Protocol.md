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
depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = 
...SNIP...
```

#### Comandos POP3

| **Comando** | **Descripción**                                                |
| ----------- | -------------------------------------------------------------- |
| `USER`      | Especifica el nombre de usuario para la autenticación.         |
| `PASS`      | Especifica la contraseña del usuario.                          |
| `STAT`      | Muestra el número total de mensajes y su tamaño en el buzón.   |
| `LIST`      | Muestra una lista de los mensajes en el buzón con sus tamaños. |
| `RETR`      | Recupera un mensaje específico del buzón.                      |
| `DELE`      | Marca un mensaje para su eliminación.                          |
| `RSET`      | Cancela las eliminaciones marcadas en el buzón.                |
| `QUIT`      | Finaliza la sesión y desconecta del servidor.                  |


#### OpenSSL - Interacción encriptada de IMAP POP3

```shell-session
amr251@htb[/htb]$ openssl s_client -connect 10.129.14.128:imaps

CONNECTED(00000003)
Can't use SSL_get_servername
depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb
...SNIP...
```

#### Comandos IMAP


