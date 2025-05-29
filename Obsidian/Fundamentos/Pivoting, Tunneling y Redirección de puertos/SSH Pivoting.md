### Usando plink.exe

**Plink**, abreviatura de **PuTTY Link**, es una herramienta SSH para línea de comandos en Windows que forma parte del paquete de PuTTY cuando se instala. Al igual que SSH, Plink también puede usarse para crear reenvíos de puertos dinámicos y proxys SOCKS. Antes del otoño de 2018, Windows no incluía un cliente SSH nativo, por lo que los usuarios tenían que instalar uno por su cuenta. La herramienta preferida por muchos administradores de sistemas que necesitaban conectarse a otros hosts era PuTTY.

> *Imagina que estamos realizando un pentest y conseguimos acceso a una máquina con Windows. Enumeramos rápidamente el host y su postura de seguridad, y determinamos que está moderadamente protegido. Necesitamos usar este host como punto de pivote, pero es poco probable que podamos subir nuestras propias herramientas sin exponernos. En su lugar, podemos vivir del entorno existente y utilizar lo que ya está presente. Si el host es antiguo y PuTTY está instalado (o podemos encontrar una copia en un recurso compartido), **Plink puede ser nuestra vía hacia el éxito**. Podemos utilizarlo para establecer nuestro pivote y posiblemente evitar la detección durante más tiempo.*

Veamos el siguiente diagrama:
![[plink.png| 1000]]

La máquina atacante Windows comienza un proceso plink.exe con el comando que vemos justo debajo para empezar un port forwarding dinámico sobre el servidor Ubuntu. Esto comienza una sesión SSH entre el host atacante Windows y el servidor Ubuntu, y entonces plink empieza a escuchar en el puerto 9050. El comando en cuestión es el siguiente:

```cmd-session
plink -ssh -D 9050 ubuntu@10.129.15.50
```

##### Análisis del diagrama

 **🖥️ Máquina atacante (Windows): `10.10.15.5`**

1. **`Plink SSH Client`**  
    Se conecta vía SSH a una máquina intermedia Linux (Ubuntu), donde puede ejecutar comandos y establecer túneles.
     	Esta máquina intermedia sí tiene acceso a la red interna `172.16.5.0/24`.
2. **Túnel SSH con Plink (SOCKS proxy en 127.0.0.1:9050)**  
    El túnel se establece así:
    
```
plink.exe -ssh user@10.129.15.50 -D 9050
```

Esto crea un **proxy SOCKS en localhost:9050** que redirige tráfico a través del túnel SSH.

3. **`Proxifier`**  
    Redirige el tráfico generado por `mstsc.exe` (cliente RDP) hacia el proxy SOCKS (`127.0.0.1:9050`).
4. **`MSTSC.exe`**  
    Apunta al objetivo `172.16.5.19:3389` como si estuviera accesible directamente, pero **todo el tráfico RDP viaja a través del túnel SSH** gracias al proxy.

---

**🧩 Máquina intermedia comprometida (Ubuntu)**

- Tiene dos IPs:
    - Externa: `10.129.15.50` (accesible desde Internet o la red atacante).
    - Interna: `172.16.5.129` (acceso a la red interna de la víctima).
- Recibe la conexión SSH desde la máquina atacante.
- Redirige el tráfico RDP a través de la red interna hasta `172.16.5.19` (máquina Windows A).
    

---

 **🖥️ Máquina víctima final (Windows A)**

- IP: `172.16.5.19`
- Servicio: RDP activo en el puerto 3389.

El flujo completo es este:

```
[1] Windows atacante ejecuta Plink:
    → Se conecta vía SSH al servidor Ubuntu (10.129.15.50)
    → Crea un proxy SOCKS local en 127.0.0.1:9050

[2] Proxifier intercepta tráfico de MSTSC:
    → Lo redirige al proxy SOCKS 9050 (creado por Plink)

[3] Plink reenvía ese tráfico:
    → A través del túnel SSH hacia Ubuntu

[4] Ubuntu reenvía a la red interna:
    → El tráfico llega finalmente a 172.16.5.19:3389

[5] Resultado:
    → El atacante accede por RDP a la máquina víctima de red interna.
```

### Usando Sshuttle

**Sshuttle** es otra herramienta escrita en Python que elimina la necesidad de configurar **proxychains**. Sin embargo, esta herramienta solo funciona para realizar pivotes a través de **SSH** y no ofrece otras opciones para pivotar mediante servidores proxy **TOR** o **HTTPS**. **Sshuttle** puede ser extremadamente útil para automatizar la ejecución de reglas **iptables** y añadir reglas de pivoteo para el host remoto. Podemos configurar el servidor Ubuntu como punto de pivote y enrutar todo el tráfico de red de **Nmap** con **sshuttle** utilizando el ejemplo que se mostrará más adelante en esta sección.

Un uso interesante de **sshuttle** es que **no necesitamos usar proxychains para conectarnos a los hosts remotos**. Vamos a instalar **sshuttle** desde nuestro host pivote Ubuntu y configurarlo para conectarnos al host Windows mediante **RDP**.

```
sudo apt install sshuttle
```

Para usar sshuttle, especificamos la opción -r para conectarnos a la máquina remota con un nombre de usuario y contraseña. Luego, debemos incluir la red o IP que queremos enrutar a través del host pivote; en nuestro caso, es la red 172.16.5.0/23.

```shell-session
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v 
```

Con este comando, sshuttle crea una entrada en nuestras `iptables` para redirigir todo el tráfico a la red 172.16.5.0/23 a través del host pivote. Ahora podemos usar cualquier herramienta sin el uso de proxychains

```shell-session
nmap -v -sV -p3389 172.16.5.19 -A -Pn
```

