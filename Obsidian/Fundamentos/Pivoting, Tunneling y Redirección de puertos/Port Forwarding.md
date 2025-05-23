> La redirección de puertos (port forwarding) es una técnica que nos permite redirigir una solicitud de comunicación de un puerto a otro. Esta técnica utiliza TCP como la capa principal de comunicación para proporcionar una interacción en tiempo real para el puerto redirigido. Sin embargo, se pueden utilizar diferentes protocolos de la capa de aplicación, como SSH, o incluso SOCKS (que no pertenece a la capa de aplicación), para encapsular el tráfico redirigido. Esta técnica puede ser eficaz para evadir cortafuegos (firewalls) y aprovechar servicios existentes en el host comprometido para pivotar hacia otras redes.

### SSH Local Port Forwarding

![[Pasted image 20250521091836.png | center | 700]]

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

El output nos muestra que el puerto 22 (SSH) está abierto. Para acceder al servicio MySQL