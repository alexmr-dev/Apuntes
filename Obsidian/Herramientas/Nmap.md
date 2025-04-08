---

---
-------
- Tags: #networking #pentesting #scanning
-----
## ¿Qué es nmap?

> **Nmap (Network Mapper)** es una herramienta de código abierto utilizada para el descubrimiento de redes y auditoría de seguridad. Permite identificar dispositivos en una red, detectar puertos abiertos, servicios en ejecución, sistemas operativos y posibles vulnerabilidades.

Nmap se utiliza en múltiples escenarios, desde la administración de sistemas hasta pruebas de penetración. Puede realizar escaneos rápidos y también análisis profundos con técnicas avanzadas de evasión y detección.

🔗 [Página oficial de Nmap](https://nmap.org/)  
🔗 [Repositorio en GitHub](https://github.com/nmap/nmap)
## Parámetros principales

🔹 **Descubrimiento de equipos**

| Parámetro    | Nombre         | Funcionamiento                                                                                                             |
| ------------ | -------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `-sL`        | List scan      | Sólo lista objetivos, no envía ningún paquete a los obj                                                                    |
| `-sn`        | Ping sweep     | Sólo lista hosts. No envía ningún paquete a los objetivos, deshabilita escaneo de puertos                                  |
| `-Pn`        | No ping        | No realiza ninguna técnica de descubrimiento. Pasa directamente al análisis de puertos y deshabilita la detección de hosts |
| `-PS<ports>` | Ping TCP SYN   | Envía un **TCP SYN**, por defecto al puerto 80, aunque se puede especificar puerto                                         |
| `-PA<ports>` | Ping TCP ACK   | Envía un **TCP ACK** vacío. Traspasa cortafuegos sin estado                                                                |
| `-PU<ports>` | Ping UDP       | Envía un UDP vacío a un puerto                                                                                             |
| `-PE`        | Ping ICMP Echo | Envía un ICMP Echo Request                                                                                                 |
| `-PR`        | Ping ARP       | Sólo para objetivos de nuestra red local, envía un ARP request.                                                            |
| `-PR`        | Ping ICMP      | Envía un ICMP Address Mask Request. Muchos cortafuegos no filtran este ICMP.                                               |

🔹 **Modificadores

| Parámetro | Nombre | Funcionamiento                                                                       |
| --------- | ------ | ------------------------------------------------------------------------------------ |
| `-n`      | DNS    | No hace resolución DNS, lo que agiliza el escaneo y lo hace más sigiloso             |
| `-R`      | DNS    | Realiza la resolución inversa de DNS incluso a los objetivos que aparecen como Down. |

🔹 **Análisis de puertos**

| Parámetro     | Nombre      | Funcionamiento                                                                                                            |
| ------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------- |
| `-sT`         | Connect     | Envía un SYN, luego un RST para cerrar conexión. Conexión TCP                                                             |
| `-sS`         | SYN Stealth | Envía un SYN. Es la técnica usada por defecto. Rápida, fiable y relativamente sigilosa. También denominada half-open scan |
| `-sU`         | UPD Scan    | Envía UDP vacío. Más lento que un análisis TCP.                                                                           |
| `-sA`         | TCP ACK     | Envía ACK vacío. Sólo determina si los puertos están o no filtrados.                                                      |
| `-sN`         | TCP NULL    | Envía TCP con todos los flags a 0.                                                                                        |
| `-sF`         | TCP FIN     | Envía TCP con el flag FIN a 1.                                                                                            |
| `-sX`         | XMas Scan   | Envía TCP con los flags FIN, PSH y URG a 1.                                                                               |
| `-sO`         | IP Protocol | Envía paquetes IP con la cabecera vacía (excepto para TCP, UDP e ICMP) iterando sobre el campo IP Protocol.               |
| `-sM`         | TCP Maimon  | Envía ACK con el flag FIN a 1.                                                                                            |
| `-sW`         | TCP Window  | Envía ACK vacío. Muy parecido a ACK Stealth. Diferencia entre puertos open y closed                                       |
| `-T0` a `-T5` | Time        | Modificar velocidad del escaneo (`T0` ultra lento, `T5` ultra rápido)                                                     |

🔹 **Especificación de puertos**

| Parámetro          | Funcionamiento                                                               |
| ------------------ | ---------------------------------------------------------------------------- |
| `-F`               | Limita el análisis a los 100 puertos más comunes                             |
| `-r`               | Los puertos se analizan en orden secuencial creciente.                       |
| `-p<rango>`        | Especifica el rango de puertos a analizar. **-p- escanea todos los puertos** |
| `--top-ports<num>` | Analiza los <num> puertos más comunes, según clasificación de Nmap.          |

🔹 **Detección de versiones y SO**

| Parámetro | Funcionamiento                                                                                                           |
| --------- | ------------------------------------------------------------------------------------------------------------------------ |
| `-sV`     | Interroga al conjunto de puertos abiertos detectados para tratar de descubrir servicios y versiones en puertos abiertos. |
| `-O`      | Envía paquetes TCP y UDP al objetivo. Detección remota de SO                                                             |
| `-A`      | Detección de SO, versión, escaneo de scripts y traceroute                                                                |

🔹 **Evasión de cortafuegos**

| Parámetro   | Nombre              | Funcionamiento                                                                                                       |
| ----------- | ------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `-f`        | Fragmentar paquetes | Divide los paquetes en fragmentos de 8 bytes después de la cabecera IP.                                              |
| `--mtu`     | Fragmentar paquetes | Especifica el tamaño deseado. En múltiplos de 8 bytes.                                                               |
| `-D`        | Decoy               | Permite especificar un conjunto de IP válidas que se usarán como dirección origen en el análisis a modo de señuelos. |
| `-S <IP>`   | Falsear dirección   | Envía paquetes IP con la dirección origen especificada.                                                              |
| `-g <port>` |                     | Envía paquetes usando el puerto especificado, cuando sea posible.                                                    |

🔹 **Salida**

| Parámetro        | Nombre                       | Funcionamiento                                                                                   |
| ---------------- | ---------------------------- | ------------------------------------------------------------------------------------------------ |
| `-oN <file>`     | Salida normal                | Registra en un fichero una salida muy similar a la mostrada por pantalla en modo interactivo.    |
| `-oX <file>`     | Salida XML                   | Crea un fichero XML con los detalles del análisis                                                |
| `-oG <file>`     | Salida greppable             | Salida con formato especial que es fácilmente tratable con herramientas de consola como grep     |
| `-oA <patrón>`   | Salida en todos los formatos | Crea un fichero para los tipos de salida normal, XML y “grepable”                                |
| `-v[<nivel>]`    | Verbosidad                   | Aumenta la cantidad de información sobre el progreso del análisis que muestra nmap por pantalla. |
| `-d[<nivel>]`    | Debug                        | Añade información de depuración a la salida                                                      |
| `--reason`       | Razón                        | Indica la razón por la que se ha concluido el estado de un puerto o equipo.                      |
| `--open`         | Puertos abiertos             | Muestra en la salida los puertos identificados como (posiblemente) abiertos                      |
| `--packet-trace` | Traza de paquetes            | Hace que Nmap imprima información sobre cada paquete que envía o recibe                          |

## Comandos básicos

📌 **Escaneo rápido de una IP**

```bash
nmap 192.168.1.79
```

📌 **Escaneo de una red completa**

```bash
nmap 192.168.1.0/24
```

📌 **Escaneo en modo sigiloso (SYN scan)**

```bash
nmap -sS 192.168.1.1
```

📌 **Escaneo con detección de sistema operativo y versión de servicios**

```bash
nmap -A 192.168.1.1
```

📌 **Guardar resultados en un archivo**

```bash
nmap -oN scan_results.txt 192.168.1.1
```

📌 Enumeración HTTP

```bash
nmap --script http-enum -p80 192.168.1.88
```

📌 Reconocimiento más profundo

```bash
nmap -sCV -p22,80,3000,3306,5000 192.168.1.88 -oN targeted
```
## Casos prácticos

🔹 **Descubrir dispositivos en la red**

```bash
nmap -sn 192.168.1.0/24
```

🔎 Esto envía paquetes ICMP para listar dispositivos conectados sin escanear puertos.

----

🔹 **Descubrir puertos abiertos en un objetivo**

```bash
nmap -p- 192.168.1.1
```

🔎 Escanea **todos** los puertos (1-65535).

------

🔹 **Detectar servicios y versiones**

```bash
nmap -sV 192.168.1.1
```

🔎 Identifica qué servicios están corriendo en los puertos abiertos.

-----

🔹 **Escaneo sigiloso para evitar detección**

```bash
nmap -sS -Pn -D RND:10 192.168.1.1
```

🔎 Usa un escaneo **SYN stealth**, evita la detección con `-Pn` y usa **decoys** (`-D RND:10`).

-----

🔹 **Escaneo agresivo con traceroute y scripts NSE**

```bash
nmap -A 192.168.1.1
```

🔎 Activa escaneo profundo con análisis de SO, traceroute y más.

----

🔹 **Escaneo de vulnerabilidades con scripts NSE**

```bash
nmap --script=vuln 192.168.1.1
```

🔎 Usa scripts para detectar vulnerabilidades conocidas.

----

🔹 **Escaneo con detección de firewall**

```bash
nmap -sA 192.168.1.1
```

🔎 Usa paquetes ACK para determinar si hay un **firewall** en el objetivo.

----

🔹 **Bypass de firewall con fragmentación de paquetes**

```bash
nmap -f 192.168.1.1
```

🔎 Divide paquetes en fragmentos pequeños para evadir IDS/IPS.


## Ejemplo de análisis completo en una red local

```bash
nmap -sS -p- -sV -O -A -T4 192.168.1.0/24 -oN reporte.txt
```

🔎 Realiza un **escaneo SYN completo** de toda la red, identificando **sistemas operativos, versiones de servicios y traceroute**, guardando los resultados en `reporte.txt`.
## Ver también

Comprobar el siguiente [enlace](https://ns2.elhacker.net/cheat-sheet/) con múltiples cheatsheets