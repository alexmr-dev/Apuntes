---

---
----
- Tags: #pentesting 
-----

### ¿En qué consiste?

Un test de penetración cuenta con muchos procesos. Resumidamente, desde el principio hasta el final, las fases son las siguientes:

| Fase                           | Descripción                                                                                                                                                                                                               |
|--------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Pre-Engagement**             | El primer paso es crear todos los documentos necesarios en la fase de preinvolucramiento, discutir los objetivos de la evaluación y aclarar cualquier pregunta.                                                        |
| **Recolección de Información** | Una vez completadas las actividades de preinvolucramiento, investigamos el sitio web existente de la empresa asignada para la evaluación. Identificamos las tecnologías en uso y aprendemos cómo funciona la aplicación web. |
| **Evaluación de Vulnerabilidades** | Con esta información, podemos buscar vulnerabilidades conocidas e investigar características cuestionables que puedan permitir acciones no deseadas.                                                                |
| **Explotación**                | Una vez que encontramos posibles vulnerabilidades, preparamos nuestro código de explotación, herramientas y entorno, y probamos el servidor web en busca de estas vulnerabilidades potenciales.                      |
| **Post-Explotación**           | Tras explotar con éxito el objetivo, recopilamos información y examinamos el servidor web desde el interior. Si encontramos información sensible, intentamos escalar nuestros privilegios (según el sistema y configuraciones).    |
| **Movimiento Lateral**         | Si otros servidores y hosts en la red interna están en alcance, intentamos movernos a través de la red y acceder a otros hosts y servidores utilizando la información que hemos recopilado.                        |
| **Prueba de Concepto**         | Creamos una prueba de concepto que demuestra que estas vulnerabilidades existen y, potencialmente, automatizamos los pasos individuales que desencadenan estas vulnerabilidades.                                     |
| **Post-Engagement**            | Finalmente, se completa la documentación y se presenta al cliente como un informe formal. Posteriormente, podemos realizar una reunión de revisión para aclarar cualquier aspecto de las pruebas o resultados y brindar soporte al personal encargado de remediar nuestros hallazgos. |

### Escaneo de redes y servicios

Vamos a considerar un ejemplo práctico escaneando con `nmap` la red `10.129.12.0/24`. En este caso, solo contiene 2 hosts. Para realizar el escaneo, podemos tirar del siguiente comando _(Para más información, consultar [[Nmap]])_

```shell-session
nmap -sV -p- 10.129.12.0/24 -oA network-scan
```

Asumiendo que el escaneo identifica dos hosts, el output nos mostrará los puertos abiertos para cada host analizado. Para no hacer demasiado largo este documento, asumimos que los siguientes puertos son los mostrados en el análisis:
****
**10.129.12.10**  
**Puerto 21 (FTP)**: En ejecución vsftpd 3.0.3, un servidor FTP popular. FTP es a menudo un objetivo de ataques debido a mecanismos de autenticación débiles o configuraciones incorrectas.

**Puerto 22 (SSH)**: En ejecución OpenSSH 8.2p1. SSH es un protocolo seguro, pero las vulnerabilidades en versiones antiguas o credenciales débiles podrían ser explotadas.

**Puerto 80 (HTTP)**: Aloja un servidor web Apache httpd 2.4.41. Los servidores web son vectores de ataque comunes, especialmente si alojan aplicaciones vulnerables o configuraciones incorrectas.

**Puerto 443 (HTTPS)**: También ejecutando Apache httpd 2.4.41 con SSL/TLS. Los servicios HTTPS pueden ser vulnerables a configuraciones incorrectas de SSL/TLS o conjuntos de cifrado desactualizados.

**Puerto 4369 (Erlang Port Mapper Daemon)**: Usado por aplicaciones basadas en Erlang. Este servicio es menos común y puede indicar una aplicación especializada, posiblemente mal configurada o vulnerable.
****
**10.129.12.20**  
**Puerto 22 (SSH)**: En ejecución OpenSSH para Windows 9.5. SSH proporciona acceso remoto seguro, aunque las implementaciones específicas de Windows pueden tener consideraciones de seguridad únicas.

**Puerto 139 (NetBIOS)**: Un protocolo heredado usado para compartir archivos y servicios de impresora. A menudo es un objetivo en ataques debido a vulnerabilidades históricas.

**Puerto 445 (SMB)**: En ejecución el protocolo Server Message Block (SMB) de Microsoft, crítico para el intercambio de archivos en entornos Windows. SMB ha sido un objetivo de grandes exploits como EternalBlue.

**Puerto 3000 (HTTP)**: En ejecución un servidor Golang net/http. Las aplicaciones web en puertos no estándar pueden indicar servicios internos o entornos de desarrollo que requieren revisión de seguridad.

**Puerto 3389 (RDP)**: El Protocolo de Escritorio Remoto (RDP) de Microsoft, usado para administración remota. RDP es frecuentemente objetivo de ataques de fuerza bruta o exploits si no está adecuadamente asegurado.
****
##### Aprovechando los Resultados
Los resultados del escaneo proporcionan una excelente visión general para realizar pruebas adicionales. Los evaluadores pueden priorizar los objetivos en función de los servicios identificados y los riesgos asociados. Por ejemplo:

- **Escaneo de Vulnerabilidades**: Utiliza herramientas como Nessus o OpenVAS para escanear en busca de vulnerabilidades conocidas en las versiones de software identificadas.
- **Pruebas de Credenciales**: Intenta ataques de fuerza bruta en servicios como FTP, SSH y RDP para verificar contraseñas débiles.
- **Análisis de Configuración**: Revisa la configuración de los servidores web (puertos 80/443) y los brokers de mensajes (puerto 8161) en busca de configuraciones incorrectas, como credenciales predeterminadas o configuraciones inseguras.
- **Pruebas de Explotación**: Si se identifican vulnerabilidades, intenta explotarlas utilizando marcos como Metasploit para evaluar su impacto.

##### Frutas al Alcance

En ciberseguridad, las "frutas al alcance" son vulnerabilidades o configuraciones fáciles de identificar y explotar, como software sin parches o credenciales predeterminadas. Estas son oportunidades rápidas para acceder a sistemas o mejorar la seguridad. Su identificación depende de la experiencia, y se encuentran en la etapa de **Recopilación de Información** y **Evaluación de Vulnerabilidades**, investigando servicios y evaluando riesgos.

**Buscar Frutas al Alcance**  
Un error común es enfocarse en un solo servicio para explotarlo sin entender el propósito del objetivo. Es recomendable, especialmente al principio, trabajar con lo que se observa. Si prestas atención durante la fase de recopilación de información y haces una investigación adecuada, la mayoría de los problemas desaparecen.

Los problemas suelen comenzar cuando:

- No prestan atención (errores en comandos, puerto incorrecto, detalles pasados por alto).
- Sobrecargan el análisis (hacen las cosas más complejas de lo que son, no entienden los pasos o sacan conclusiones precipitadas).

Las causas más comunes incluyen:

- No saber por dónde empezar (no prestaron atención).
- No saber qué buscar (no prestaron atención).
- No saber qué hacer con la información (no prestaron atención).
- No saber cómo hacerlo (sobrecargaron el análisis).
- No saber por qué algo no funciona (no prestaron atención o sobrepensaron).
- No saber cómo hacerlo funcionar (no prestaron atención o sobrepensaron).


