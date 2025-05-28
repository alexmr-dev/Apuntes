***
- Tags: #SSH #ICMP
***

> Durante una auditoría red team, una prueba de penetración o una evaluación de Active Directory, a menudo nos encontraremos en situaciones en las que ya hemos comprometido credenciales, claves SSH, hashes o tokens de acceso que nos permiten acceder a otro sistema, **pero ese sistema no es directamente accesible desde nuestra máquina atacante**.

![[pivoting.png| 700]]

En estos casos, necesitaremos usar un **host pivot** (una máquina ya comprometida) para encontrar una forma de alcanzar el siguiente objetivo.
Uno de los pasos más importantes al acceder a una máquina por primera vez es comprobar:

- Nuestro nivel de privilegio.    
- Las conexiones de red activas.    
- La posible existencia de software de acceso remoto o VPN.    

Si una máquina tiene **más de una tarjeta de red**, es probable que podamos usarla para movernos a otro segmento de red.
**Pivoting** es, en esencia, el concepto de **movernos hacia otras redes** a través de una máquina comprometida para encontrar más objetivos en distintos segmentos.

##### Términos habituales para referirse a una máquina de pivoting:

- Pivot Host (host pivot)    
- Proxy    
- Foothold (punto de apoyo)    
- Beach Head system (sistema de cabeza de playa)    
- Jump Host (host de salto)    

El uso principal del **pivoting** es **superar la segmentación de red** (tanto física como virtual) para acceder a redes aisladas. 

##### ¿Y el tunneling (túneles)?

El tunneling es un **subconjunto del pivoting**. Consiste en encapsular el tráfico de red dentro de otro protocolo y enrutarlo a través de él.

**Ejemplo ilustrativo:**

Imagina que necesitas enviar una **llave** a un compañero, pero no quieres que nadie sepa que estás enviando una llave. Entonces, la escondes dentro de un **peluche**, junto con instrucciones sobre cómo usarla. Empaquetas el peluche y lo envías.  
Cualquiera que inspeccione el paquete verá solo un peluche, sin darse cuenta de que contiene algo más. Solo tu compañero sabrá que la llave está dentro y cómo usarla al recibirla.

**Aplicaciones comunes como las VPNs o navegadores especializados son formas de tunneling**, ya que encapsulan y enrutan el tráfico.

##### ¿Es lo mismo pivoting que movimiento lateral (lateral movement)?

En el ámbito de IT y ciberseguridad, es habitual encontrarse con **diferentes términos para referirse a cosas similares**.  
En el caso del pivoting, muchas veces se le llama también **movimiento lateral**.

Pero... **¿son lo mismo?**

> La respuesta es: **no exactamente**.

A continuación (en el siguiente apartado del módulo), se comparan y contrastan **lateral movement**, **pivoting** y **tunneling**, ya que pueden generar confusión al interpretarse como conceptos idénticos, aunque no lo son del todo.

### Movimiento lateral

El **movimiento lateral** se describe como una técnica usada para ampliar nuestro acceso a otros hosts, aplicaciones y servicios dentro de un entorno de red. También puede ayudarnos a acceder a recursos del dominio que necesitamos para **elevar privilegios**.
El movimiento lateral suele permitir **escaladas de privilegios entre distintos hosts**.

**Ejemplo práctico** de movimiento lateral:

> Durante una auditoría, obtuvimos acceso inicial al entorno y conseguimos controlar la cuenta de administrador local. Escaneamos la red y detectamos tres máquinas Windows adicionales. Intentamos las mismas credenciales de administrador local, y una de ellas las aceptó. Así logramos movernos lateralmente a esa máquina y seguir comprometiendo el dominio.
### Pivoting

El **pivoting** implica el uso de múltiples hosts comprometidos para **cruzar límites de red** a los que normalmente no tendríamos acceso. Es una técnica **orientada a objetivos**, con el propósito de avanzar más profundamente en la red comprometiendo máquinas o infraestructuras concretas.

**Ejemplo práctico** de pivoting:

> En una auditoría complicada, la red objetivo estaba segmentada tanto física como lógicamente, lo que dificultaba nuestros movimientos. Comprometimos una máquina de ingeniería utilizada para tareas administrativas en el entorno operativo y empresarial. Esa máquina tenía **dos interfaces de red conectadas a segmentos distintos** (dual-homed). Gracias a eso, pudimos pivotar entre redes y continuar con la evaluación.

Para poder aplicar con éxito el concepto de **pivoting** durante una auditoría, es fundamental tener una buena comprensión de ciertos conceptos clave de redes. Esta sección es un repaso rápido de los fundamentos esenciales que debemos dominar para entender bien el pivoting.

Para llevar a cabo técnicas de _pivoting_ de forma eficaz, es fundamental tener una base sólida en conceptos de redes. Uno de los más importantes es el direccionamiento IP. Toda máquina que se comunique en una red necesita una dirección IP. Esta puede ser asignada automáticamente mediante un servidor DHCP o manualmente (de forma estática), especialmente en dispositivos críticos como servidores, routers o impresoras.

La dirección IP se asigna a una interfaz de red, conocida como NIC (Network Interface Controller), también llamada tarjeta o adaptador de red. Un sistema puede disponer de varias NICs, tanto físicas como virtuales, lo que permite que tenga varias IPs y pueda comunicarse con distintas redes simultáneamente.

Detectar oportunidades de _pivoting_ depende, en gran medida, de las IPs asignadas a los equipos comprometidos, ya que estas indican a qué redes puede acceder ese host. Por eso, es esencial revisar siempre las interfaces de red disponibles mediante comandos como `ifconfig` en Linux/macOS o `ipconfig` en Windows.

Cualquier ordenador puede actuar como router si es capaz de reenviar tráfico entre redes. En ejercicios de pivoting, a menudo convertimos un host comprometido en un router para acceder a redes internas no directamente alcanzables. Herramientas como _AutoRoute_ permiten añadir rutas hacia esas redes a través del host pivot.

La clave para esto es la **tabla de rutas**, que todos los sistemas operativos mantienen y utilizan para decidir cómo enviar paquetes hacia su destino. Estas rutas pueden estar basadas en interfaces conectadas directamente, y el tráfico hacia redes desconocidas se enviará a través de la **puerta de enlace por defecto**.

Revisar la tabla de rutas de un host comprometido nos ayuda a identificar nuevas redes accesibles y planificar cómo movernos por la infraestructura de forma más eficaz.

### Tunneling

El **tunneling** se refiere al uso de distintos protocolos para **encapsular y enviar tráfico** hacia/desde una red, especialmente en situaciones donde nuestro tráfico puede ser detectado. Por ejemplo, usamos HTTP o HTTPS para ocultar el tráfico de **Command & Control (C2)** entre nuestro servidor y los hosts víctimas. El objetivo es **evitar la detección**, camuflando nuestras acciones como tráfico normal. También se usa para exfiltración de datos o para introducir cargas maliciosas adicionales.

**Ejemplo práctico** de tunneling:

> Hemos usado túneles ocultando nuestro tráfico en HTTP y HTTPS. Esto nos permitió mantener el control C2 sobre los hosts comprometidos. Las instrucciones se escondían en peticiones GET y POST que parecían legítimas. Si el paquete estaba bien formado, se redirigía a nuestro servidor de control; si no, se desviaba a otro sitio web para despistar a los defensores.

### Resumiendo

- **Lateral Movement**: permite expandirnos **horizontalmente** dentro de la misma red, buscando **acceso y escalada de privilegios**.    
- **Pivoting**: nos permite avanzar **verticalmente** hacia **otros segmentos de red** inaccesibles directamente.    
- **Tunneling**: se centra en **ocultar el tráfico** usando otros protocolos, ya sea para exfiltración, comunicación C2 o introducir cargas útiles.

### Protocolos

Los protocolos definen cómo se comunican los sistemas en red, y cada servicio asociado suele usar un puerto concreto como identificador. Aunque los puertos son lógicos (no físicos), nos indican qué aplicaciones están accesibles en una dirección IP.

Podemos aprovechar puertos abiertos permitidos por el firewall —como el 80 para HTTP— para infiltrarnos en la red. Por eso es importante observar qué servicios están disponibles y por qué puertos se exponen.

Además, cuando ejecutamos payloads, debemos controlar tanto los **puertos de destino como los de origen**, asegurando que nuestras conexiones se establezcan correctamente hacia nuestros listeners. Este control de puertos será clave para movernos y mantener acceso durante una intrusión.