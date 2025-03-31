---

---
------
- Tags: #web #networking 
-------
## ¿Qué es BurpSuite?

> **BurpSuite** es una herramienta de prueba de penetración utilizada para encontrar vulnerabilidades de seguridad en aplicaciones web. Es una de las herramientas de prueba de penetración más populares y utilizadas en la industria de la seguridad informática. BurpSuite se compone de varias herramientas diferentes que se pueden utilizar juntas para identificar vulnerabilidades en una aplicación web.
## Herramientas de Burpsuite

Se trata de una herramienta extremadamente potente, la cual puede ser utilizada para identificar una amplia variedad de vulnerabilidades de seguridad en aplicaciones web. Al utilizar las diferentes herramientas que componen BurpSuite, los usuarios pueden identificar vulnerabilidades de forma automatizada o manual, según sus necesidades. Esto permite a los usuarios encontrar vulnerabilidades y corregirlas antes de que sean explotadas por un atacante.

Si nos vamos al panel principal del programa, vemos que tenemos muchas opciones para utilizar. Veamos algunas de ellas:
##### Proxy

Es la herramienta principal de BurpSuite y actúa como un intermediario entre el navegador web y el servidor web. Esto permite a los usuarios interceptar y modificar las solicitudes y respuestas HTTP y HTTPS enviadas entre el navegador y el servidor. El Proxy también es útil para la identificación de vulnerabilidades, ya que permite a los usuarios examinar el tráfico y analizar las solicitudes y respuestas.

Desde aquí podremos interceptar la comunicación, añadiendo el puerto de nuestra conveniencia en la configuración:

![[burpsuite_proxy.png]]

Luego, podremos usar **FoxyProxy** o alguna otra herramienta para habilitar un proxy en nuestro navegador web, poniendo el mismo puerto que hayamos configurado. Al estar el intercepter en **On**, cualquier movimiento que hagamos será interceptado y podremos comprobar el request realizado. Si desde aquí pulsamos **`Ctrl + R`**, enviaremos el request al **repeater**

##### Repeater

Es una herramienta que permite a los usuarios reenviar y repetir solicitudes HTTP y HTTPS. Esto es útil para probar diferentes entradas y verificar la respuesta del servidor. También es útil para la identificación de vulnerabilidades, ya que permite a los usuarios probar diferentes valores y detectar respuestas inesperadas.

Desde aquí podremos modificar el request y ver el response obtenido tanto como queramos, usando **`Ctrl + Space`**.

##### Scanner

Es una herramienta de prueba de vulnerabilidades automatizada que se utiliza para identificar vulnerabilidades en aplicaciones web. El Scanner utiliza técnicas de exploración avanzadas para detectar vulnerabilidades en la aplicación web, como inyecciones SQL, cross-site scripting (XSS), vulnerabilidades de seguridad de la capa de aplicación (OSWAP Top 10) y más.

##### Intruder

Es una herramienta que se utiliza para automatizar ataques de fuerza bruta. Los usuarios pueden definir diferentes payloads para diferentes partes de la solicitud, como la URL, el cuerpo de la solicitud y las cabeceras. Posteriormente, Intruder automatiza la ejecución de las solicitudes utilizando diferentes payloads y los usuarios pueden examinar las respuestas para identificar vulnerabilidades. 

En esta herramienta, disponemos de 4 tipos de ataques diferentes, en función de cómo se van a tratar los payloads en el ataque:

- **Sniper attack**: Inserta cada payload donde elijamos, uno a la vez
- **Battering ram attack**: Pone el mismo payload en todas las posiciones seleccionadas
- **Pitchfork attack**: Permite payloads diferentes 
- **Cluster bomb attack**: Para cada payload, pone otro distinto, a modo de combinatoria

![[burpsuite_attack_payload.png]]
##### Comparer

Es una herramienta que se utiliza para comparar dos solicitudes HTTP o HTTPS. Esto es útil para detectar diferencias entre las solicitudes y respuestas y analizar la seguridad de la aplicación.