---

---
----
- Tags: #linux #enumeracion
-----
## ¿En qué consiste?

> La enumeración es un proceso crítico para identificar por ejemplo vías potenciales de poder elevar nuestros privilegios de usuario, así como para comprender la estructura del sistema objetivo y encontrar información útil para futuros ataques. Una vez hayamos comprometido una máquina, no siempre tendremos privilegios de administrador, por lo que debemos aplicar reconocimiento para buscar vulnerabilidades y **escalar privilegios**

## Herramientas

Existen múltiples herramientas para ello realizar la enumeración y reconocimiento de un sistema. Veámoslas:

##### 1. LSE (Linux Smart Enumeration)

Es una herramienta de enumeración para sistemas Linux que permite a los atacantes obtener información detallada sobre la configuración del sistema, los servicios en ejecución y los permisos de archivo. LSE utiliza una variedad de comandos de Linux para recopilar información y presentarla en un formato fácil de entender. Al utilizar LSE, los atacantes pueden detectar posibles vulnerabilidades y encontrar información valiosa para futuros ataques. Disponible en el siguiente [enlace](https://github.com/diego-treitos/linux-smart-enumeration). Simplemente obtenemos con `wget` o `curl` el archivo `lse.sh`, le damos permisos de ejecución y lo ejecutamos. 

##### 2. Pspy

Es una herramienta de enumeración de procesos que permite a los atacantes observar los procesos y comandos que se ejecutan en el sistema objetivo a intervalos regulares de tiempo. Pspy es una herramienta útil para la detección de malware y backdoors, así como para la identificación de procesos maliciosos que se ejecutan en segundo plano sin la interacción del usuario. Disponible en el siguiente [enlace](https://github.com/DominicBreuker/pspy)

##### 3. GFTOBins

Esta web proporciona una lista de binarios de Unix legítimos, para entre otros propósitos, evadir shells restrictivas o elevar privilegios. La web se encuentra disponible en el siguiente [enlace](https://gtfobins.github.io/)