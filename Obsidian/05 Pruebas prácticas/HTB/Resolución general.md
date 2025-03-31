> En esta nota se van a cubrir pautas y consejos para resolver máquinas de Hack the Box. 
## Documentación de ayuda

Resolver máquinas de HTB por nuestra cuenta puede llegar a ser muy complicado al principio. Vale la pena comprobar el canal de s4vitar, que cuenta con vídeos resolviendo muchísimas máquinas paso a paso. Tenemos el excel con todos los enlaces aquí: [Planning de Estudio](https://docs.google.com/spreadsheets/d/1dzvaGlT_0xnT-PGO27Z_4prHgA8PHIpErmoWdlUrSoA/edit?pli=1&gid=0#gid=0)

Otro blog altamente recomendado es el de [0xdf](https://0xdf.gitlab.io/) , que cuenta con múltiples 'walkthroughs' de muchas máquinas de HTB. En cualquier punto del proceso de aprendizaje, vale la pena leer tanto material como sea posible para entender mejor un tema y obtener diferentes perspectivas. Además de los blogs relacionados con las cajas de HTB retiradas, también es importante buscar publicaciones de blog sobre exploits/ataques recientes, técnicas de explotación de Active Directory, informes de eventos CTF y reportes de bug bounty. Todos ellos pueden contener una gran cantidad de información que puede ayudar a conectar algunos puntos en nuestro aprendizaje o incluso enseñarnos algo nuevo que pueda ser útil en una evaluación.

##### Sitios Web de Tutoriales

Existen muchos sitios web de tutoriales para practicar habilidades fundamentales de IT, como la creación de scripts.  
Dos excelentes sitios web de tutoriales son [Under The Wire](https://underthewire.tech/wargames) y [Over The Wire](https://overthewire.org/wargames/). Estos sitios están diseñados para ayudar a entrenar a los usuarios en el uso de Windows PowerShell y la línea de comandos de Linux, respectivamente, a través de diversos escenarios en un formato de "war games".  
Llevan al usuario a través de varios niveles, que consisten en tareas o desafíos para entrenarlos en el uso básico a avanzado de la línea de comandos de Windows y Linux, así como en la creación de scripts en Bash y PowerShell. Estas habilidades son fundamentales para cualquier persona que desee tener éxito en esta industria.

## Orden general en una resolución

Si bien cada máquina es un mundo, es importante seguir ciertos pasos a la hora de lograr resolver una máquina, es decir, convertirnos en root (y obtener el flag de root.txt, que suele ser lo habitual en estas máquinas). 

#### 1. Enumeración

De primeras, todas las máquinas tienen un enfoque black-box, es decir, no sabemos nada sobre la misma, el entorno, etc. Es por eso que necesitamos enumerar todo lo que hay disponible. Al iniciar, nos enfrentamos a un enfoque de caja negra, es decir, desconocemos detalles sobre la máquina y su entorno. Por ello, la enumeración exhaustiva es esencial para descubrir todos los recursos y servicios disponibles.

##### 1.1 Escaneo de Puertos

Utilizamos herramientas como `nmap` para identificar los puertos abiertos y los servicios que se ejecutan en ellos. Por ejemplo:
```
nmap -sC -sV -oN escaneo_inicial.txt <IP_de_la_máquina>
```

Este comando realiza un escaneo de scripts y detección de versiones, guardando los resultados en `escaneo_inicial.txt`.

##### 1.2 Enumeración de Servicios

Basándonos en los puertos y servicios detectados, profundizamos en cada uno. Por ejemplo, si se identifica un servidor web en el puerto 80, es recomendable:

- Navegar por el sitio web manualmente.
    
- Utilizar herramientas como `gobuster` o `dirb` para descubrir directorios y archivos ocultos.
    
- Analizar el código fuente de las páginas en busca de comentarios o información sensible.
    

##### 1.3 Enumeración de Usuarios y Sistemas

Si se detectan servicios como SSH o FTP, intentamos identificar posibles nombres de usuario. Herramientas como `enum4linux` pueden ser útiles para recopilar información en sistemas Windows.

#### 2. Explotación

Con la información recopilada durante la enumeración, procedemos a identificar y aprovechar vulnerabilidades en los servicios o aplicaciones detectadas.

##### 2.1 Explotación de Vulnerabilidades Conocidas

Investigamos si las versiones de los servicios identificados tienen vulnerabilidades conocidas. Bases de datos como CVE y herramientas como `searchsploit` son útiles para este propósito.

##### 2.2 Explotación Manual

En casos donde no existan exploits públicos, analizamos la lógica de la aplicación en busca de fallos, como inyecciones SQL, vulnerabilidades XSS o malas configuraciones.

#### 3. Escalada de Privilegios

Una vez obtenida una sesión inicial con privilegios limitados, el siguiente objetivo es elevar nuestros privilegios a nivel de administrador o root.

##### 3.1 Enumeración del Sistema Interno

Dentro de la máquina comprometida, recopilamos información sobre:

- Versiones del kernel y del sistema operativo.
    
- Permisos y propietarios de archivos y directorios.
    
- Procesos en ejecución y tareas programadas.
    

Herramientas como `linpeas` o `winPEAS` pueden automatizar este proceso.

##### 3.2 Explotación de Vulnerabilidades Locales

Buscamos vulnerabilidades en el sistema que permitan la escalada de privilegios, como exploits de kernel o configuraciones incorrectas de permisos.

##### 3.3 Abuso de Tareas Programadas y Servicios

Si identificamos tareas programadas o servicios que se ejecutan con altos privilegios y que podemos modificar, podemos utilizarlos para ejecutar nuestro código malicioso y escalar privilegios.

#### 4. Post-Explotación

Una vez con privilegios elevados, consolidamos nuestro acceso y recopilamos información adicional.

##### 4.1 Obtención de Flags

Localizamos y leemos los archivos `user.txt` y `root.txt` para capturar las flags correspondientes.

##### 4.2 Limpieza

Eliminamos cualquier archivo o configuración que hayamos modificado para no dejar rastros de nuestra actividad.

## Recursos Adicionales

Para mejorar nuestras habilidades y conocimientos, es recomendable explorar los siguientes recursos:

- **Hack The Box Academy**: Ofrece módulos de aprendizaje estructurados sobre diversas técnicas y herramientas de hacking.
    
- **TryHackMe**: Plataforma similar que proporciona rutas de aprendizaje guiadas y laboratorios prácticos.
    
- **PortSwigger Web Security Academy**: Enfocada en seguridad web, ofrece material educativo sobre vulnerabilidades y técnicas de explotación.
    

Además, participar en comunidades y foros relacionados con la ciberseguridad puede proporcionar insights valiosos y mantenernos actualizados sobre las últimas tendencias y vulnerabilidades.

**Nota**: La práctica constante y la revisión de write-ups de máquinas ya resueltas son fundamentales para el aprendizaje continuo y la mejora de nuestras habilidades en ciberseguridad.

## Consejos

- Recuerda que la enumeración es un proceso iterativo. Después de realizar nuestros escaneos de puertos con Nmap, asegúrate de llevar a cabo una enumeración detallada de todos los puertos abiertos, basándote en los servicios que se estén ejecutando en los puertos descubiertos. Sigue el mismo proceso que hicimos con Nibbles:​
    
    - **Enumeración/Escaneo con Nmap**: realiza un escaneo rápido para identificar puertos abiertos, seguido de un escaneo completo de todos los puertos.​
        
    - **Análisis Web**: verifica cualquier puerto web identificado en busca de aplicaciones web en ejecución y archivos/directorios ocultos. Algunas herramientas útiles para esta fase incluyen `whatweb` y `Gobuster`.​
        
- Si identificas la URL del sitio web, puedes añadirla a tu archivo `/etc/hosts` junto con la IP que obtendrás en la pregunta siguiente para cargarlo de manera normal, aunque esto no es necesario.​
    
- Después de identificar las tecnologías en uso, utiliza herramientas como `Searchsploit` para encontrar exploits públicos o busca en Google técnicas de explotación manual.​
    
- Tras obtener un acceso inicial, utiliza el truco de Python3 pty o los pasos de [[Shells#Tener una TTY funcional]] para mejorar a una pseudo TTY.​
    
- Realiza una enumeración manual y automatizada del sistema de archivos, buscando configuraciones incorrectas, servicios con vulnerabilidades conocidas y datos sensibles en texto claro, como credenciales.​
    
- Organiza esta información de manera offline para determinar las diversas formas de escalar privilegios a root en este objetivo.​
    
- Existen dos maneras de obtener un punto de apoyo: una utilizando Metasploit y otra mediante un proceso manual. Desafíate a ti mismo a trabajar y comprender ambos métodos.