---

---
-----
- Tags: #bash #OWASP 
-----
## ¿En qué consiste?

> **Shellshock** es una vulnerabilidad crítica descubierta en 2014 en el intérprete de comandos Bash, que afecta a numerosos sistemas Unix. La falla radica en la forma en que Bash procesa las funciones definidas dentro de las variables de entorno. Esto permite a un atacante inyectar y ejecutar comandos arbitrarios a través de variables manipuladas, lo que puede derivar en la ejecución remota de código, escalada de privilegios o la divulgación de información sensible.

Esta vulnerabilidad es especialmente preocupante en entornos donde Bash es utilizado para procesar solicitudes CGI en servidores web, ya que un atacante podría explotar este fallo a través de parámetros HTTP o encabezados manipulados, comprometiendo el sistema de forma remota.

Si por ejemplo, haciendo un descubrimiento de directorios con `gobuster` encontrásemos que efectivamente existe este directorio en una web, podría haber una potencial vulnerabilidad a shellshock. (Es importante añadir el parámetro `--add-slash` al final para ello)

## Mecanismo de explotación

El ataque Shellshock se produce cuando se envía una variable de entorno especialmente formada que contiene código malicioso. Por ejemplo, mediante un payload como:

```bash
env x='() { :;}; echo vulnerable' bash -c "echo test"
```

Si el sistema es vulnerable, Bash ejecutará el código inyectado y la salida mostrará “vulnerable test”. Este comportamiento demuestra cómo Bash interpreta la definición de funciones en las variables de entorno y, en el proceso, ejecuta comandos adicionales sin la debida validación.

Otro ejemplo sería al introducir en una llamada la cabecera "User Agent":

```bash
 curl -s http://127.0.0.1/cgi-bin/status/ --proxy http://192.168.1.62:3128 -H "User-Agent: () { :;}; echo; /usr/bin/whoami"
```

De esta manera, estamos ejecutando el comando `whoami` (que está en esa ruta, lo sabemos porque hemos hecho un `which whoami`) y nos devuelve www-data. El `echo;` previo al comando es necesario usualmente, a veces incluso hay que poner más de un `echo`.

## Escenarios de riesgo

Un escenario común en el que se puede explotar Shellshock es la presencia de directorios **/cgi-bin** en servidores web. Estos directorios suelen alojar scripts CGI que, en muchos casos, se ejecutan con Bash para procesar solicitudes. Si estos scripts no están debidamente protegidos, un atacante podría enviar una solicitud HTTP con variables de entorno manipuladas para desencadenar el fallo de Shellshock, obteniendo acceso remoto al sistema.

## Medidas de prevención

- **Actualizar Bash:**  
    La acción primordial es asegurarse de que la versión de Bash esté actualizada y parcheada contra Shellshock. Mantener el sistema al día con las actualizaciones de seguridad es vital.
    
- **Revisar y endurecer scripts CGI:**  
    Limitar el uso de Bash en scripts CGI o aplicar validaciones estrictas a las variables de entorno puede mitigar el riesgo. Considerar el uso de intérpretes alternativos cuando sea posible.
    
- **Restringir el acceso a directorios sensibles:**  
    Configurar adecuadamente el servidor web y el firewall para limitar el acceso a directorios como /cgi-bin, reduciendo así la superficie de ataque.
    
- **Auditoría y monitoreo:**  
    Realizar auditorías regulares y monitorear los logs del servidor para detectar cualquier actividad sospechosa que pudiera indicar un intento de explotación.