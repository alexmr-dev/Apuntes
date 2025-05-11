> Este archivo es un $cheatsheet$ de comandos útiles en Linux. Se irán añadiendo más y más a medida que avance en el estudio de Linux

### 1. Directorios y archivos

| Comando   | Descripción                             | Opciones                                                                        | Ejemplos                                                                               |
| --------- | --------------------------------------- | ------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| **ls**    | Lista archivos y directorios            | `-l`: Formato largo<br>`-a`: Incluye archivos ocultos<br>`-h`: Tamaños legibles | `ls -l` → muestra detalles<br>`ls -a` → incluye ocultos<br>`ls -lh` → tamaños legibles |
| **cd**    | Cambia de directorio                    | *(ninguna)*                                                                     | `cd /ruta/a/directorio` → cambia al directorio                                         |
| **pwd**   | Muestra el directorio actual            | *(ninguna)*                                                                     | `pwd` → imprime el directorio actual                                                   |
| **mkdir** | Crea un nuevo directorio                | *(ninguna)*                                                                     | `mkdir mi_directorio` → crea el directorio                                             |
| **rm**    | Elimina archivos o carpetas             | `-r`: Elimina recursivamente<br>`-f`: Fuerza la eliminación                     | `rm archivo.txt`<br>`rm -r carpeta`<br>`rm -f archivo.txt`                             |
| **cp**    | Copia archivos o carpetas               | `-r`: Copia recursivamente                                                      | `cp archivo.txt destino/`<br>`cp -r carpeta/ destino/`                                 |
| **mv**    | Mueve o renombra archivos               | *(ninguna)*                                                                     | `mv archivo.txt nuevo.txt` → renombrar<br>`mv archivo.txt carpeta/` → mover            |
| **touch** | Crea un archivo vacío o actualiza fecha | *(ninguna)*                                                                     | `touch archivo.txt` → crea archivo vacío                                               |
| **cat**   | Muestra contenido de archivos           | *(ninguna)*                                                                     | `cat archivo.txt` → muestra el contenido                                               |
| **head**  | Muestra primeras líneas de un archivo   | `-n`: Número de líneas                                                          | `head archivo.txt`<br>`head -n 5 archivo.txt`                                          |
| **tail**  | Muestra últimas líneas de un archivo    | `-n`: Número de líneas                                                          | `tail archivo.txt`<br>`tail -n 5 archivo.txt`                                          |
| **ln**    | Crea enlaces entre archivos             | `-s`: Enlace simbólico (soft link)                                              | `ln -s origen enlace` → crea un enlace simbólico                                       |
| **find**  | Busca archivos y carpetas               | `-name`: Buscar por nombre<br>`-type`: Buscar por tipo                          | `find /ruta -name "*.txt"` → busca archivos `.txt`                                     |

### 2. Permisos de archivos

| Comando | Descripción | Opciones | Ejemplos |
|---------|-------------|----------|----------|
| **chmod** | Cambia los permisos de archivos | `u`: Usuario (propietario)<br>`g`: Grupo<br>`o`: Otros<br>`+`: Añadir permisos<br>`-`: Quitar permisos<br>`=`: Establecer permisos específicos | `chmod u+rwx archivo.txt` → otorga permisos de lectura, escritura y ejecución al propietario |
| **chown** | Cambia el propietario de un archivo | *(ninguna)* | `chown usuario archivo.txt` → cambia el propietario a "usuario" |
| **chgrp** | Cambia el grupo asociado a un archivo | *(ninguna)* | `chgrp grupo archivo.txt` → cambia el grupo a "grupo" |
| **umask** | Establece los permisos por defecto para archivos nuevos | *(ninguna)* | `umask 022` → permisos por defecto: propietario con lectura/escritura, grupo y otros solo lectura |
`chmod` permite modificar los permisos de lectura, escritura y ejecución de archivos y directorios para el **usuario (u)**, **grupo (g)** y **otros (o)**. 

```bash
chmod [quién][operador][permiso] archivo
```

- **Quién**: `u` (usuario), `g` (grupo), `o` (otros), `a` (todos)
- **Operador**: `+` (añadir), `-` (quitar), `=` (establecer exactamente)
- **Permiso**: `r` (read), `w` (write), `x` (execute)

Ejemplos:
```bash
chmod a+x script.sh       # Añadir permiso de ejecución a todos
chmod u=rw file.txt       # Propietario con lectura y escritura, sin ejecución
chmod go-r file.txt       # Quitar lectura a grupo y otros
```

**🔢 Formato numérico (octal)**

```bash
chmod [permisos en octal] archivo
```

| Número | Permisos | Significado         |
| ------ | -------- | ------------------- |
| 0      | ---      | Sin permisos        |
| 1      | --x      | Solo ejecutar       |
| 2      | -w-      | Solo escribir       |
| 3      | -wx      | Escribir + ejecutar |
| 4      | r--      | Solo leer           |
| 5      | r-x      | Leer + ejecutar     |
| 6      | rw-      | Leer + escribir     |
| 7      | rwx      | Todo                |

Ejemplos:
```bash
chmod 755 script.sh       # rwx para el propietario, rx para grupo y otros
chmod 644 documento.txt   # rw para propietario, r para grupo y otros
```

**🔒 Permisos especiales**

- **SUID (Set User ID)**: Permite que el archivo se ejecute con los permisos del propietario, no del usuario que lo ejecuta.

```bash
chmod u+s archivo
chmod 4755 archivo
```

- **SGID (Set Group ID)**: Similar a SUID, pero con el grupo.

```bash
chmod g+s archivo
chmod 2755 archivo
```

- **Sticky Bit**: Común en directorios como `/tmp`; solo el propietario puede borrar sus archivos.

```bash
chmod +t directorio
chmod 1777 /tmp
```

Podemos leer archivos con `ls -l` para ver qué permisos tienen. Se diferencian de la siguiente manera:

![[Pasted image 20250511204833.png | 400]]
### 3. Compresión y archivado

| Comando | Descripción | Opciones | Ejemplos |
|---------|-------------|----------|----------|
| `tar` | Crear o extraer archivos comprimidos (archivos `.tar`, `.tar.gz`, etc.). | `-c`: Crear un nuevo archivo.<br>`-x`: Extraer archivos de un archivo.<br>`-f`: Especificar el nombre del archivo.<br>`-v`: Modo detallado (verbose).<br>`-z`: Comprimir con gzip.<br>`-j`: Comprimir con bzip2. | `tar -czvf archivo.tar.gz directorio/`<br>Crea un archivo `.tar.gz` comprimido con el contenido del directorio. |
| `gzip` | Comprimir archivos. | `-d`: Descomprimir archivos. | `gzip archivo.txt`<br>Comprime el archivo y lo renombra como `archivo.txt.gz`. |
| `zip` | Crear archivos comprimidos `.zip`. | `-r`: Incluir directorios de forma recursiva. | `zip archivo.zip archivo1.txt archivo2.txt`<br>Crea un `.zip` con los archivos indicados. |
**Ejemplos prácticos de `tar`**:

| Comando                                 | Descripción                                                     |
| --------------------------------------- | --------------------------------------------------------------- |
| `tar -cvf archivo.tar directorio/`      | Crea un archivo `archivo.tar` con el contenido de `directorio/` |
| `tar -czvf archivo.tar.gz directorio/`  | Igual, pero **comprimido con gzip**                             |
| `tar -xvf archivo.tar`                  | Extrae un archivo `.tar` en el directorio actual                |
| `tar -xzvf archivo.tar.gz`              | Extrae un `.tar.gz`                                             |
| `tar -xvf archivo.tar -C /ruta/destino` | Extrae en una carpeta específica                                |
| `tar -tvf archivo.tar`                  | Lista el contenido del archivo sin extraer                      |
### 4. Administración de procesos y búsqueda

| Comando | Descripción                                                | Opciones                                                                                                                                                                                                                                                                                                                                                | Ejemplos                                                                                                                                                                                                                                                               |
| ------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ps`    | Muestra procesos en ejecución.                             | `aux`: Muestra todos los procesos.                                                                                                                                                                                                                                                                                                                      | `ps aux` muestra todos los procesos activos con información detallada.                                                                                                                                                                                                 |
| `top`   | Monitoriza procesos del sistema en tiempo real.            | *(Sin opciones comunes)*                                                                                                                                                                                                                                                                                                                                | `top` muestra una vista dinámica de los procesos y su uso de recursos.                                                                                                                                                                                                 |
| `kill`  | Termina un proceso por su PID.                             | `-9`: Fuerza la terminación del proceso.                                                                                                                                                                                                                                                                                                                | `kill 1234` termina el proceso con PID 1234. <br><br> `kill -9 1234` lo fuerza a cerrarse.                                                                                                                                                                             |
| `pkill` | Termina procesos por nombre.                               | *(Sin opciones comunes)*                                                                                                                                                                                                                                                                                                                                | `pkill firefox` termina todos los procesos llamados "firefox".                                                                                                                                                                                                         |
| `pgrep` | Lista PIDs de procesos por nombre.                         | *(Sin opciones comunes)*                                                                                                                                                                                                                                                                                                                                | `pgrep ssh` lista los PIDs de procesos llamados "ssh".                                                                                                                                                                                                                 |
| `grep`  | Busca patrones o expresiones regulares en archivos/textos. | `-i`: Ignorar mayúsculas/minúsculas. <br> `-v`: Mostrar líneas que **no** coinciden. <br> `-r` o `-R`: Búsqueda recursiva. <br> `-l`: Mostrar solo nombres de archivos. <br> `-n`: Mostrar números de línea. <br> `-w`: Coincidencias exactas. <br> `-c`: Contar coincidencias. <br> `-e`: Múltiples patrones. <br> `-A/B/C`: Mostrar líneas alrededor. | `grep -i "hola" archivo.txt` busca "hola" ignorando mayúsculas.<br><br> `grep -v "error" archivo.txt` omite líneas con "error". <br> <br> `grep -r "clave" carpeta/` busca en todos los archivos. <br> <br> `grep -n "patrón" archivo.txt` muestra el número de línea. |

### 5. Procesamiento de texto

| Comando | Descripción                                                              | Opciones                                                                                    | Ejemplos                                                                                                                                                        |
| ------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `awk`   | Herramienta poderosa para procesar y analizar texto línea por línea.     | `-F`: Define el delimitador de campo.                                                       | `awk '{print $1}' archivo.txt` muestra la primera columna. <br><br> `awk -F':' '{print $1, $3}' /etc/passwd` muestra nombre de usuario y UID.                   |
| `sed`   | Editor de texto en línea para sustituciones y transformaciones.          | `-i`: Editar archivos en el lugar. <br> `s/pat/rep/`: Sustituye texto.                      | `sed 's/error/OK/g' archivo.txt` reemplaza "error" por "OK". <br><br> `sed -i 's/foo/bar/g' archivo.txt` modifica el archivo directamente.                      |
| `cut`   | Extrae secciones de texto por delimitador o posición.                    | `-d`: Define delimitador. <br> `-f`: Campo(s) a mostrar. <br> `-c`: Posiciones específicas. | `cut -d':' -f1 /etc/passwd` muestra solo los nombres de usuario. <br><br> `cut -c1-5 archivo.txt` muestra los primeros 5 caracteres de cada línea.              |
| `sort`  | Ordena líneas de texto.                                                  | `-r`: Orden inverso. <br> `-n`: Orden numérico. <br> `-k`: Especifica columna para ordenar. | `sort archivo.txt` ordena alfabéticamente. <br><br> `sort -n archivo.txt` ordena numéricamente. <br> <br> `sort -k2 archivo.txt` ordena por la segunda columna. |
| `tee`   | Duplica la salida estándar a un archivo mientras se muestra en pantalla. | `-a`: Añadir al archivo en vez de sobrescribir.                                             | `echo "nueva línea"`                                                                                                                                            |
`awk` es una herramienta potente de procesamiento de texto que permite analizar y transformar archivos línea por línea, dividiendo cada línea en campos y aplicando patrones y acciones sobre ellos. 

```bash
awk [opciones] 'patrón {acción}' archivo
```

**🔧 Conceptos clave**

- **Campos**: Cada línea se divide automáticamente en campos separados por un delimitador (por defecto, espacios o tabulaciones).

    - `$1`, `$2`, ..., `$NF`: Acceden a los campos 1, 2, ..., N de la línea.
    - `$0`: Representa la línea completa.
        
- **Variables especiales**:
    
    - `NR`: Número de línea actual (registro).        
    - `NF`: Número de campos en la línea actual.        
    - `FS`: Delimitador de campos de entrada (Field Separator).        
    - `OFS`: Separador de campos de salida (Output Field Separator).
        
- **Bloques especiales**:
    
    - `BEGIN {}`: Se ejecuta antes de procesar cualquier línea.        
    - `END {}`: Se ejecuta después de procesar todas las líneas.        

**🎯 Ejemplos de uso**

```bash
awk '{print $1}' archivo.txt
# Muestra la primera columna de cada línea

awk -F':' '{print $1, $3}' /etc/passwd
# Usa ":" como delimitador y muestra nombre de usuario y UID

awk '{suma += $2} END {print suma}' archivo.txt
# Suma todos los valores de la segunda columna

awk 'NR > 1 {print $1}' archivo.txt
# Omite la primera línea (útil para saltarse encabezados)

awk 'BEGIN {FS=","} {print $1, $3}' datos.csv
# Establece la coma como delimitador antes de procesar

awk 'NF > 0' archivo.txt
# Imprime solo las líneas no vacías

awk '{if ($3 > 50) print $1, $3}' archivo.txt
# Filtra filas donde el tercer campo sea mayor a 50
```
### 6. Información del sistema

| Comando  | Descripción                                  | Opciones                                                                     | Ejemplos                                                       |
| -------- | -------------------------------------------- | ---------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `uname`  | Muestra información del sistema.             | `-a`: Toda la información del sistema.                                       | `uname -a` Muestra toda la información del sistema.            |
| `whoami` | Muestra el nombre de usuario actual.         | No tiene opciones.                                                           | `whoami` Muestra el nombre de usuario actual.                  |
| `df`     | Muestra el uso del espacio en disco.         | `-h`: Tamaños legibles por humanos.                                          | `df -h` Muestra el uso del espacio en disco de manera legible. |
| `du`     | Estima el tamaño de archivos y directorios.  | `-h`: Tamaños legibles por humanos. <br> `-s`: Muestra solo el tamaño total. | `du -sh directorio/` Muestra el tamaño total del directorio.   |
| `free`   | Muestra información sobre el uso de memoria. | `-h`: Tamaños legibles por humanos.                                          | `free -h` Muestra el uso de memoria de manera legible.         |
| `uptime` | Muestra el tiempo de actividad del sistema.  | *(Sin opciones comunes)*                                                     | `uptime` Muestra el tiempo de actividad del sistema.           |
| `lscpu`  | Muestra información sobre la CPU.            | *(Sin opciones comunes)*                                                     | `lscpu` Muestra detalles sobre la CPU.                         |
| `lspci`  | Lista los dispositivos PCI.                  | *(Sin opciones comunes)*                                                     | `lspci` Muestra una lista de los dispositivos PCI.             |
| `lsusb`  | Lista los dispositivos USB.                  | *(Sin opciones comunes)*                                                     | `lsusb` Muestra una lista de los dispositivos USB.             |

### 7. Comandos de redes

| Comando   | Descripción                                   | Ejemplos                                                |
|-----------|-----------------------------------------------|---------------------------------------------------------|
| `ifconfig`| Muestra información de las interfaces de red.  | `ifconfig` Muestra los detalles de todas las interfaces de red. |
| `ping`    | Envía solicitudes de eco ICMP a un host.       | `ping google.com` Envía solicitudes de eco ICMP a "google.com" para verificar la conectividad. |
| `netstat` | Muestra las conexiones y estadísticas de red.  | `netstat -tuln` Muestra todas las conexiones TCP y UDP en escucha. |
| `ss`      | Muestra información de los sockets de red.     | `ss -tuln` Muestra todas las conexiones TCP y UDP en escucha. |
| `ssh`     | Conecta de manera segura a un servidor remoto. | `ssh usuario@hostname` Inicia una conexión SSH al host especificado. |
| `scp`     | Copia archivos de manera segura entre hosts.   | `scp archivo.txt usuario@hostname:/ruta/destino` Copia de manera segura "archivo.txt" al host remoto especificado. |
| `wget`    | Descarga archivos desde la web.                | `wget http://example.com/archivo.txt` Descarga "archivo.txt" desde la URL especificada. |
| `curl`    | Transfiere datos desde o hacia un servidor.    | `curl http://example.com` Recupera el contenido de una página web desde la URL especificada. |

### 8. Redireccionamiento

| Comando              | Descripción                                                    | Ejemplos                                               |
|----------------------|----------------------------------------------------------------|--------------------------------------------------------|
| `cmd < file`         | La entrada de `cmd` se toma del archivo.                       | `cmd < archivo.txt` La entrada de `cmd` se toma del archivo "archivo.txt". |
| `cmd > file`         | La salida estándar (stdout) de `cmd` se redirige al archivo.   | `cmd > archivo.txt` Redirige la salida estándar de `cmd` al archivo "archivo.txt". |
| `cmd 2> file`        | La salida de error estándar (stderr) de `cmd` se redirige al archivo. | `cmd 2> error.txt` Redirige la salida de error estándar de `cmd` al archivo "error.txt". |
| `cmd 2>&1`           | Redirige stderr al mismo lugar que stdout.                     | `cmd 2>&1` Redirige la salida de error estándar de `cmd` al mismo lugar que la salida estándar. |
| `cmd1 <(cmd2)`       | La salida de `cmd2` se usa como archivo de entrada para `cmd1`. | `cmd1 <(cmd2)` La salida de `cmd2` es utilizada como entrada para `cmd1`. |
| `cmd > /dev/null`    | Descartar la salida estándar de `cmd` enviándola al dispositivo nulo. | `cmd > /dev/null` Descarta la salida estándar de `cmd`. |
| `cmd &> file`        | Redirige todas las salidas de `cmd` (stdout y stderr) al archivo. | `cmd &> archivo.txt` Redirige todas las salidas (stdout y stderr) de `cmd` al archivo "archivo.txt". |
| `cmd 1>&2`           | Redirige stdout al mismo lugar que stderr.                    | `cmd 1>&2` Redirige la salida estándar de `cmd` al mismo lugar que stderr. |
| `cmd >> file`        | Añade la salida estándar de `cmd` al archivo.                  | `cmd >> archivo.txt` Añade la salida estándar de `cmd` al final del archivo "archivo.txt". |
| `cmd << delimiter`   | Redirige un bloque de texto al estándar de entrada de `cmd`.   | `cmd << END` seguido de un bloque de texto y luego `END`. |
**Explicación del  `<<`**: Se utiliza para redirigir un bloque de texto al estándar de entrada de un comando. Se cierra el bloque de texto utilizando el delimitador (que puede ser cualquier palabra que elijas, como "END", "EOF", etc.).

```bash
cat << EOF
Este es un ejemplo de texto
que se pasa como entrada
a un comando utilizando Here Document.
EOF
```
### 9. Variables de entorno

| Comando                          | Descripción                                                        | Ejemplos                                                          |
|----------------------------------|--------------------------------------------------------------------|-------------------------------------------------------------------|
| `export VARIABLE_NAME=value`    | Establece el valor de una variable de entorno.                     | `export PATH=/usr/local/bin` Establece la variable de entorno `PATH` con el valor `/usr/local/bin`. |
| `echo $VARIABLE_NAME`           | Muestra el valor de una variable de entorno específica.            | `echo $PATH` Muestra el valor de la variable de entorno `PATH`.  |
| `env`                            | Muestra todas las variables de entorno configuradas actualmente en el sistema. | `env` Muestra todas las variables de entorno actualmente definidas. |
| `unset VARIABLE_NAME`           | Elimina una variable de entorno.                                   | `unset PATH` Elimina la variable de entorno `PATH`.               |
| `export -p`                     | Muestra una lista de todas las variables de entorno exportadas actualmente. | `export -p` Muestra todas las variables de entorno exportadas.    |
| `env VAR1=value COMMAND`        | Establece el valor de una variable de entorno solo para un comando específico. | `env PATH=/usr/bin ls` Establece el valor de `PATH` solo para el comando `ls`. |
| `printenv`                       | Muestra los valores de todas las variables de entorno.             | `printenv` Muestra todas las variables de entorno.                |

### 10. Administración de usuarios

| Comando                                    | Descripción                                                                                   | Ejemplos                                                           |
|--------------------------------------------|-----------------------------------------------------------------------------------------------|--------------------------------------------------------------------|
| `who`                                      | Muestra quién está actualmente conectado al sistema.                                           | `who` Muestra los usuarios que están actualmente logueados.        |
| `sudo adduser username`                    | Crea una nueva cuenta de usuario en el sistema con el nombre de usuario especificado.           | `sudo adduser juan` Crea el usuario "juan" en el sistema.          |
| `finger`                                   | Muestra información sobre todos los usuarios actualmente conectados al sistema, incluyendo su nombre de usuario, hora de inicio y terminal. | `finger` Muestra los detalles de los usuarios conectados.          |
| `sudo deluser USER GROUPNAME`              | Elimina el usuario especificado del grupo especificado.                                         | `sudo deluser juan admin` Elimina al usuario "juan" del grupo "admin". |
| `last`                                     | Muestra el historial reciente de inicios de sesión de los usuarios.                            | `last` Muestra los últimos inicios de sesión en el sistema.        |
| `finger username`                          | Proporciona información sobre el usuario especificado, incluyendo su nombre de usuario, nombre real, terminal, tiempo de inactividad y hora de inicio de sesión. | `finger juan` Muestra información sobre el usuario "juan".        |
| `sudo userdel -r username`                 | Elimina la cuenta de usuario especificada del sistema, incluyendo su directorio home y archivos asociados. La opción `-r` asegura la eliminación de los archivos del usuario. | `sudo userdel -r juan` Elimina la cuenta de usuario "juan" y sus archivos. |
| `sudo passwd -l username`                  | Bloquea la contraseña de la cuenta de usuario especificada, evitando que el usuario inicie sesión. | `sudo passwd -l juan` Bloquea la contraseña del usuario "juan".   |
| `su - username`                            | Cambia a otra cuenta de usuario con el entorno de ese usuario.                                  | `su - juan` Cambia al usuario "juan" con su entorno.              |
| `sudo usermod -a -G GROUPNAME USERNAME`    | Agrega a un usuario existente al grupo especificado. El usuario se agrega sin ser eliminado de sus grupos actuales. | `sudo usermod -a -G admin juan` Agrega al usuario "juan" al grupo "admin". |

### 11. Atajos

##### 11.1 Atajos en bash

**🧭 Navegación**

| Uso      | Descripción                       |
| -------- | --------------------------------- |
| Ctrl + A | Mover al inicio de la línea.      |
| Ctrl + E | Mover al final de la línea.       |
| Ctrl + B | Mover un carácter hacia atrás.    |
| Ctrl + F | Mover un carácter hacia adelante. |
| Alt + B  | Mover una palabra hacia atrás.    |
| Alt + F  | Mover una palabra hacia adelante. |
**📂 Edición**

| Ctrl + U | Cortar/eliminar desde el cursor hasta el inicio de la línea. |
| -------- | ------------------------------------------------------------ |
| Ctrl + K | Cortar/eliminar desde el cursor hasta el final de la línea.  |
| Ctrl + W | Cortar/eliminar la palabra antes del cursor.                 |
| Ctrl + Y | Pegar el último texto cortado.                               |
| Ctrl + L | Limpiar la pantalla.                                         |

**🔍 Historial**

| Ctrl + R | Buscar en el historial de comandos (búsqueda inversa). |
| -------- | ------------------------------------------------------ |
| Ctrl + G | Salir del modo de búsqueda del historial.              |
| Ctrl + P | Ir al comando anterior en el historial.                |
| Ctrl + N | Ir al siguiente comando en el historial.               |
| Ctrl + C | Terminar el comando actual.                            |
##### 11.2 Atajos en nano

**📂 Operaciones de archivo**

| Tipo    | Uso      | Descripción                                  |
| ------- | -------- | -------------------------------------------- |
| Archivo | Ctrl + O | Guardar el archivo.                          |
| Archivo | Ctrl + X | Salir de Nano (pide guardar si hay cambios). |
| Archivo | Ctrl + R | Leer un archivo dentro del buffer actual.    |
| Archivo | Ctrl + J | Justificar el párrafo actual.                |

**🧭 Navegación**

| Tipo       | Uso        | Descripción                                                  |
|------------|------------|--------------------------------------------------------------|
| Navegación | Ctrl + Y   | Desplazarse una página hacia arriba.                         |
| Navegación | Ctrl + V   | Desplazarse una página hacia abajo.                          |
| Navegación | Alt + \    | Ir a un número de línea específico.                          |
| Navegación | Alt + ,    | Ir al principio de la línea actual.                          |
| Navegación | Alt + .    | Ir al final de la línea actual.                              |

**✍️ Edición**

| Tipo     | Uso        | Descripción                                                              |
|----------|------------|--------------------------------------------------------------------------|
| Edición  | Ctrl + K   | Cortar/eliminar desde el cursor hasta el final de la línea.             |
| Edición  | Ctrl + U   | Restaurar el último texto cortado (pegar).                              |
| Edición  | Ctrl + 6   | Marcar un bloque de texto para copiar o cortar.                         |
| Edición  | Ctrl + K   | Cortar el bloque de texto marcado. (Se repite con diferente contexto).  |
| Edición  | Alt + 6    | Copiar el bloque de texto marcado.                                      |

**🔍 Búsqueda y reemplazo**

| Tipo               | Uso        | Descripción                                                             |
|--------------------|------------|-------------------------------------------------------------------------|
| Búsqueda/Reemplazo | Ctrl + W   | Buscar una cadena de texto.                                            |
| Búsqueda/Reemplazo | Alt + W    | Buscar y reemplazar una cadena de texto.                               |
| Búsqueda/Reemplazo | Alt + R    | Repetir la última búsqueda.                                            |

##### 11.3 Atajos en vi

| Comando | Descripción |
|---------|-------------|
| `cw`    | Cambia la palabra actual. Elimina desde el cursor hasta el final de la palabra y entra en modo inserción. |
| `dd`    | Elimina la línea actual. |
| `x`     | Elimina el carácter bajo el cursor. |
| `R`     | Entra en modo reemplazo. Sobrescribe caracteres desde el cursor hasta presionar `ESC`. |
| `o`     | Inserta una nueva línea debajo de la actual y entra en modo inserción. |
| `u`     | Deshace el último cambio. |
| `s`     | Sustituye el carácter bajo el cursor y entra en modo inserción. |
| `dw`    | Elimina desde el cursor hasta el comienzo de la siguiente palabra. |
| `D`     | Elimina desde el cursor hasta el final de la línea. |
| `4dw`   | Elimina las próximas cuatro palabras desde la posición del cursor. |
| `A`     | Entra en modo inserción al final de la línea actual. |
| `S`     | Elimina la línea actual y entra en modo inserción. |
| `r`     | Reemplaza el carácter bajo el cursor por otro ingresado. |
| `i`     | Entra en modo inserción antes del cursor. |
| `3dd`   | Elimina la línea actual y las dos siguientes. |
| `ESC`   | Sale del modo de inserción o línea de comandos y regresa al modo normal. |
| `U`     | Restaura la línea actual a su estado original antes de cualquier cambio. |
| `~`     | Cambia el caso (mayúscula/minúscula) del carácter bajo el cursor. |
| `a`     | Entra en modo inserción después del cursor. |
| `C`     | Elimina desde el cursor hasta el final de la línea y entra en modo inserción. |

##### 11.4 Atajos en nvim

**Modo normal**

| Modo | Comando | Descripción |
|------|---------|-------------|
| Normal | `i` | Entra en modo inserción en la posición actual del cursor. |
| Normal | `x` | Elimina el carácter bajo el cursor. |
| Normal | `dd` | Elimina la línea actual. |
| Normal | `yy` | Copia la línea actual. |
| Normal | `p` | Pega el texto copiado o eliminado debajo de la línea actual. |
| Normal | `u` | Deshace el último cambio. |
| Normal | `Ctrl + R` | Rehace el último cambio deshecho. |

**Modo comandos**

| Modo | Comando | Descripción |
|------|---------|-------------|
| Comando | `:w` | Guarda el archivo. |
| Comando | `:q` | Cierra Neovim. |
| Comando | `:q!` | Cierra Neovim sin guardar los cambios. |
| Comando | `:wq` o `:x` | Guarda y cierra Neovim. |
| Comando | `:s/old/new/g` | Sustituye todas las apariciones de "old" por "new" en el archivo. |
| Comando | `:set nu` o `:set number` | Muestra los números de línea. |

**Modo visual**

| Modo | Comando | Descripción |
|------|---------|-------------|
| Visual | `v` | Entra en modo visual para seleccionar texto. |
| Visual | `y` | Copia el texto seleccionado. |
| Visual | `d` | Elimina el texto seleccionado. |
| Visual | `p` | Pega el texto copiado o eliminado. |
