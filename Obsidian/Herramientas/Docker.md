---

---
----
- Tags: #bash #docker
-------

## Definición

> Docker es

## 1. Comandos generales

##### 1.1 Obtener información

>  Proporciona información detallada sobre la configuración y estado actual del demonio de Docker. Incluye número de contenedores activos, versión del motor, configuración de red y almacenamiento.

``` bash
docker info
```

## 2. Comandos para contenedores

##### 2.1 Listar contenedores activos:

> Lista los contenedores activos en la máquina. Uso básico: ` docker ps `

Parámetros:
- **`-a`**:  Mostrarlos todos, incluidos los detenidos
- **`-f`**:  Filtrar según una condición
- **`-q`**:  Mostrar solo sus IDs

##### 2.2 Crear y correr un contenedor

> Crea y ejecuta un contenedor desde una imagen. Uso básico:  `docker run <image_name> `

Parámetros:
- **`-i`**: Modo interactivo
- **`-t`**: Añadir una TTY (terminal interactiva)
- **`-d`**: Ejecución en segundo plano
- **`-p`**: Asigna un puerto del host al contenedor (port-forwarding)
- **`--name`**: Asigna un nombre a un contenedor

Ejemplo:
```bash
docker run -dit -p22:22 --name myServer my_serve
```
##### 2.3 Ejecutar comandos en un contenedor

> Ejecuta un nuevo comando en un contenedor en ejecución. Uso básico: ` docker exec <CONTAINER_NAME> <COMMAND> `

Parámetros:
- **`-d`**: Ejecutar comando de fondo, 'background'
- **`-i`**: Mantiene el modo interactivo
- **`-t`**: Añadir una TTY
- **`-e`**: Establece variables de entorno

Ejemplo:
```bash
docker exec -it my_server bash
```

##### 2.4 Eliminar contenedores

> Elimina todos los contenedores. Uso básico: `docker rm [OPTIONS] [NAME] [NAME ...]`

Parámetros:
- **`-f, --force`**: Forzar eliminado
- **`--all-inactive`**: Elimina todos los contenedores inactivos

Borrar todos los contenedores:
```bash
docker rm $(docker ps -a -q) --force
```
## 3. Comandos para imágenes

##### 3.1 Listar imágenes

> Muestra una lista de todas las imágenes almacenadas. Uso básico: `docker images.`
##### 3.2 Construir y gestionar imágenes

> Construye una imagen Docker a partir de un archivo `Dockerfile`. Uso básico: `docker build -t <IMAGE_NAME> .`

Parámetros:
- **`-t`**: Añade un nombre y, opcionalmente, una versión.

Ejemplo:
```bash
docker build -t webserver .
```
##### 3.3 Eliminar imágenes

Eliminar todas las imágenes locales:
```bash
docker rmi $(docker images -q)
```

Eliminar imágenes huérfanas (dangling) es decir, aquellas que no están asociadas a un contenedor en ejecución o detenido
```bash
docker image prune
```
## 4. Comandos para redes

##### 4.1 Listar redes actuales

> Con el comando `docker network ls` se listan las redes Docker

##### 4.2 Eliminar redes

Eliminar una o más redes: (Se puede usar el parámetro **`-f`** para forzar)
```bash
docker network rm
```

Eliminar redes no utilizadas:
```bash
docker network prune
```

##### 4.3 Inspeccionar una red

> Con el comando `docker network inspect <NETWORK_NAME>` se devuelve información sobre una o más redes. Por defecto, devuelve la información en formato JSON

Parámetros:
- **`-f`**: Formato a especificar, pudiendo elegir entre 'json' o 'TEMPLATE'
- **`-v`**: Verbose (información adicional)