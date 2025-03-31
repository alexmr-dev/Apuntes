---

---
----
- Tags: #bash #linux
-----
## ¿Qué viene en este documento?

> En este documento vendrán organizados diferentes comandos de bash, organizados por categorías.

##### Comandos útiles haciendo shell 

- Obtener una terminal para ejecutar comandos:
```bash
script /dev/null -c bash
```

- Servidor simple en python para transferir archivos en local:
``` bash
cd /ruta_deseada
python3 -m http.server PORT
```

- Alternativa más cómoda a `cd` para ir a una ruta y volver cuando queramos:
```bash
pushd ruta_elegida
popd 
```

Con popd volvemos a la ruta donde estabamos antes. Esto funciona a modo de pila. 
##### Escribiendo scripts en bash

Añadir siempre `#!/bin/bash` al principio de nuestros scripts `.sh`.

- Ocultar cursor
``` bash
tput civis
# Volver a mostrarlo
tput cnorm
```

- Capturar CTRL + C
``` bash
function ctrl_c(){...}
trap ctrl_c SIGINT
```

##### Entorno virtual en python

Para crear y utilizar un entorno virtual en Python para instalar cualquier librería, sigue estos pasos:
1. **Crear el entorno virtual:**  
	Abre la terminal y ejecuta:

```bash
python3 -m venv venv
```

2. **Activar el entorno virtual:**  
	En Linux/macOS, activa el entorno con:
	
```bash
source venv/bin/activate
```

Cuando esté activo, verás el nombre del entorno (por ejemplo, `(venv)`) al inicio de la línea de comandos.

3. **Instalar librería**
	Con el entorno activado, instala la librería usando pip:

``` 
pip install libreria
```

4. Desactivar el entorno virtual:

	Una vez que hayas terminado, puedes salir del entorno virtual simplemente ejecutando `deactivate`


