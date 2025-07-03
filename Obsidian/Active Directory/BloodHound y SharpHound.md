Se ha decidido dejar un capítulo específico para estas dos herramientas pues vamos a tener que recurrir en múltiples ocasiones aquí durante las auditorías. 

##### Instalando BloodHound en Linux 

Instalar BloodHound es una tortura, así que para simplificar el proceso, simplemente tiramos de la imagen oficial de Docker y seguimos 3 sencillos pasos:

Paso 1: Descargar la imagen oficial:

```bash
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
```

Paso 2: Descomprimir y dar permisos de ejecución:

```bash
tar -xzf bloodhound-cli-linux-amd64.tar.gz
chmod +x bloodhound-cli
```

Paso 3: Instalar la imagen de docker y desplegar:

```bash
./bloodhound-cli install
...SNIP...
[+] BloodHound is ready to go!
[+] You can log in as `admin` with this password: 9VXtaWqNRb6Gv7w60XaFSO8cl65vRUyK
[+] You can get your admin password by running: bloodhound-cli config get default_password
[+] You can access the BloodHound UI at: http://127.0.0.1:8080/ui/login
```

Ponemos esa contraseña, y nos pedirá una nueva. Por dejarlo como estándar, se usará en Bloodhound la siguiente: `Admin!12345#`. Bien, desde el equipo donde tenemos acceso al DC, ejecutamos el comando que está arriba para obtener los archivos JSON correspondientes. Tras generarlos, creamos un .zip con ellos y lo subimos a BloodHound, justo en 'Upload File(s)', y esperamos a que termine de analizar. 

##### Instalando BloodHound en Windows

Consultar la [guía oficial](https://bloodhound.readthedocs.io/en/latest/installation/windows.html). Tendremos que tener instalados previamente JAVA y neo4j. Para esto último, es recomendable instalar la versión 4.4. Finalmente descargamos `BloodHound.exe` desde el repositorio oficial: [https://github.com/BloodHoundAD/BloodHound/releases](https://github.com/BloodHoundAD/BloodHound/releases)

Las credenciales serán las mismas que hayamos puesto durante la instalación de neo4j. 

##### SharpHound

Esta herramienta es la que nos va a generar el zip que posteriormente usaremos en BloodHound. Una vez lo tengamos descargado en Windows, podemos usarlo de la siguiente manera:

```
PS C:\Tools> .\SharpHound.exe -c All --zipfilename nombre_fichero_zip
```

##### BloodHound-Python

Este es el método más efectivo para generar el zip desde una máquina Linux. Su uso funciona de la siguiente manera:

```bash
sudo bloodhound-python -u 'user' -p 'pass' -ns 172.16.5.5 -d domain -c all 
```

Tras un rato obtendremos el zip que usaremos posteriormente en BloodHound para ver las relaciones mediante grafos. 

##### Buscar usuarios vulnerables a Kerberoasting

En el apartado `</> CYPHER` de BloodHound, escribimos la siguiente consulta una vez haya cargado correctamente el Zip. 

```
MATCH (u:User) WHERE u.hasspn=true RETURN u
```

Nos dará cuentas que tienen un SPN asociado. 

