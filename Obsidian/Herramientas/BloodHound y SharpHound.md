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

Credenciales de acceso:

```
username: admin
password: Admin!12345#
```

Si en otro momento queremos usar de nuevo BloodHound CLI, hacemos esto:

```bash
sudo ./bloodhound-cli containers start

[+] Checking the status of Docker and the Compose plugin...
[+] Starting the BloodHound environment
[+] Running `docker` to restart containers with docker-compose.yml...
 Container bloodhound-app-db-1  Starting
 Container bloodhound-graph-db-1  Starting
 Container bloodhound-graph-db-1  Started
 Container bloodhound-app-db-1  Started
 Container bloodhound-graph-db-1  Waiting
 Container bloodhound-app-db-1  Waiting
 Container bloodhound-graph-db-1  Healthy
 Container bloodhound-app-db-1  Healthy
 Container bloodhound-bloodhound-1  Starting
 Container bloodhound-bloodhound-1  Started
```

Y ya lo tendremos abierto, por defecto en el puerto 8080:

```
sudo ./bloodhound-cli running
[+] Checking the status of Docker and the Compose plugin...
[+] Collecting list of running BloodHound containers...
[+] Found 3 running BloodHound containers

 Name            Container ID                                                     Image                                  Status                  Ports
 ––––––––––––    ––––––––––––                                                     ––––––––––––                           ––––––––––––            ––––––––––––
 bhce_bloodhound 34a768662eef597c3004f2905dcb99c961314804c6bc9c0d79099e98adb315f4 docker.io/specterops/bloodhound:latest Up 4 seconds            127.0.0.1:8080:8080 » 8080/tcp
 bhce_neo4j      32239d916f3bd6feab4e1c3e4b215a22b73250f9b37302dffb7461e6b2463ea2 docker.io/library/neo4j:4.4            Up 14 seconds (healthy) 7473/tcp, 127.0.0.1:7474:7474 » 7474/tcp, 127.0.0.1:7687:7687 » 7687/tcp
 bhce_postgres   ece693364586f15ca16b79b9a55404a21cedbc80d12ce64071a20370b7871fe2 docker.io/library/postgres:16          Up 14 seconds (healthy) 5432/tcp
```

##### Instalando BloodHound en Windows

Consultar la [guía oficial](https://bloodhound.readthedocs.io/en/latest/installation/windows.html). Tendremos que tener instalados previamente JAVA y neo4j. Para esto último, es recomendable instalar la versión 4.4. Finalmente descargamos `BloodHound.exe` desde el repositorio oficial: [https://github.com/BloodHoundAD/BloodHound/releases](https://github.com/BloodHoundAD/BloodHound/releases)

Las credenciales serán las mismas que hayamos puesto durante la instalación de neo4j. De la tortura de instalar BloodHound no nos libramos en Windows tampoco, y tenemos que seguir estos pasos.

Primero, descargamos el JDK 11 del siguiente [enlace](https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.23%2B9/OpenJDK11U-jdk_x64_windows_hotspot_11.0.23_9.zip). Lo ponemos en alguna ruta que vayamos a recordar, como por ejemplo, `C:\Program Files\Java\jdk-11\jdk-11.0.23+9`. Ahora modificamos las variables de entorno, y establecemos `JAVA_HOME` apuntando a dicha ruta, y la ponemos también en el PATH de esta manera:

![[Pasted image 20250725222841.png]]

Posteriormente, descargamos neo4j 4.4 desde [aquí](https://neo4j.com/download-center/#community](https://neo4j.com/download-center/#community):

![[Pasted image 20250725222934.png | 400]]

Lo ponemos en alguna ruta. En mi caso, la he puesto en `C:\WinOffTools`, y he añadido dicha carpeta como exclusión para Windows Defender para evitar problemas. Abrimos PoweShell como administrador y hacemos esto:

```powershell
PS C:\WinOffTools\neo4j-community-4.4.44\bin> .\neo4j.bat install-service
Neo4j service installed.
```

> Tendremos que ponernos en la ruta `bin`

Si todo ha ido bien, no dará ningún fallo. El siguiente paso es lanzar Neo4j:

```powershell
net start neo4j
El servicio de Neo4j Graph Database - neo4j está iniciándose.
El servicio de Neo4j Graph Database - neo4j se ha iniciado correctamente.
```

Si todo ha ido bien, no habrá dado ningún fallo. Nos vamos a http://localhost:7474/ e iniciamos sesión con las credenciales `neo4j:neo4j`. Nos pedirá cambiar la contraseña, yo he puesto `bloodhound` por conveniencia. Tendremos el panel listo.

![[Pasted image 20250725223312.png]]

> Muy importante crear las variables de entorno `NEO4J_CONF` y `NEO4J_HOME`, apuntando a `C:\WinOffTools\neo4j-community-4.4.44`

Ahora, descargamos BloodHound del repositorio oficial: [https://github.com/BloodHoundAD/BloodHound/releases](https://github.com/BloodHoundAD/BloodHound/releases) y lo añadimos a la ruta excluida por el Defender, en mi caso, `C:\WinOffTools\BloodHound-win32-x64`. Para descargarlo de forma sencilla podemos tirar de `certutil` con PS como administrador:

```powershell
certutil -urlcache -split -f "https://github.com/SpecterOps/BloodHound-Legacy/releases/download/v4.3.1/BloodHound-win32-x64.zip" C:\WinOffTools\BloodHound.zip
```

Ejecutamos BloodHound.exe y nos conectamos con las credenciales establecidas. (`neo4j`:`bloodhound`)

> Cuando queramos limpiar la información de Neo4j, simplemente ejecutamos esta query: `MATCH (n) DETACH DELETE n`. Así estamos listos para cargar un nuevo zip con BloodHound

![[Pasted image 20250726181256.png]]
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

