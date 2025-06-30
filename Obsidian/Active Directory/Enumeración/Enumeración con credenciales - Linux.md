Ahora que hemos conseguido un punto de apoyo en el dominio, es hora de profundizar usando nuestras credenciales de usuario de dominio de bajo privilegio. Como ya tenemos una idea general de la base de usuarios y de equipos del dominio, toca enumerar el dominio en profundidad. Nos interesa información sobre atributos de usuarios y equipos del dominio, membresías de grupos, objetos de directiva de grupo (GPO), permisos, ACL, confianzas y más. Disponemos de varias herramientas, pero lo esencial es recordar que la mayoría de ellas no funcionarán sin credenciales válidas de usuario de dominio, sea cual sea su nivel de permisos. Por tanto, como mínimo, deberemos haber obtenido la contraseña en claro de un usuario, su hash NTLM o acceso SYSTEM en un equipo unido al dominio.

> _Nota: Para hacer este módulo de HTB se han seguido las credenciales de usuario `forend:Klmcargo2`  

### CrackMapExec

CME ofrece un menú de ayuda para cada protocolo (por ejemplo, `crackmapexec winrm -h`). Asegúrate de revisar todo el menú de ayuda y todas las opciones posibles. Por ahora, las opciones que nos interesan son:

- `-u Username`  El usuario cuyas credenciales utilizaremos para autenticarnos.    
- `-p Password`  La contraseña del usuario.
- `Target` (IP o FQDN)  El host objetivo a enumerar (en nuestro caso, el Controlador de Dominio).
- `--users`  Especifica que se deben enumerar los usuarios del dominio.
- `--groups`  Especifica que se deben enumerar los grupos del dominio.
- `--loggedon-users`  Intenta enumerar los usuarios que están conectados en el objetivo, si los hay.

Comenzaremos usando el protocolo SMB para enumerar usuarios y grupos. Apuntaremos al Controlador de Dominio (cuya dirección descubrimos antes) porque contiene todos los datos de la base de datos del dominio que nos interesan. Recuerda anteponer `sudo` a todos los comandos.

##### CME - Enumeración de Usuario de Dominio

Empezamos apuntando CME al Controlador de Dominio y usando las credenciales del usuario **forend** para obtener la lista de todos los usuarios del dominio. Fíjate en que, al mostrarnos la información de cada usuario, incluye atributos como **badPwdCount**. Esto es útil para ataques de password spraying dirigidos: podríamos filtrar la lista de usuarios objetivo excluyendo aquellos cuyo **badPwdCount** sea mayor que 0, para evitar bloquear cuentas por error.

```shell-session
amr251@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users
```

También podemos obtener una lista completa de grupos de dominio. Deberíamos guardar todo el output en archivos fácilmente accesibles para consultarlos en caso de reportar la información encontrada o usarla con otras herramientas.

##### CME - Enumeración de grupo de dominio

```shell-session
amr251@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Enumerated domain group(s)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Administrators                           membercount: 3
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Users                                    membercount: 4
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Guests                                   membercount: 2
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Print Operators                          membercount: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Backup Operators                         membercount: 1
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Replicator                               membercount: 0

<SNIP>
```

El fragmento anterior lista los grupos dentro del dominio y el número de usuarios en cada uno. La salida también muestra los grupos integrados en el Controlador de Dominio, como **Backup Operators**. Podemos empezar a apuntar los grupos de interés. Fíjate en grupos clave como **Administrators**, **Domain Admins**, **Executives** y cualquier otro que pueda contener administradores de TI con privilegios; esos usuarios elevados serán los objetivos más valiosos durante nuestra evaluación.

##### CME - Usuarios logueados

```shell-session
amr251@htb[/htb]$ sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users

SMB         172.16.5.130    445    ACADEMY-EA-FILE  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-FILE) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.5.130    445    ACADEMY-EA-FILE  [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 (Pwn3d!)
SMB         172.16.5.130    445    ACADEMY-EA-FILE  [+] Enumerated loggedon users
SMB         172.16.5.130    445    ACADEMY-EA-FILE  INLANEFREIGHT\clusteragent              logon_server: ACADEMY-EA-DC01
SMB         172.16.5.130    445    ACADEMY-EA-FILE  INLANEFREIGHT\lab_adm                   logon_server: ACADEMY-EA-DC01
SMB         172.16.5.130    445    ACADEMY-EA-FILE  INLANEFREIGHT\svc_qualys                logon_server: ACADEMY-EA-DC01
SMB         172.16.5.130    445    ACADEMY-EA-FILE  INLANEFREIGHT\wley                      logon_server: ACADEMY-EA-DC01

<SNIP>
```

En este servidor vemos múltiples usuarios conectados; destaca que **forend** es administrador local (lo indica “Pwn3d!”) y que **svc_qualys**, un Domain Admin, también tiene sesión activa. Esto sugiere que puede usarse como jump host y que robar o suplantar las credenciales de **svc_qualys** en memoria sería un objetivo sencillo. Herramientas como CME permiten esta enumeración enfocada, mientras que BloodHound (o PowerView) facilita la detección gráfica y rápida de sesiones de usuario en el dominio.

##### CME - Búsqueda de shares/recursos

Podemos usar el flag `--shares` para enumerar recursos disponibles en el host remoto y el nivel de acceso que nuestra cuenta tiene en cada share:

```shell-session
amr251@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares
```

Existe un módulo llamado `spider_plus` que excavará a través de cada recurso con permisos de lectura y listará todos los archivos leíbles.

```shell-session
amr251@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'

...SNIP...
SPIDER_P... 172.16.5.5      445    ACADEMY-EA-DC01  [*]     OUTPUT: /tmp/cme_spider_plus
```

En el comando anterior ejecutamos el spider contra las Department Shares. Al finalizar, CME guarda los resultados en un fichero JSON en `/tmp/cme_spider_plus/<IP_del_host>`. A continuación vemos un fragmento de esa salida JSON.

Podríamos explorar para encontrar archivos interesantes, como `web.config` o scripts que contengan contraseñas. Si quisiéramos profundizar, podríamos descargar esos ficheros y revisar su contenido en busca de credenciales embebidas u otra información sensible.

### SMBMap

SMBMap te permite, desde un host Linux, enumerar recursos SMB remotos usando credenciales de dominio: muestra qué comparticiones existen, sus permisos y su contenido, y facilita descargar/subir ficheros o ejecutar comandos. Además de listar shares, ofrece opciones como listado recursivo de directorios o búsqueda de contenido en archivos, lo que resulta muy útil para extraer información valiosa de los recursos compartidos.

##### Comprobar acceso

```shell-session
amr251@htb[/htb]$ smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5

[+] IP: 172.16.5.5:445	Name: inlanefreight.local                               
    Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	Department Shares                                 	READ ONLY	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share 
	User Shares                                       	READ ONLY	
	ZZZ_archive                                       	READ ONLY
```

La salida anterior nos muestra a qué recursos puede acceder nuestro usuario y con qué permisos. Al igual que con CME, vemos que **forend** no tiene acceso a ADMIN$ ni a C$ del DC (lo esperable para una cuenta estándar), pero sí permiso de lectura en IPC$, NETLOGON y SYSVOL, que es lo predeterminado en cualquier dominio. Los recursos no estándar, como **Department Shares** y los shares de usuario o de archivo, son los más interesantes. Hagamos un listado recursivo de directorios en **Department Shares**: como cabe esperar, aparecerán subdirectorios para cada departamento de la empresa.

##### Lista recursiva de todos los directorios

```shell-session
amr251@htb[/htb]$ smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only

[+] IP: 172.16.5.5:445	Name: inlanefreight.local                               
    Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Department Shares                                   	READ ONLY	
	.\Department Shares\*
```

Al profundizar el listado recursivo, se mostrará la salida de todos los subdirectorios dentro de los directorios de nivel superior. El uso de `--dir-only` ofrece únicamente la lista de directorios y no incluye los archivos. Pruébalo contra otros recursos compartidos en el Controlador de Dominio y comprueba qué puedes encontrar.

### RPCClient

Debido a las sesiones NULL de SMB (tratadas en profundidad en la sección de password spraying) en algunos de nuestros hosts, podemos realizar enumeración autenticada o no autenticada usando `rpcclient` en el dominio INLANEFREIGHT.LOCAL. Un ejemplo de uso de `rpcclient` desde un punto de vista no autenticado (si esta configuración existe en el dominio objetivo) sería:

```bash
rpcclient -U "" -N 172.16.5.5
```

Al ver usuarios en **rpcclient**, aparece junto a cada uno un campo **rid**, que es el identificador relativo (en hexadecimal) que Windows añade al **SID** del dominio para crear el SID completo de un objeto. Por ejemplo, el dominio **INLANEFREIGHT.LOCAL** tiene SID base `S-1-5-21-3842939050-3880317879-2865463114`; al sumar el RID hexadecimal `0x457` (decimal 1111) de **htb-student**, obtenemos su SID completo `S-1-5-21-3842939050-3880317879-2865463114-1111`. Ese valor es único en el dominio. En cambio, cuentas integradas como **Administrator** siempre usan el mismo RID (`0x1f4` → 500), lo que facilita identificarlas y profundizar en su enumeración con herramientas como **rpcclient**.

##### Enumeración de usuarios con RPCClient por RID

```shell-session
rpcclient $> queryuser 0x457
```

Al consultar con `queryuser` el RID `0x457`, `rpcclient` nos devolvió la información de **htb-student**, tal como esperábamos. Para obtener los RID de todos los usuarios de forma masiva, bastaría con usar el comando `enumdomusers`.

### Impacket Toolkit

Impacket es un conjunto de herramientas en Python para interactuar y explotar protocolos Windows (entre ellas wmiexec.py y psexec.py). Tras capturar y crackear el hash de wley (obteniendo la contraseña transporter@4), utilizaremos esas credenciales—siendo administrador local en ACADEMY-EA-FILE—para las siguientes acciones.
##### Psexec.py

Una de las herramientas más útiles del conjunto Impacket es **psexec.py**. Psexec.py es una réplica del ejecutable psexec de Sysinternals, pero funciona de forma ligeramente distinta al original. La herramienta crea un servicio remoto subiendo un ejecutable con nombre aleatorio al recurso ADMIN$ del equipo objetivo. A continuación, registra el servicio mediante RPC y el Windows Service Control Manager. Una vez establecido, la comunicación se realiza a través de una tubería con nombre (named pipe), ofreciendo una shell remota interactiva con privilegios SYSTEM en el equipo víctima.

```bash
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125  
```

##### Wmiexec.py

Wmiexec.py ofrece una shell seminteractiva usando WMI, sin dejar archivos en el equipo objetivo y generando menos registros. Se ejecuta con el usuario administrador local que especifiques (en lugar de SYSTEM), lo que lo hace más sigiloso; aunque sigue siendo detectable por AV/EDR modernos. Usaremos la misma cuenta que con psexec.py para acceder.

```bash
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5  
```

Este shell de WMI no es totalmente interactivo: cada comando lanza un nuevo `cmd.exe`, lo que genera un evento 4688 (“nuevo proceso creado”) en los registros y puede alertar a un defensor. Además, funciona bajo el contexto del usuario (por ejemplo, **wley**) y no como **SYSTEM**, lo que lo hace algo más discreto pero aún detectable. Aun así, Impacket es una herramienta esencial para pentesters en entornos Windows.

### Windapsearch

Windapsearch es un script en Python que, mediante consultas LDAP, permite enumerar usuarios, grupos y equipos de un dominio Windows. Tenemos varias opciones con Windapsearch para realizar una enumeración estándar (volcar usuarios, equipos y grupos) y una más detallada. La opción `--da` (enumerar los miembros del grupo de administradores de dominio) y la opción `-PU` (buscar usuarios privilegiados). La opción `-PU` es interesante porque realiza una búsqueda recursiva de usuarios con membresías de grupos anidados.

##### Windapsearch - Administradores de Dominio

```shell-session
amr251@htb[/htb]$ python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da

[+] Using Domain Controller at: 172.16.5.5
[+] Getting defaultNamingContext from Root DSE
[+]	Found: DC=INLANEFREIGHT,DC=LOCAL
[+] Attempting bind
[+]	...success! Binded as: 
[+]	 u:INLANEFREIGHT\forend
[+] Attempting to enumerate all Domain Admins
[+] Using DN: CN=Domain Admins,CN=Users.CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
[+]	Found 28 Domain Admins:

cn: Administrator
userPrincipalName: administrator@inlanefreight.local

cn: lab_adm

cn: Matthew Morgan
userPrincipalName: mmorgan@inlanefreight.local

<SNIP>
```

Con `windapsearch -PU` puedes detectar usuarios con privilegios elevados derivados de membresías de grupos anidados, lo cual es muy útil para informar sobre permisos excesivos en tu reporte.

##### Windapsearch - usuarios privilegiados

```shell-session
amr251@htb[/htb]$ python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU
```

Observarás que realizó variaciones sobre nombres comunes de grupos elevados en distintos idiomas. Esta salida ejemplifica el peligro de la membresía de grupos anidados, y resultará aún más evidente cuando usemos los gráficos de BloodHound para visualizarlo.

### BloodHound.py

Con credenciales de dominio, ejecutamos el ingestor BloodHound.py desde nuestro host Linux para recolectar datos de Active Directory (usuarios, grupos, equipos, miembros de grupos, GPO, ACL, sesiones, accesos RDP/WinRM, etc.) y generar “rutas de ataque” gráficas en la GUI de BloodHound. Gracias a su teoría de grafos y a queries predefinidas o personalizadas en Cypher, detecta relaciones y vulnerabilidades sutiles que pasarían desapercibidas con otras herramientas. Además de la versión C# (SharpHound) para Windows, existe este collector en Python (necesita Impacket, ldap3 y dnspython), ideal cuando no disponemos de un equipo Windows unido al dominio o para evitar levantar alertas en entornos muy protegidos.

```shell-session
amr251@htb[/htb]$ sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all 

INFO: Found AD domain: inlanefreight.local
INFO: Connecting to LDAP server: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
...SNIP...
```

El comando ejecutó Bloodhound.py con el usuario **forend**, indicando el controlador de dominio como servidor DNS (`-ns`) y el dominio INLANEFREIGHT.LOCAL (`-d`), además de la opción `-c all` para realizar todas las comprobaciones. Al completarse, generará en el directorio actual archivos JSON nombrados según la fecha.

##### Subiendo el zip generado en BloodHound GUI

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

![[Bloodhound1.png]]

La consulta “Find Shortest Paths To Domain Admins” traza relaciones entre usuarios, grupos, hosts, ACLs y GPOs para identificar posibles rutas de escalada hasta privilegios de dominio, lo que guía nuestro movimiento lateral. Tras cargar los JSON, explora las pestañas Database Info, Node Info y Analysis—con sus consultas predefinidas—y prueba consultas Cypher personalizadas. Ajusta en Settings la vista de nodos y bordes o activa el modo oscuro. Más adelante veremos SharpHound en Windows y cómo aprovechar esos datos en la GUI de BloodHound antes de pasar a otras herramientas desde un host Windows en INLANEFREIGHT.LOCAL.

