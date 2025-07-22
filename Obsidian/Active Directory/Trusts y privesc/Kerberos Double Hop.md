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

