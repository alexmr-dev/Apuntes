En la sección anterior vimos herramientas de enumeración desde Linux; ahora, desde un host Windows unido al dominio, probaremos SharpHound/BloodHound, PowerView/SharpView, Grouper2, Snaffler y utilidades nativas de AD para detectar tanto rutas de ataque como hallazgos informativos que pueden interesar al cliente (configuraciones erróneas, atributos de cuentas, permisos excesivos, trusts con otros dominios, etc.). También exploraremos recursos compartidos accesibles para nuestro usuario, pues suelen contener datos sensibles (por ejemplo, credenciales) que facilitan movimientos laterales o de elevación de privilegios.
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

| Comando                  | Descripción                                                                                  |
|--------------------------|----------------------------------------------------------------------------------------------|
| `Get-NetLocalGroup`      | Enumera los grupos locales en el equipo local o remoto                                       |
| `Get-NetLocalGroupMember`| Enumera los miembros de un grupo local específico                                           |
| `Get-NetShare`           | Muestra los recursos compartidos abiertos en el equipo local o remoto                        |
| `Get-NetSession`         | Devuelve información de sesiones en el equipo local o remoto                                 |
| `Test-AdminAccess`       | Comprueba si el usuario actual tiene acceso administrativo al equipo local o remoto          |

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

##### Administradores locales

![[AD_BloodHound_exe_2.png | 800]]

Esto es solo una muestra de las consultas útiles que podemos ejecutar. A medida que avancemos en este módulo, verás muchas más que pueden ayudar a descubrir otras debilidades en el dominio. Para un estudio más profundo de BloodHound, consulta el módulo Active Directory Bloodhound. Tómate tu tiempo para probar cada una de las consultas en la pestaña Analysis y familiarizarte con la herramienta. También merece la pena experimentar con consultas Cypher personalizadas pegándolas en el cuadro Raw Query situado en la parte inferior de la pantalla.

Ten en cuenta que, a lo largo de la auditoría, debemos documentar cada archivo que transfiramos hacia y desde los hosts del dominio y la ubicación en disco donde se almacenó. Esto es buena práctica por si necesitamos justificar nuestras acciones ante el cliente. Además, según el alcance del compromiso, conviene cubrir bien nuestras huellas y limpiar todo lo que hayamos dejado en el entorno al finalizar la auditoría.



