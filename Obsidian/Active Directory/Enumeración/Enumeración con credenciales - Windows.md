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

| Comando               | Descripción                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| `Get-DomainGPO`       | Devuelve todas las GPO o GPO específicas en AD                              |
| `Get-DomainPolicy`    | Devuelve la política predeterminada de dominio o la política del controlador |

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







