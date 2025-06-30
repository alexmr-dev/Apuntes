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

PathConditions      : {%PROGRAMFILES%\*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : 921cc481-6e17-4653-8f75-050b80acca20
Name                : (Default Rule) All files located in the Program Files folder
Description         : Allows members of the Everyone group to run applications that are located in the Program Files folder.
UserOrGroupSid      : S-1-1-0
Action              : Allow

PathConditions      : {%WINDIR%\*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : a61c8b2c-a319-4cd0-9690-d2177cad7b51
Name                : (Default Rule) All files located in the Windows folder
Description         : Allows members of the Everyone group to run applications that are located in the Windows folder.
UserOrGroupSid      : S-1-1-0
Action              : Allow

PathConditions      : {*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : fd686d83-a829-4351-8ff4-27c7de5755d2
Name                : (Default Rule) All files
Description         : Allows members of the local Administrators group to run all applications.
UserOrGroupSid      : S-1-5-32-544
Action              : Allow
```

---
### PowerShell Contrained Language

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