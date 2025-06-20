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