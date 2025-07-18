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

