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

os atacantes aprovechan las entradas ACE para ampliar su acceso o establecer persistencia. Esto es muy útil para nosotros como pentesters, ya que muchas organizaciones desconocen qué ACEs se han aplicado a cada objeto o el impacto que pueden tener si se configuran incorrectamente. Estas configuraciones no pueden detectarse con herramientas de escaneo de vulnerabilidades y a menudo permanecen sin revisarse durante años, especialmente en entornos grandes y complejos. En una auditoría en la que el cliente ya ha corregido los “low hanging fruit” de AD, el abuso de ACLs puede ser una vía excelente para moverse lateral o verticalmente e incluso lograr la compromi­sión total del dominio. Algunos ejemplos de permisos de seguridad sobre objetos de Active Directory son:

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