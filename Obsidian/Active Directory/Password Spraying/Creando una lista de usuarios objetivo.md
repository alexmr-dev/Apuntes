Para hacer un ataque de **password spraying** necesitamos una lista de usuarios válidos del dominio. Podemos obtenerla mediante:

- **SMB NULL session** o **LDAP anonymous bind** para enumerar usuarios.    
- Herramientas como **Kerbrute** o **linkedin2username** con diccionarios comunes.    
- Credenciales obtenidas por otras vías (por ejemplo, con **Responder** o un spray anterior).    

Es **clave conocer la política de contraseñas**: longitud mínima, complejidad, umbral de bloqueo y temporizador. Esto nos permite ajustar el ataque para evitar bloquear cuentas. Si no tenemos la política, podemos:

- Preguntarla al cliente.    
- Hacer intentos puntuales y muy espaciados.    

Siempre debemos **registrar**:

- Usuarios atacados    
- Controlador de dominio    
- Hora y fecha    
- Contraseñas usadas    

Esto protege al auditor y evita errores o duplicidades. 

### SMB Null Session - Obtener listado de usuarios

Si estamos dentro de una máquina en la red interna pero no contamos con credenciales válidas del dominio, podemos intentar obtener una lista de usuarios recurriendo a sesiones SMB NULL o a enlaces LDAP anónimos hacia los controladores de dominio. Estas configuraciones, si están mal configuradas, permiten listar todos los usuarios del dominio y consultar la política de contraseñas sin autenticación previa.

Otra opción, si ya tienes acceso como usuario **SYSTEM** en algún host del dominio, es aprovechar que el sistema puede actuar como objeto de equipo y consultar directamente Active Directory. Si no dispones de ninguno de estos vectores, puedes generar una lista estimada de usuarios a partir de fuentes externas como LinkedIn o mediante técnicas de recolección de correos corporativos.

Para trabajar con sesiones SMB NULL o enlaces LDAP anónimos puedes apoyarte en herramientas como `enum4linux`, `rpcclient` o `CrackMapExec`. En cualquiera de los casos será necesario limpiar la salida para quedarte solo con los nombres de usuario, preferiblemente con un nombre por línea, para facilitar ataques posteriores.

