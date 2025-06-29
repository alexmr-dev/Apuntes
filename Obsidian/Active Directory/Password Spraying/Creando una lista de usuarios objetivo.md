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

Para trabajar con sesiones SMB NULL o enlaces LDAP anónimos puedes apoyarte en herramientas como `enum4linux`, `rpcclient` o `CrackMapExec`. En cualquiera de los casos será necesario limpiar la salida para quedarte solo con los nombres de usuario, preferiblemente con un nombre por línea, para facilitar ataques posteriores. Esto lo podemos realizar con la flag `-U` con `enum4linux`.

```shell-session
amr251@htb[/htb]$ enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

administrator
guest
krbtgt
lab_adm
htb-student

<SNIP>
```

Como ya sabemos, podemos usar `enumdomusers` si ganamos una sesión con `rpcclient -U "" -N <TARGET>`. Además, con `crackmapexec smb <TARGET> --users` podemos hacer lo mismo. Esta herramienta resulta útil porque también muestra el **badpwdcount**, es decir, el número de intentos fallidos de inicio de sesión. Gracias a esto, podemos eliminar de nuestra lista aquellos usuarios que estén cerca del umbral de bloqueo. También muestra el **baddpwdtime**, que indica la fecha y hora del último intento fallido de contraseña. Esto nos permite saber cuán cerca está una cuenta de que se le reinicie el contador de intentos fallidos.

En entornos con múltiples controladores de dominio, estos valores se mantienen de forma separada en cada uno. Para obtener un recuento preciso del número total de intentos fallidos de una cuenta, habría que consultar cada DC individualmente y sumar los valores, o bien consultar directamente al controlador que tiene el rol **PDC Emulator**.

### Recopilando usuarios con LDAP anónimo

Cuando se permite la **vinculación anónima por LDAP**, podemos aprovecharlo para obtener una lista de usuarios del dominio. Hay varias herramientas que permiten hacer esto, como `windapsearch` o `ldapsearch`. Si optamos por `ldapsearch`, necesitaremos especificar un filtro de búsqueda LDAP válido. Estos filtros determinan qué tipo de objetos queremos recuperar del Directorio Activo, y se explican en detalle en el módulo dedicado a LDAP en Active Directory.

##### Usando ldapsearch

```shell-session
[!bash!]$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "

guest
ACADEMY-EA-DC01$
```

Herramientas como `windapsearch` hacen más fácil esto (aunque deberíamos entender cómo crear nuestros propios filtros de búsqueda LDAP). Aquí podemos especificar acceso anónimo con un usuario en blanco (flag `-u`) y la flag `-U` para decirle a la herramienta que obtenga solo usuarios

##### Usando windapsearch

```shell-session
[!bash!]$ ./windapsearch.py --dc-ip 172.16.5.5 -u "" -U

[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 172.16.5.5
[+] Getting defaultNamingContext from Root DSE
[+]	Found: DC=INLANEFREIGHT,DC=LOCAL
[+] Attempting bind
[+]	...success! Binded as: 
[+]	 None

[+] Enumerating all AD users
[+]	Found 2906 users: 
```

### Enumerando usuarios con Kerbrute

Si no tenemos ningún tipo de acceso en la red interna, podemos utilizar **Kerbrute** tanto para enumerar cuentas válidas de Active Directory como para hacer **password spraying**. Esta herramienta aprovecha la **preautenticación de Kerberos**, que es más rápida y sigilosa que otros métodos, ya que **no genera eventos como el ID 4625** (fallos de inicio de sesión), lo que la hace menos detectable.

Kerbrute envía peticiones TGT al controlador de dominio sin preautenticación. Si el KDC responde con **PRINCIPAL UNKNOWN**, el usuario no existe. Si solicita preautenticación, significa que el usuario es válido. Esta técnica permite enumerar usuarios sin bloquear cuentas ni generar alertas. Sin embargo, **al pasar al password spraying**, los intentos fallidos sí se contabilizan y pueden bloquear cuentas, por lo que hay que actuar con precaución.

Se puede probar con listas como `jsmith.txt`, que contiene más de 48.000 usuarios en formato `flast`. El repositorio _statistically-likely-usernames_ de GitHub es una buena fuente para este tipo de ataques.

##### Enumeración de usuarios con kerbrute

```shell-session
[!bash!]$  kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 
```

Con Kerbrute, hemos comprobado más de 48.000 nombres de usuario en solo 12 segundos, descubriendo más de 50 válidos. Aunque este método no genera eventos de fallo de inicio de sesión, sí provoca el **evento 4768** ("se solicitó un ticket de autenticación Kerberos") si el registro de eventos de Kerberos está habilitado por directiva de grupo. Los defensores pueden configurar su SIEM para detectar un pico de estos eventos, lo que podría delatar la actividad.

Si no conseguimos generar una lista de usuarios válidos con técnicas internas, siempre podemos recurrir a **OSINT**, buscando correos corporativos o usando herramientas como **linkedin2username**, que generan nombres de usuario a partir de perfiles de empleados en LinkedIn. Esto puede ayudarnos a construir diccionarios para intentos posteriores.

### Enumeración credencializada para construir nuestra lista de usuarios

Con credenciales válidas, podemos emplear cualquiera de las herramientas mencionadas anteriormente para generar una lista de usuarios. Una de las formas más rápidas y sencillas de hacerlo es utilizando **CrackMapExec**, que permite enumerar directamente los usuarios del dominio desde un sistema Linux autenticado en la red interna. Esto facilita la recopilación de objetivos potenciales para ataques como el password spraying o la escalada de privilegios.

##### Usando crackmapexec con credenciales válidas

```shell-session
[!bash!]$ sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users

[sudo] password for htb-student: 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\htb-student:Academy_student_AD! 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Enumerated domain user(s)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\administrator                  badpwdcount: 1 baddpwdtime: 2022-02-23 21:43:35.059620
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\guest                          badpwdcount: 0 baddpwdtime: 1600-12-31 19:03:58
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\lab_adm                        badpwdcount: 0 baddpwdtime: 2021-12-21 14:10:56.859064
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\krbtgt                         badpwdcount: 0 baddpwdtime: 1600-12-31 19:03:58
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\htb-student                    badpwdcount: 0 baddpwdtime: 2022-02-22 14:48:26.653366
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\avazquez                       badpwdcount: 20 baddpwdtime: 2022-02-17 22:59:22.684613
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\pfalcon                        badpwdcount: 0 baddpwdtime: 1600-12-31 19:03:58

<SNIP>
```


























































