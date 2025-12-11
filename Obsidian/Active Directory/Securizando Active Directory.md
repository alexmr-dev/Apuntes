Veamos medidas de hardening para detener las TTPs comunes utilizadas en este módulo. Como pentesters, nuestro objetivo es mejorar la postura de seguridad del cliente. Debemos entender tácticas defensivas comunes y cómo afectan las redes evaluadas. Estos pasos básicos de hardening benefician más a una organización que adquirir nuevas herramientas EDR o SIEM, que solo ayudan si existe una postura de seguridad base con logging habilitado y documentación/tracking adecuado de hosts en la red.

### Paso 1: Documentar y auditar

Un hardening adecuado de AD puede contener atacantes y prevenir movimiento lateral, escalada de privilegios y acceso a datos/recursos sensibles. Un paso esencial es comprender todo lo presente en el entorno AD. Se debe realizar una auditoría anual (o cada pocos meses) de lo siguiente para mantener registros actualizados:

##### Cosas que documentar

- Convenciones de nomenclatura de OUs, equipos, usuarios, grupos
- Configuraciones de DNS, red y DHCP
- Comprensión detallada de todas las GPOs y los objetos a los que se aplican
- Asignación de roles FSMO
- Inventario completo y actualizado de aplicaciones
- Lista de todos los hosts empresariales y su ubicación
- Cualquier relación de trust con otros dominios o entidades externas
- Usuarios con permisos elevados

### Personas, procesos y tecnología

El hardening de AD se puede dividir en las categorías Personas, Procesos y Tecnología. Estas medidas abarcan los aspectos de hardware, software y humanos de cualquier red.
##### Personas

Los usuarios son el eslabón más débil incluso en entornos endurecidos. Aplicar mejores prácticas para usuarios estándar y administradores previene "victorias fáciles". Medidas clave:

- Política de contraseñas fuerte con filtro que prohíba palabras comunes. Usar gestor de contraseñas empresarial si es posible.
- Rotar contraseñas periódicamente para cuentas de servicio.
- No permitir acceso de administrador local en workstations salvo necesidad específica.
- Deshabilitar cuenta admin local `RID-500` por defecto y crear nueva cuenta admin sujeta a rotación LAPS.
- Implementar niveles separados de administración para usuarios administrativos.
- Limpiar grupos privilegiados. Restringir membresía en grupos altamente privilegiados solo a usuarios que lo requieran.
- Colocar cuentas en grupo `Protected Users` cuando sea apropiado.
- Deshabilitar delegación Kerberos para cuentas administrativas.

##### Grupo *Protected Users*

Este grupo apareció por primera vez en Windows Server 2012 R2. Este grupo puede usarse para restringir lo que los miembros de este grupo privilegiado pueden hacer en un dominio. Añadir usuarios a Protected Users previene que las credenciales de usuario sean abusadas si se dejan en memoria en un host.

##### Visualizando el Grupo Protected Users con Get-ADGroup

```powershell-session
PS C:\Users\htb-student> Get-ADGroup -Identity "Protected Users" -Properties Name,Description,Members


Description       : Members of this group are afforded additional protections against authentication security threats.
                    See http://go.microsoft.com/fwlink/?LinkId=298939 for more information.
DistinguishedName : CN=Protected Users,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
GroupCategory     : Security
GroupScope        : Global
Members           : {CN=sqlprod,OU=Service Accounts,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL, CN=sqldev,OU=Service
                    Accounts,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL}
Name              : Protected Users
ObjectClass       : group
ObjectGUID        : e4e19353-d08f-4790-95bc-c544a38cd534
SamAccountName    : Protected Users
SID               : S-1-5-21-2974783224-3764228556-2640795941-525
```

El grupo proporciona las siguientes protecciones en Domain Controller y dispositivos:

- Los miembros no pueden ser delegados con delegación restringida o no restringida.
- CredSSP no almacenará en caché credenciales en texto plano en memoria, incluso si está configurado en Group Policy.
- Windows Digest no almacenará en caché la contraseña en texto plano del usuario, incluso si está habilitado.
- Los miembros no pueden autenticarse usando autenticación NTLM ni usar claves DES o RC4.
- Después de adquirir un TGT, las claves a largo plazo o credenciales en texto plano del usuario no se almacenan en caché.
- Los miembros no pueden renovar un TGT más allá del TTL original de 4 horas.

> El grupo Protected Users puede causar problemas imprevistos con la autenticación, lo que puede resultar fácilmente en bloqueos de cuentas. Una organización nunca debe colocar a todos los usuarios privilegiados en este grupo sin realizar pruebas escalonadas.

Junto con garantizar que los usuarios no puedan causarse daño a sí mismos, debemos considerar nuestras políticas y procedimientos para el acceso y control del dominio.

### Procesos

Mantener y aplicar políticas que impacten significativamente la postura de seguridad organizacional es necesario. Sin políticas definidas, es imposible responsabilizar a los empleados y difícil responder a incidentes sin procedimientos definidos como un plan de recuperación ante desastres. Aspectos clave:

- Políticas adecuadas para gestión de activos AD (auditorías, etiquetas de activos, inventarios periódicos).
- Políticas de control de acceso (aprovisionamiento/desaprovisionamiento de cuentas), mecanismos de autenticación multifactor.
- Procesos para aprovisionamiento y desmantelamiento de hosts (líneas base de hardening, imágenes gold).
- Políticas de limpieza AD: ¿Se eliminan o deshabilitan cuentas de ex-empleados? ¿Proceso para eliminar registros obsoletos? Desmantelamiento de sistemas operativos/servicios legacy.
- Calendario de auditorías de usuarios, grupos y hosts.

### Tecnologías

Revisa periódicamente AD en busca de configuraciones incorrectas legacy y amenazas emergentes. Al realizar cambios en AD, asegura que no se introducen configuraciones incorrectas comunes. Presta atención a vulnerabilidades introducidas por AD y herramientas/aplicaciones del entorno.

- Ejecuta herramientas como BloodHound, PingCastle y Grouper periódicamente para identificar configuraciones incorrectas de AD.
- Asegura que los administradores no almacenan contraseñas en el campo de descripción de cuentas AD.
- Revisa SYSVOL en busca de scripts que contengan contraseñas y datos sensibles.
- Evita usar cuentas de servicio "normales", utiliza Group Managed (gMSA) y Managed Service Accounts (MSA) donde sea posible para mitigar el riesgo de Kerberoasting.
- Deshabilita Unconstrained Delegation donde sea posible.
- Previene acceso directo a Domain Controllers mediante jump hosts endurecidos.
- Considera establecer el atributo `ms-DS-MachineAccountQuota` en `0`, lo que impide que usuarios añadan cuentas de máquina y previene ataques como noPac y Resource-Based Constrained Delegation (RBCD).
- Deshabilita el servicio print spooler donde sea posible para prevenir varios ataques.
- Deshabilita autenticación NTLM para Domain Controllers si es posible.
- Usa Extended Protection for Authentication junto con habilitar Require SSL only para permitir conexiones HTTPS para Certificate Authority Web Enrollment y Certificate Enrollment Web Service.
- Habilita SMB signing y LDAP signing.
- Toma medidas para prevenir enumeración con herramientas como BloodHound.
- Idealmente, realiza pentests trimestrales/evaluaciones de seguridad AD, pero si existen restricciones presupuestarias, deben realizarse anualmente como mínimo.
- Prueba backups para validez y revisa/practica planes de recuperación ante desastres.
- Habilita restricción de acceso anónimo y previene enumeración null session estableciendo la clave de registro `RestrictNullSessAccess` en `1` para restringir acceso null session a usuarios no autenticados.

### Protecciones por sección

Como una perspectiva diferente, hemos desglosado las acciones significativas por sección y correlacionado controles basados en la TTP y una etiqueta MITRE. Cada etiqueta corresponde con una sección de la Enterprise ATT&CK Matrix que se encuentra aquí. Cualquier etiqueta marcada como `TA` corresponde a una táctica general, mientras que una etiqueta marcada como `T###` es una técnica encontrada en la matriz bajo tácticas.

| TTP                      | MITRE Tag | Descripción                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ------------------------ | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| External Reconnaissance  | T1589     | Esta porción de un ataque es extremadamente difícil de detectar y defender. Un atacante no tiene que interactuar directamente con tu entorno empresarial, por lo que es imposible saber cuándo está ocurriendo. Lo que se puede hacer es monitorear y controlar los datos que liberas públicamente al mundo. Las ofertas de trabajo, documentos (y los metadatos adjuntos), y otras fuentes de información abiertas como registros BGP y DNS revelan algo sobre tu empresa. Tener cuidado de limpiar los documentos antes de su publicación puede asegurar que un atacante no pueda obtener el contexto de nombres de usuario de ellos, por ejemplo. Lo mismo se puede decir de no proporcionar información detallada sobre herramientas y equipos utilizados en tus redes a través de ofertas de trabajo.                                                                                                                                                                                                                                                            |
| Internal Reconnaissance  | T1595     | Para el reconocimiento de nuestras redes internas, tenemos más opciones. Esto a menudo se considera una fase activa y, como tal, generará tráfico de red que podemos monitorear y colocar defensas basadas en lo que vemos. Monitorear el tráfico de red en busca de ráfagas sospechosas de paquetes de gran volumen desde una fuente o varias fuentes puede ser indicativo de escaneo. Un Firewall o Sistema de Detección de Intrusiones de Red (NIDS) configurado correctamente detectará estas tendencias rápidamente y alertará sobre el tráfico. Dependiendo de la herramienta o dispositivo, incluso puede ser capaz de agregar una regla bloqueando el tráfico de dichos hosts de manera proactiva. La utilización de monitoreo de red junto con un SIEM puede ser crucial para detectar el reconocimiento. Ajustar adecuadamente la configuración del Windows Firewall o tu EDR de elección para que no responda al tráfico ICMP, entre otros tipos de tráfico, puede ayudar a negar a un atacante cualquier información que pueda obtener de los resultados. |
| Poisoning                | T1557     | Utilizar opciones de seguridad como SMB message signing y cifrar el tráfico con un mecanismo de cifrado fuerte ayudará mucho a detener ataques de poisoning y man-in-the-middle. SMB signing utiliza códigos de autenticación hasheados y verifica la identidad del remitente y destinatario del paquete. Estas acciones romperán los ataques de relay ya que el atacante solo está suplantando tráfico.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Password Spraying        | T1110/003 | Esta acción es quizás la más fácil de defender y detectar. Un simple logging y monitoreo puede alertarte de ataques de password spraying en tu red. Vigilar tus logs en busca de múltiples intentos de login observando los Event IDs 4624 y 4648 para cadenas de intentos inválidos puede alertarte de password spraying o intentos de fuerza bruta para acceder al host. Tener políticas de contraseñas fuertes, una política de bloqueo de cuentas configurada, y utilizar autenticación de dos factores o multifactor puede ayudar a prevenir el éxito de un ataque de password spray. Para una mirada más profunda a las configuraciones de políticas recomendadas, consulta este artículo y la documentación de NIST.                                                                                                                                                                                                                                                                                                                                           |
| Credentialed Enumeration | TA0006    | No hay una defensa real que puedas implementar para detener este método de ataque. Una vez que un atacante tiene credenciales válidas, efectivamente puede realizar cualquier acción que el usuario esté autorizado a hacer. Sin embargo, un defensor vigilante puede detectar y detener esto. Monitorear actividad inusual como emitir comandos desde la CLI cuando un usuario no debería tener necesidad de utilizarla. Múltiples solicitudes RDP enviadas de host a host dentro de la red o movimiento de archivos desde varios hosts pueden ayudar a alertar a un defensor. Si un atacante logra adquirir privilegios administrativos, esto puede volverse mucho más difícil, pero hay herramientas heurísticas de red que se pueden implementar para analizar constantemente la red en busca de actividad anómala. La segmentación de red puede ayudar mucho aquí.                                                                                                                                                                                               |
| LOTL                     | N/A       | Puede ser difícil detectar a un atacante mientras está utilizando los recursos integrados en los sistemas operativos host. Aquí es donde tener una línea base del tráfico de red y comportamiento del usuario resulta útil. Si tus defensores entienden cómo se ve la actividad de red regular del día a día, tienes la oportunidad de detectar lo anormal. Vigilar command shells y utilizar una política de Applocker configurada correctamente puede ayudar a prevenir el uso de aplicaciones y herramientas a las que los usuarios no deberían tener acceso o necesitar.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Kerberoasting            | T1558/003 | Kerberoasting como técnica de ataque está ampliamente documentada, y hay muchas formas de detectarla y defenderse contra ella. La forma número uno de protegerse contra Kerberoasting es utilizar un esquema de cifrado más fuerte que RC4 para los mecanismos de autenticación Kerberos. Aplicar políticas de contraseñas fuertes puede ayudar a prevenir que los ataques de Kerberoasting sean exitosos. Utilizar cuentas de servicio Group Managed probablemente sea la mejor defensa, ya que esto hace que Kerberoasting ya no sea posible. Auditar periódicamente los permisos de cuentas de tus usuarios en busca de membresía excesiva en grupos puede ser una forma efectiva de detectar problemas.                                                                                                                                                                                                                                                                                                                                                           |