Antes de comenzar cualquier prueba de penetración, **realizar una fase de reconocimiento externo** puede ser muy beneficioso. Esta fase cumple varias funciones clave:

- **Validar la información** proporcionada por el cliente en el documento de alcance.    
- **Asegurarse de actuar dentro del alcance correcto**, especialmente si se trabaja de forma remota.    
- **Detectar información pública que pueda impactar** en la auditoría, como credenciales filtradas.    

La idea es clara: entender bien el terreno antes de actuar, para garantizar una prueba lo más completa y precisa posible. Esto incluye **identificar filtraciones de información** o datos comprometidos ya disponibles públicamente. Algunos ejemplos concretos:

- Obtener el **formato de los nombres de usuario** a través de la web corporativa o redes sociales.    
- Buscar **repositorios de GitHub** del cliente en busca de credenciales o configuraciones sensibles subidas por error.    
- Analizar **documentos públicos** que puedan contener referencias a portales internos o servicios accesibles desde fuera.    

Este reconocimiento inicial puede parecer trivial, pero muchas veces es la **puerta de entrada real** al entorno interno.

### ¿Qué estamos buscando?

Cuando efectuamos un reconocimiento externo, hay varios items clave que deberíamos buscar. Esta información puede no estar siempre accesible de forma pública, pero sería prudente comprobar qué hay ahí fuera. Si nos atascamos durante un pentest, mirar atrás a lo que podría ser obtenido a través de reconocimiento pasivo puede darnos esa información para continuar, como filtraciones de contraseñas que podrían ser utilizadas para accededer a un VPN o algún otro servicio expuesto. 

##### 📡 Puntos clave de reconocimiento externo

| Punto de datos             | Descripción                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Espacio IP**             | ASN válidos asociados al objetivo, rangos de IP utilizados por la infraestructura pública, presencia en la nube y proveedores de hosting, registros DNS, etc.                                                                                                                                                      |
| **Información de dominio** | Basada en datos IP, DNS y registros del sitio. ¿Quién administra el dominio? ¿Existen subdominios vinculados al objetivo? ¿Hay servicios accesibles públicamente (servidores de correo, DNS, portales web, VPN, etc.)? ¿Podemos identificar medidas defensivas como SIEM, antivirus, IPS/IDS, etc.?                |
| **Formato de esquemas**    | ¿Podemos descubrir cuentas de correo electrónico, nombres de usuario de AD o políticas de contraseñas? Cualquier dato que nos permita generar una lista válida de usuarios para realizar ataques como password spraying, credential stuffing o fuerza bruta.                                                       |
| **Divulgaciones de datos** | Archivos públicos accesibles (.pdf, .ppt, .docx, .xlsx, etc.) que contengan información relevante: listados de intranet, metadatos de usuarios, shares, software o hardware crítico (ejemplo: credenciales subidas a un GitHub público, formato de nombre de usuario encontrado en los metadatos de un PDF, etc.). |
| **Datos de brechas**       | Cualquier usuario, contraseña u otra información crítica filtrada públicamente que pueda ser usada por un atacante para obtener acceso inicial.                                                                                                                                                                    |

### ¿Dónde estamos buscando?

Nuestra lista de información puede ser construida de muchas formas distintas. Hay muchas webs y herramientas que pueden darnos un poco o toda la información de la tabla superior que podríamos usar para obtener información vital en nuestra auditoría. La siguiente tabla lista recursos potenciales y ejemplos que pueden ser utilizados:
##### 🔍 Fuentes de información para reconocimiento externo

| Recurso                         | Ejemplos |
|----------------------------------|----------|
| **Registros ASN / IP**          | IANA, ARIN (para búsquedas en América), RIPE (para Europa), BGP Toolkit |
| **Registradores de dominio y DNS** | Domaintools, PTRArchive, ICANN, peticiones manuales de registros DNS al dominio o a servidores conocidos como 8.8.8.8 |
| **Redes sociales**              | Búsquedas en LinkedIn, Twitter, Facebook, redes sociales relevantes de la región, artículos de prensa, y cualquier información útil sobre la organización |
| **Webs corporativas públicas**  | Las webs corporativas suelen incluir información valiosa. Secciones como “Quiénes somos” o “Contacto”, documentos incrustados o noticias pueden contener datos útiles |
| **Repositorios y almacenamiento en la nube / desarrollo** | GitHub, buckets S3 de AWS, contenedores Azure Blob, Google Dorks para buscar archivos expuestos públicamente |
| **Fuentes de datos comprometidos (brechas)** | HaveIBeenPwned para ver si hay correos corporativos en brechas públicas, Dehashed para buscar correos con contraseñas en texto claro o hashes que puedan crackearse offline. Estas credenciales pueden probarse en portales expuestos (Citrix, RDS, OWA, 0365, VPN, VMware Horizon, aplicaciones personalizadas, etc.) que usen autenticación AD |
El **BGP Toolkit de Hurricane Electric** es muy útil para identificar los **bloques de direcciones IP** asignados a una organización y su **ASN** (Sistema Autónomo). Basta con introducir un dominio o IP para obtener datos relevantes.

- **Grandes empresas** suelen tener su **propio ASN**, ya que alojan su infraestructura.    
- **Empresas pequeñas o nuevas** suelen alojar sus servicios en proveedores como **Cloudflare, AWS, Azure o Google Cloud**.    

Esto es crítico porque si la infraestructura **no es propia**, puede estar **fuera del alcance autorizado**. Atacar sin querer a un tercero por compartir infraestructura (por ejemplo, un servidor en la nube) **viola el acuerdo con el cliente**.

> **Siempre hay que validar si los sistemas están autogestionados o son de terceros**, y esto debe quedar **claramente definido en el documento de alcance**.

En algunos casos, se necesita **permiso escrito del proveedor**, como:
- **AWS**: permite pentesting sobre ciertos servicios sin aprobación previa.    
- **Oracle**: exige notificación previa mediante su formulario específico.    

Este tipo de gestiones debe tramitarlas tu empresa (equipo legal, contratos, etc.). Si hay duda, **escala el asunto antes de lanzar cualquier ataque externo**. Es tu responsabilidad tener **permiso explícito** sobre cada host a auditar. Detenerse a confirmar el alcance **siempre es mejor que excederse**.

### 🧍‍♂️ Recolección de usuarios (Username Harvesting)

Se puede utilizar una herramienta como **linkedin2username** para extraer nombres desde la página de LinkedIn de la empresa y generar distintos formatos de nombre de usuario (ej: `flast`, `first.last`, `f.last`, etc.).  
Esto permite construir una lista de posibles cuentas a usar en ataques de **password spraying**.

### 🔐 Búsqueda de credenciales (Credential Hunting)

**Dehashed** es una herramienta muy útil para buscar **credenciales en texto claro** o **hashes de contraseñas** en bases de datos filtradas.  
Se puede consultar directamente desde su web o mediante scripts que acceden a su **API**.

Aunque muchas veces se encuentran contraseñas antiguas o cuentas ya inactivas, también pueden aparecer credenciales **válidas para portales externos que usen autenticación AD**, o incluso acceso interno.

Además, sirve para **reforzar o enriquecer** las listas de usuarios para ataques posteriores de spraying o fuerza bruta.

```shell-session
sudo python3 dehashed.py -q inlanefreight.local -p
```

> *El script de Dehashed puede encontrarse [aquí](https://github.com/mrb3n813/Pentest-stuff/blob/master/dehashed.py)*