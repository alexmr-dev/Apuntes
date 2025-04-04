> Los operadores de búsqueda son como los códigos secretos de los motores de búsqueda. Estos comandos y modificadores especiales desbloquean un nuevo nivel de precisión y control, permitiéndote encontrar tipos específicos de información dentro de la vastedad de la web indexada.

Aunque la sintaxis exacta puede variar ligeramente entre motores de búsqueda, los principios fundamentales permanecen consistentes. Vamos a profundizar en algunos operadores de búsqueda esenciales y avanzados:

| Operador | Descripción del Operador | Ejemplo | Descripción del Ejemplo |
|----------|--------------------------|---------|-------------------------|
| site:    | Limita los resultados a un sitio web o dominio específico. | site:example.com | Encuentra todas las páginas accesibles públicamente en example.com. |
| inurl:   | Busca páginas con un término específico en la URL. | inurl:login | Busca páginas de inicio de sesión en cualquier sitio web. |
| filetype:| Busca archivos de un tipo específico. | filetype:pdf | Encuentra documentos PDF descargables. |
| intitle: | Busca páginas con un término específico en el título. | intitle:"confidential report" | Busca documentos titulados "confidential report" o variaciones similares. |
| intext: o inbody: | Busca un término dentro del texto del cuerpo de las páginas. | intext:"password reset" | Identifica páginas web que contengan el término “password reset”. |
| cache:   | Muestra la versión almacenada en caché de una página web (si está disponible). | cache:example.com | Muestra la versión en caché de example.com para ver su contenido anterior. |
| link:    | Busca páginas que enlazan a una página web específica. | link:example.com | Identifica sitios web que enlazan a example.com. |
| related: | Busca sitios web relacionados con una página web específica. | related:example.com | Descubre sitios web similares a example.com. |
| info:    | Proporciona un resumen de información sobre una página web. | info:example.com | Obtén detalles básicos sobre example.com, como su título y descripción. |
| define:  | Proporciona definiciones de una palabra o frase. | define:phishing | Obtén una definición de "phishing" desde diversas fuentes. |
| numrange:| Busca números dentro de un rango específico. | site:example.com numrange:1000-2000 | Busca páginas en example.com que contengan números entre 1000 y 2000. |
| allintext: | Busca páginas que contengan todas las palabras especificadas en el texto del cuerpo. | allintext:admin password reset | Busca páginas que contengan tanto "admin" como "password reset" en el texto del cuerpo. |
| allinurl: | Busca páginas que contengan todas las palabras especificadas en la URL. | allinurl:admin panel | Busca páginas con "admin" y "panel" en la URL. |
| allintitle: | Busca páginas que contengan todas las palabras especificadas en el título. | allintitle:confidential report 2023 | Busca páginas con "confidential", "report" y "2023" en el título. |
| AND      | Limita los resultados exigiendo que todos los términos estén presentes. | site:example.com AND (inurl:admin OR inurl:login) | Busca páginas de admin o login específicamente en example.com. |
| OR       | Amplía los resultados incluyendo páginas que contengan cualquiera de los términos. | "linux" OR "ubuntu" OR "debian" | Busca páginas web que mencionen Linux, Ubuntu o Debian. |
| NOT      | Excluye los resultados que contengan el término especificado. | site:bank.com NOT inurl:login | Busca páginas en bank.com excluyendo las páginas de inicio de sesión. |
| * (comodín) | Representa cualquier carácter o palabra. | site:socialnetwork.com filetype:pdf user* manual | Busca manuales de usuario (guía de usuario, manual de usuario) en formato PDF en socialnetwork.com. |
| .. (rango numérico) | Busca resultados dentro de un rango numérico específico. | site:ecommerce.com "price" 100..500 | Busca productos con precios entre 100 y 500 en un sitio web de comercio electrónico. |
| " " (comillas) | Busca frases exactas. | "information security policy" | Busca documentos que mencionen exactamente la frase "information security policy". |
| - (signo menos) | Excluye términos de los resultados de búsqueda. | site:news.com -inurl:sports | Busca artículos de noticias en news.com excluyendo contenido relacionado con deportes. |
### Reconocimiento web

Estos marcos de trabajo tienen como objetivo proporcionar un conjunto completo de herramientas para la reconocibilidad web:

#### FinalRecon

Una herramienta de reconocimiento basada en Python que ofrece una variedad de módulos para diferentes tareas, como la verificación de certificados SSL, recopilación de información Whois, análisis de cabeceras y rastreo. Su estructura modular permite una fácil personalización para necesidades específicas.

inalRecon ofrece una gran cantidad de información de reconocimiento:

**Información de la Cabecera**: Revela detalles del servidor, tecnologías utilizadas y posibles malas configuraciones de seguridad.  
**Búsqueda Whois**: Descubre detalles del registro de dominio, incluyendo información del registrante y datos de contacto.  
**Información del Certificado SSL**: Examina la validez del certificado SSL/TLS, el emisor y otros detalles relevantes.  
**Rastreo**:

- HTML, CSS, JavaScript: Extrae enlaces, recursos y posibles vulnerabilidades de estos archivos.
- Enlaces Internos/Externos: Mapea la estructura del sitio web e identifica conexiones con otros dominios.
- Imágenes, robots.txt, sitemap.xml: Recopila información sobre rutas de rastreo permitidas/prohibidas y la estructura del sitio web.
- Enlaces en JavaScript, Wayback Machine: Descubre enlaces ocultos y datos históricos del sitio web.

**Enumeración DNS**: Consulta más de 40 tipos de registros DNS, incluyendo registros DMARC para la evaluación de seguridad del correo electrónico.

**Enumeración de Subdominios**: Utiliza múltiples fuentes de datos (crt.sh, AnubisDB, ThreatMiner, CertSpotter, API de Facebook, API de VirusTotal, API de Shodan, API de BeVigil) para descubrir subdominios.

**Enumeración de Directorios**: Soporta listas de palabras personalizadas y extensiones de archivos para descubrir directorios y archivos ocultos.

**Wayback Machine**: Recupera URLs de los últimos cinco años para analizar cambios en el sitio web y posibles vulnerabilidades.

```shell-session
amr251@htb[/htb]$ git clone https://github.com/thewhiteh4t/FinalRecon.git
amr251@htb[/htb]$ cd FinalRecon
amr251@htb[/htb]$ pip3 install -r requirements.txt
amr251@htb[/htb]$ chmod +x ./finalrecon.py
```

| Opción            | Argumento        | Descripción                                              |
|-------------------|------------------|----------------------------------------------------------|
| -h, --help        |                  | Muestra el mensaje de ayuda y sale.                      |
| --url             | URL              | Especifica la URL del objetivo.                          |
| --headers         |                  | Recupera la información de la cabecera para la URL del objetivo. |
| --sslinfo         |                  | Obtiene la información del certificado SSL para la URL del objetivo. |
| --whois           |                  | Realiza una búsqueda Whois para el dominio objetivo.     |
| --crawl           |                  | Rastrea el sitio web del objetivo.                       |
| --dns             |                  | Realiza una enumeración DNS en el dominio objetivo.      |
| --sub             |                  | Enumera los subdominios para el dominio objetivo.        |
| --dir             |                  | Busca directorios en el sitio web del objetivo.          |
| --wayback         |                  | Recupera URLs de Wayback para el objetivo.               |
| --ps              |                  | Realiza un escaneo rápido de puertos en el objetivo.     |
| --full            |                  | Realiza un escaneo completo de reconocimiento en el objetivo. |
#### Recon-ng

Un potente marco escrito en Python que ofrece una estructura modular con varios módulos para diferentes tareas de reconocimiento. Puede realizar enumeración DNS, descubrimiento de subdominios, escaneo de puertos, rastreo web e incluso explotar vulnerabilidades conocidas.

#### theHarvester

Diseñado específicamente para recopilar direcciones de correo electrónico, subdominios, hosts, nombres de empleados, puertos abiertos y banners de diversas fuentes públicas como motores de búsqueda, servidores de claves PGP y la base de datos SHODAN. Es una herramienta de línea de comandos escrita en Python.

#### SpiderFoot

Una herramienta de automatización de inteligencia de código abierto que se integra con diversas fuentes de datos para recopilar información sobre un objetivo, incluidos direcciones IP, nombres de dominio, direcciones de correo electrónico y perfiles en redes sociales. Puede realizar búsquedas DNS, rastreo web, escaneo de puertos y más.

#### OSINT Framework

Una colección de diversas herramientas y recursos para la recopilación de inteligencia de código abierto. Cubre una amplia gama de fuentes de información, incluidos medios sociales, motores de búsqueda, registros públicos y más.

#### ReconSpider

```bash
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
```

Luego, simplemente lo descomprimimos y ejecutamos el script con Python. Se genera un reporte JSON que podemos visualizar cómodamente con `jq`.

```shell-session
python3 ReconSpider.py <URL>
cat results.json | jq
```

