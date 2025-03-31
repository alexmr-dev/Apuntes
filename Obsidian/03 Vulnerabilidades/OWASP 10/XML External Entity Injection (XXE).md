---

---
----
- Tags: #XML #OWASP
----
## ¿En qué consiste?

> Un ataque XXE generalmente implica la inyección de una **entidad** XML maliciosa en una solicitud HTTP, que es procesada por el servidor y puede resultar en la exposición de información sensible. Ocurre cuando una aplicación analiza datos XML que contienen referencias a entidades externas maliciosas. Esto puede permitir a un atacante acceder a archivos sensibles, realizar solicitudes a servidores internos o ejecutar código de manera remota. Por ejemplo, un atacante podría inyectar una entidad XML que hace referencia a un archivo en el sistema del servidor y obtener información confidencial de ese archivo. 

## ¿Cómo funciona?

Los ataques XXE explotan la capacidad de los Document Type Definitions (DTDs) en XML para definir entidades. Un atacante puede inyectar una entidad externa maliciosa en un documento XML, que luego es procesada por la aplicación vulnerable. Al hacerlo, el atacante puede:

- Leer archivos locales en el servidor.
- Realizar solicitudes HTTP a sistemas internos (Server-Side Request Forgery - SSRF).
- Ejecutar comandos de forma remota, en ciertos entornos.

**Ejemplo de carga maliciosa**

```xml
<?xml version="1.0" encoding="ISO-8859-1"?> 
<!DOCTYPE foo [ 
	<!ELEMENT foo ANY > 
	<!ENTITY xxe SYSTEM "file:///etc/passwd" > 
]> 
<foo>&xxe;</foo>
```

En este ejemplo, la entidad `xxe` intenta leer el contenido del archivo `/etc/passwd` en un sistema Unix. [owasp.org](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_%28XXE%29_Processing)

## Impacto de las vulnerabilidades XXE

Las consecuencias de una vulnerabilidad XXE pueden ser severas e incluyen:

- **Divulgación de información sensible:** Acceso no autorizado a archivos confidenciales en el servidor.
- **Denegación de servicio (DoS):** Mediante la inclusión de entidades que consumen muchos recursos, como referencias a `/dev/random`.
- **SSRF (Server-Side Request Forgery):** Permite al atacante enviar solicitudes desde el servidor a otras máquinas, potencialmente eludiendo restricciones de firewall.
- **Ejecución remota de código:** En ciertos entornos, es posible ejecutar comandos en el servidor.

## Ejemplos de ataques XXE

1. **Lectura de archivos locales:** Un atacante puede intentar leer archivos sensibles en el servidor.

```xml
<?xml version="1.0" encoding="ISO-8859-1"?> 
<!DOCTYPE foo [ 
	<!ELEMENT foo ANY > 
	<!ENTITY xxe SYSTEM "file:///etc/shadow" > 
]> 
<foo>&xxe;</foo>
```

2. **SSRF para escaneo de puertos internos**: El atacante puede usar el servidor para escanear puertos internos

```xml
<?xml version="1.0" encoding="ISO-8859-1"?> 
<!DOCTYPE foo [ 
	<!ELEMENT foo ANY > 
	<!ENTITY xxe SYSTEM "http://localhost:8080/secret" > 
]> 
<foo>&xxe;</foo>
```

3. **Denegación de servicio**: Mediante la inclusión de una entidad que referencia un recurso interminable

```xml
<?xml version="1.0" encoding="ISO-8859-1"?> 
<!DOCTYPE foo [ 
	<!ELEMENT foo ANY > 
	<!ENTITY xxe SYSTEM "file:///dev/random" > 
]> 
<foo>&xxe;</foo>
```

## Prevención y mitigación

Para proteger las aplicaciones contra ataques XXE:

- **Deshabilitar la resolución de entidades externas:** Configure el analizador XML para que no procese DTDs ni entidades externas.
- **Validar y sanitizar entradas:** Asegúrese de que los datos XML de entrada sean seguros y no contengan DTDs maliciosas.
- **Actualizar bibliotecas y analizadores XML:** Utilice versiones actualizadas de bibliotecas que aborden vulnerabilidades XXE.
- **Implementar políticas de seguridad estrictas:** Restringir el acceso del servidor a recursos innecesarios y monitorear actividades sospechosas.

Para una guía detallada sobre la prevención de XXE, consulte la [Cheat Sheet de OWASP sobre Prevención de XXE](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html).

## Recursos adicionales

- **OWASP Top Ten 2017 - A4: XML External Entities (XXE):** [Enlace](https://owasp.org/www-project-top-ten/2017/A4_2017-XML_External_Entities_%28XXE%29)
- **OWASP XML External Entity (XXE) Processing:** [Enlace](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_%28XXE%29_Processing)
- **Artículo sobre XXE en Wikipedia:** [Enlace](https://es.wikipedia.org/wiki/Ataque_de_entidad_externa_XML)

