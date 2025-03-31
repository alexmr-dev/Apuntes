---

---
----
- Tags: #pentesting 
-----
## ¿Qué es? 

> El Cross-Site Request Forgery (CSRF) es una vulnerabilidad de seguridad en la que un atacante engaña a un usuario legítimo para que realice una acción no deseada en un sitio web sin su conocimiento o consentimiento. En esencia, el atacante fuerza la ejecución de solicitudes HTTP en el contexto de la sesión del usuario, aprovechándose del hecho de que los navegadores envían de forma automática cookies y otros datos de autenticación con cada solicitud

## ¿Cómo funciona?

**1. Preparación del Ataque:**  
    El atacante crea un enlace o una página web maliciosa que contiene un formulario o una petición automatizada (por ejemplo, mediante JavaScript o etiquetas HTML como `<img>` o `<iframe>`). Esta petición está diseñada para realizar una acción específica en el sitio web objetivo (por ejemplo, una transferencia bancaria, cambio de contraseña, etc.).
    
**2. Engaño a la Víctima:**  
    La víctima, que ya ha iniciado sesión en el sitio vulnerable (por ejemplo, su banco en línea), visita el sitio controlado por el atacante o hace clic en un enlace malicioso. Como el navegador incluye automáticamente las cookies de sesión, la solicitud maliciosa se ejecuta en el contexto autenticado de la víctima.
    
**3. Ejecución de la Acción:**  
    El servidor del sitio vulnerable recibe la solicitud, la procesa y realiza la acción sin diferenciar si la solicitud fue generada intencionadamente por el usuario o forzada por un atacante.

## Ejemplo de ataque CSRF

Imagina que un usuario ha iniciado sesión en su cuenta bancaria. El atacante envía por correo electrónico un enlace oculto o malicioso que, al ser visitado, ejecuta un formulario oculto que realiza una transferencia de fondos. Por ejemplo:

``` html
<form action="https://banco.com/transferir" method="POST" style="display:none;">
	<input type="hidden" name="monto" value="1000">
	<input type="hidden" name="destino" value="cuenta_atacante">
</form>
<script>
	document.forms[0].submit();
</script>
```

Si el usuario visita la página del atacante, el formulario se envía automáticamente, realizando la transferencia sin su conocimiento.

> Nota: Este es un ejemplo simplificado. Los sitios modernos implementan mecanismos de protección para evitar este tipo de ataques.

## Medidas de Prevención

1. **Tokens CSRF:**  
    Una de las técnicas más comunes es incluir un token único y secreto en cada formulario o solicitud sensible. El servidor valida este token antes de procesar la acción, asegurándose de que la solicitud proviene de una fuente legítima.
    
    - Ejemplo: Cada vez que se carga un formulario, se genera un token aleatorio que se almacena en la sesión del usuario y se incluye en el formulario. Al enviar la solicitud, el servidor compara el token recibido con el almacenado.
2. **Cabecera Referer y Origin:**  
    Verificar que la solicitud provenga de la misma fuente (dominio) puede ayudar a descartar peticiones foráneas. Sin embargo, estos encabezados pueden ser manipulados o no estar presentes en todas las circunstancias.
    
3. **Cookies con el atributo `SameSite`:**  
    Configurar las cookies de sesión con `SameSite=strict` o `SameSite=lax` limita el envío de cookies a peticiones que se originan desde el mismo sitio, reduciendo el riesgo de CSRF.
    
4. **Validación en el Lado del Servidor:**  
    Además de los tokens, implementar verificaciones adicionales en el servidor, como límites de frecuencia o confirmaciones de acciones sensibles, refuerza la protección contra ataques CSRF.
    
5. **Uso de CAPTCHA y Confirmaciones:**  
    Para acciones críticas, se puede solicitar al usuario una confirmación adicional o la solución de un CAPTCHA para asegurar que la acción es intencionada.

## Resumen

El CSRF explota la confianza que un sitio web tiene en el navegador del usuario, permitiendo que acciones maliciosas se ejecuten en su nombre. La implementación de tokens únicos, la verificación de encabezados y la configuración adecuada de las cookies son medidas fundamentales para proteger una aplicación web de este tipo de ataque.