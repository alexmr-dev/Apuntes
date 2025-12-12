## Escenario

Un miembro del equipo comenzó una Prueba de Penetración Externa y fue trasladado a otro proyecto urgente antes de poder terminar. El miembro del equipo logró encontrar y explotar una vulnerabilidad de subida de archivos después de realizar reconocimiento del servidor web expuesto externamente. Antes de cambiar de proyecto, nuestro compañero dejó una web shell protegida por contraseña (con las credenciales: `admin:My_W3bsH3ll_P@ssw0rd!`) en su lugar para que nosotros comencemos en el directorio `/uploads`. Como parte de esta evaluación, nuestro cliente, Inlanefreight, nos ha autorizado a ver hasta dónde podemos llevar nuestro punto de apoyo y está interesado en ver qué tipos de problemas de alto riesgo existen dentro del entorno AD. Aprovecha la web shell para obtener un punto de apoyo inicial en la red interna. Enumera el entorno de Active Directory buscando fallas y configuraciones incorrectas para moverte lateralmente y finalmente lograr el compromiso del dominio.

Aplica lo aprendido en este módulo para comprometer el dominio y responde las preguntas a continuación para completar la parte I de la evaluación de habilidades.

**Preguntas:**
##### 1. _Sube los contenidos del archivo flag.txt en el Escritorio del administrador del servidor web_


##### 2. _Realiza Kerberoast a una cuenta con el SPN MSSQLSvc/SQL01.inlanefreight.local:1433 y envía el nombre de la cuenta como respuesta_


##### 3. _Crackea la contraseña de la cuenta. Envía el valor en texto claro._


##### 4. _Envía el contenido del archivo flag.txt en el escritorio del Administrator en MS01_


##### 5. _Encuentra credenciales en texto claro de otro usuario del dominio. Envía el nombre de usuario como respuesta._


##### 6. _Envía la contraseña en texto claro de este usuario._


##### 7. _¿Qué ataque puede realizar este usuario?_


##### 8. _Toma el control del dominio y envía el contenido del archivo flag.txt en el escritorio del Administrator en DC01_

