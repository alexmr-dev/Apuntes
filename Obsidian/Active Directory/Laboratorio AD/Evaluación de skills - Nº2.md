## Escenario

Nuestro cliente Inlanefreight nos ha contratado nuevamente para realizar una prueba de penetración interna de alcance completo. El cliente busca encontrar y remediar tantas fallas como sea posible antes de pasar por un proceso de fusión y adquisición. El nuevo CISO está particularmente preocupado por fallas de seguridad de AD más matizadas que pueden haber pasado desapercibidas durante pruebas de penetración anteriores. El cliente no está preocupado por tácticas sigilosas/evasivas y también nos ha proporcionado una VM Parrot Linux dentro de la red interna para obtener la mejor cobertura posible de todos los ángulos de la red y el entorno de Active Directory. Conéctate al host de ataque interno vía SSH (también puedes conectarte usando `xfreerdp` como se muestra al principio de este módulo) y comienza a buscar un punto de apoyo en el dominio. Una vez que tengas un punto de apoyo, enumera el dominio y busca fallas que puedan utilizarse para moverte lateralmente, escalar privilegios y lograr el compromiso del dominio.

Aplica lo aprendido en este módulo para comprometer el dominio y responde las preguntas a continuación para completar la parte II de la evaluación de habilidades.

##### 1. _Obtén un hash de contraseña para una cuenta de usuario de dominio que pueda aprovecharse para obtener un punto de apoyo en el dominio. ¿Cuál es el nombre de la cuenta?_



##### 2. _¿Cuál es la contraseña en texto claro de este usuario?_



##### 3. _Envía el contenido del archivo C:\flag.txt en MS01._



##### 4. _Usa un método común para obtener credenciales débiles de otro usuario. Envía el nombre de usuario del usuario cuyas credenciales obtienes._



##### 5. _¿Cuál es la contraseña de este usuario?_



##### 6. _Localiza un archivo de configuración que contenga una cadena de conexión MSSQL. ¿Cuál es la contraseña del usuario listado en este archivo?_



##### 7. _Envía el contenido del archivo flag.txt en el escritorio del Administrator en el host SQL01._



##### 8. _Envía el contenido del archivo flag.txt en el escritorio del Administrator en el host MS01._



##### 9. _Obtén credenciales para un usuario que tenga derechos GenericAll sobre el grupo Domain Admins. ¿Cuál es el nombre de cuenta de este usuario?_



##### 10. _Crackea el hash de contraseña de este usuario y envía la contraseña en texto claro como respuesta._



##### 11. _Envía el contenido del archivo flag.txt en el escritorio del Administrator en el host DC01._



##### 12. _Envía el hash NTLM para la cuenta KRBTGT del dominio objetivo después de lograr el compromiso del dominio._

