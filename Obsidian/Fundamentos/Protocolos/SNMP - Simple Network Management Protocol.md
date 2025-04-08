> El Protocolo Simple de Administración de Red (SNMP) fue creado para monitorear dispositivos de red. Además, este protocolo también se puede usar para gestionar tareas de configuración y cambiar ajustes de forma remota. Los dispositivos habilitados para SNMP incluyen enrutadores, switches, servidores, dispositivos IoT y muchos otros que pueden ser consultados y controlados utilizando este protocolo estándar. La versión actual es SNMPv3, que mejora la seguridad, pero también aumenta la complejidad de su uso.

Además del intercambio de información, SNMP también transmite comandos de control mediante agentes a través del puerto **UDP 161**. El cliente puede establecer valores específicos en el dispositivo y cambiar opciones y configuraciones con estos comandos. A diferencia de la comunicación clásica, donde siempre es el cliente quien solicita activamente la información al servidor, SNMP también permite el uso de "traps" a través del puerto **UDP 162**. Estos son paquetes de datos enviados desde el servidor SNMP al cliente sin ser explícitamente solicitados. Si un dispositivo está configurado adecuadamente, se enviará un trap cuando ocurra un evento específico en el servidor.

Para que el cliente y el servidor SNMP intercambien valores, los objetos SNMP disponibles deben tener direcciones únicas conocidas por ambas partes. Este mecanismo de direccionamiento es esencial para transmitir datos y monitorear redes con éxito mediante SNMP.
### MIB

Para asegurar que el acceso SNMP funcione entre diferentes fabricantes y combinaciones de cliente-servidor, se creó la **Base de Información de Gestión** (MIB, por sus siglas en inglés). La MIB es un formato independiente para almacenar información de dispositivos. Es un archivo de texto en el que se listan todos los objetos SNMP consultables de un dispositivo en una jerarquía estándar de árbol. Contiene al menos un **Identificador de Objeto** (OID), que, además de la dirección única y el nombre, proporciona información sobre el tipo, los derechos de acceso y una descripción del objeto respectivo. Los archivos MIB están escritos en formato de texto ASCII basado en la **Notación de Sintaxis Abstracta Uno** (ASN.1). Las MIB no contienen datos, sino que explican dónde encontrar la información, qué valores devuelve para el OID específico y qué tipo de datos se usa.
### OID

Un **OID** (Identificador de Objeto) representa un nodo en un espacio de nombres jerárquico. Cada nodo está identificado por una secuencia de números, lo que permite determinar la posición del nodo en el árbol. Cuanto más larga es la secuencia, más específica es la información. Muchos nodos en el árbol OID no contienen datos, sino solo referencias a nodos inferiores. Los OIDs están compuestos por enteros y suelen estar concatenados por notación de puntos. Se pueden consultar muchas MIBs para obtener los OIDs asociados en el **Registro de Identificadores de Objetos**.
### SNMPv1

**SNMP versión 1** (SNMPv1) se utiliza para la gestión y monitoreo de redes. Es la primera versión del protocolo y aún se usa en muchas redes pequeñas. Permite recuperar información de los dispositivos de red, configurar dispositivos y proporciona **traps**, que son notificaciones de eventos. Sin embargo, SNMPv1 carece de un mecanismo de autenticación, lo que significa que cualquiera que acceda a la red puede leer y modificar los datos de la red. Otro gran defecto de SNMPv1 es que no soporta cifrado, por lo que todos los datos se envían en texto claro y pueden ser fácilmente interceptados.
### SNMPv2

**SNMPv2** existió en diferentes versiones, y la versión que aún se usa es la **v2c**, donde la "c" significa **comunidad basada en SNMP**. En cuanto a seguridad, SNMPv2 está al nivel de SNMPv1 y fue ampliado con funciones adicionales de SNMP basado en partidos, que ya no se utiliza. Sin embargo, un problema importante de SNMPv2 es que la cadena de comunidad, que proporciona seguridad, se transmite en texto claro, lo que significa que no tiene cifrado incorporado.
### SNMPv3

La seguridad en **SNMPv3** ha aumentado considerablemente con características de seguridad como la autenticación mediante nombre de usuario y contraseña, y el cifrado de transmisión de datos (mediante clave compartida). Sin embargo, también ha aumentado la complejidad, con muchas más opciones de configuración que en SNMPv2.
### Cadenas de Comunidad

Las **cadenas de comunidad** pueden verse como contraseñas que se utilizan para determinar si la información solicitada puede ser visualizada o no. Es importante señalar que muchas organizaciones todavía utilizan **SNMPv2**, ya que la transición a **SNMPv3** puede ser muy compleja, pero los servicios aún necesitan seguir activos. Esto genera una gran preocupación entre muchos administradores y crea problemas que intentan evitar. La falta de conocimiento sobre cómo se puede obtener la información y cómo los atacantes la usan hace que el enfoque de los administradores parezca inexplicable. Al mismo tiempo, la falta de cifrado en los datos enviados también es un problema, ya que cada vez que las cadenas de comunidad se envían a través de la red, pueden ser interceptadas y leídas.
### Configuración por defecto

El daemon de configuración por defecto de SNMP define la configuración básica para el servicio, que incluye las direcciones IP, puertos, MIB, OIDs, autenticación y las cadenas de comunidad.

```shell-session
amr251@htb[/htb]$ cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s*$/d'

sysLocation    Sitting on the Dock of the Bay
sysContact     Me <me@example.org>
sysServices    72
master  agentx
agentaddress  127.0.0.1,[::1]
view   systemonly  included   .1.3.6.1.2.1.1
view   systemonly  included   .1.3.6.1.2.1.25.1
rocommunity  public default -V systemonly
rocommunity6 public default -V systemonly
rouser authPrivUser authpriv -V systemonly
```

### Configuración peligrosa

| Configuración                                         | Descripción                                                                                  |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `rwuser noauth`                                       | Proporciona acceso completo al árbol OID sin autenticación.                                  |
| `rwcommunity <cadena de comunidad> <dirección IPv4>`  | Proporciona acceso completo al árbol OID sin importar desde dónde se envíen las solicitudes. |
| `rwcommunity6 <cadena de comunidad> <dirección IPv6>` | Igual que `rwcommunity`, pero utilizando IPv6 en lugar de IPv4.                              |
### Footprinting al servicio

Para hacer footprinting al servicio SNMP, podemos usar herramientas como `snmpwalk`, `onesixtyone` y `braa`. `snmpwalk` es usado para listar los OIDs con su información. `onesixtyone` para hacer fuerza bruta e intentar obtener los nombres de las cadenas de comunidad, pues pueden ser nombradas de forma arbitraria por el administrador. Puesto que estas cadenas pueden estar atadas a cualquier fuente, identificar las cadenas puede llevar bastante tiempo.

#### SNMPwalk

```shell-session
amr251@htb[/htb]$ snmpwalk -v2c -c public 10.129.14.128
```

#### Onesixtyone

```shell-session
amr251@htb[/htb]$ onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt 10.129.14.128

Scanning 1 hosts, 3220 communities
10.129.14.128 [public] Linux htb 5.11.0-37-generic #41~20.04.2-Ubuntu SMP Fri Sep 24 09:06:38 UTC 2021 x86_64
```

A menudo, cuando ciertas cadenas de comunidad están atadas a direcciones IP específicas, se nombran con el hostname del host, y a veces incluso símbolos son añadidos a esos nombres para hacerlos más complicados de identificar. Sin embargo, si imaginamos una extensa red con unos 100 servidores administrados usando SNMP, las etiquetas, en ese caso, tendrán un patrón en ellas. Por tanto, podemos usar diferentes reglas para adivinarlas. Podemos usar [crunch](https://secf00tprint.github.io/blog/passwords/crunch/advanced/en) para crear wordlists personalizadas. Una vez sepamos una cadena de comunidad, podemos usarla con [braa](https://github.com/mteg/braa) para hacer fuerza bruta sobre los OIDs individuales

#### Braa

```shell-session
amr251@htb[/htb]$ braa <community string>@<IP>:.1.3.6.*   # Syntax
amr251@htb[/htb]$ braa public@10.129.14.128:.1.3.6.*

10.129.14.128:20ms:.1.3.6.1.2.1.1.1.0:Linux htb 5.11.0-34-generic #36~20.04.1-Ubuntu SMP Fri Aug 27 08:06:32 UTC 2021 x86_64
10.129.14.128:20ms:.1.3.6.1.2.1.1.2.0:.1.3.6.1.4.1.8072.3.2.10
10.129.14.128:20ms:.1.3.6.1.2.1.1.3.0:548
10.129.14.128:20ms:.1.3.6.1.2.1.1.4.0:mrb3n@inlanefreight.htb
10.129.14.128:20ms:.1.3.6.1.2.1.1.5.0:htb
10.129.14.128:20ms:.1.3.6.1.2.1.1.6.0:US
10.129.14.128:20ms:.1.3.6.1.2.1.1.7.0:78
...SNIP...
```