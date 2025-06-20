## Desde Linux

En este punto ya se ha completado la enumeración inicial del dominio: se ha obtenido información básica de usuarios y grupos, identificado hosts clave como el controlador de dominio y determinado el esquema de nombres usado.
Ahora comienza una nueva fase con dos técnicas clave:

- **Network poisoning** (envenenamiento de red)    
- **Password spraying**    

El objetivo es conseguir credenciales válidas en texto claro de un usuario de dominio, lo que permitirá avanzar con enumeración autenticada.
Se utilizarán ataques tipo **Man-in-the-Middle** contra los protocolos **LLMNR** y **NBT-NS**, que pueden revelar hashes o credenciales en texto claro. Aunque no se cubre en este módulo, esos hashes también pueden usarse en ataques **SMB relay** para autenticarse en otros equipos sin necesidad de crackear la contraseña.

#### LLMNR & NBT-NS Primer

**LLMNR (Link-Local Multicast Name Resolution)** y **NBT-NS (NetBIOS Name Service)** son mecanismos de resolución de nombres que Windows utiliza cuando el DNS falla.

- **LLMNR** usa el puerto UDP 5355 y permite que los hosts en la misma red local se consulten entre sí.    
- Si LLMNR falla, se usa **NBT-NS**, que utiliza UDP 137 y resuelve nombres NetBIOS en la red local.    

El problema es que **cualquier máquina en la red puede responder a estas peticiones**, lo que permite realizar ataques de envenenamiento con herramientas como **Responder**. Este ataque consiste en simular que tu máquina es la que tiene la respuesta a esas solicitudes, provocando que la víctima se conecte a ti. Si eso implica autenticación, puedes capturar **hashes NetNTLM** y luego:

- Crackearlos offline para obtener la contraseña en claro    
- Reutilizarlos directamente mediante **SMB relay** o contra otros servicios como LDAP    

Cuando no hay **SMB signing**, este tipo de ataque puede dar acceso administrativo en la red. El módulo de **movimiento lateral** cubrirá más adelante el ataque SMB relay en profundidad.

#### Ejemplo rápido de envenenamiento LLMNR/NBT-NS

1. Un usuario intenta conectarse a `\\print01.inlanefreight.local`, pero por error escribe `\\printer01.inlanefreight.local`.    
2. El servidor DNS responde que ese host no existe.    
3. El equipo del usuario lanza una petición LLMNR/NBT-NS preguntando a la red si alguien conoce ese nombre.    
4. El atacante (con **Responder** en ejecución) responde haciéndose pasar por ese host.    
5. El equipo víctima **cree la respuesta** y envía una **solicitud de autenticación**, incluyendo el nombre de usuario y el hash **NetNTLMv2**.    
6. El atacante puede entonces:    
    - **Crackear el hash offline**, o        
    - Usarlo en un ataque **SMB relay** si las condiciones lo permiten

Se busca capturar **hashes NTLMv1 y NTLMv2** transmitidos por la red, para luego **crackearlos offline** con herramientas como **Hashcat** o **John**, y así obtener la **contraseña en claro**. Esto permite:

- Obtener un primer acceso al dominio.    
- Escalar privilegios si se captura el hash de una cuenta con más permisos que la actual.

| Herramienta    | Descripción                                                                                                                                             |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Responder**  | Herramienta en Python diseñada para envenenar tráfico LLMNR, NBT-NS y MDNS. Muy utilizada desde hosts Linux. También tiene versión `.exe` para Windows. |
| **Inveigh**    | Plataforma MITM escrita en C# y PowerShell. Permite realizar ataques de spoofing y envenenamiento.                                                      |
| **Metasploit** | Incluye módulos para escaneo y spoofing en este tipo de ataques.                                                                                        |

##### Protocolos que pueden ser atacados

LLMNR, NBT-NS, mDNS, DNS, DHCP, ICMP, HTTP, HTTPS, SMB, LDAP, WebDAV, Proxy Auth

**Responder** además soporta MSSQL, DCE-RPC, FTP, POP3, IMAP, SMTP.

**Responder** es una herramienta sencilla pero muy potente, con múltiples funcionalidades. Antes la usamos en modo pasivo (`-A`), donde solo **escuchaba** tráfico sin intervenir.

Ahora pasamos al **modo activo**, donde empezará a **responder a peticiones LLMNR/NBT-NS** y otras, realizando envenenamiento para capturar hashes NTLM.

##### Opciones clave del comando `responder`:

- `-I <interfaz>` o `-i <IP>`: obligatorio especificar interfaz o IP.    
- `-A`: modo análisis (pasivo, solo escucha).    
- `-f`: intenta identificar el sistema operativo remoto.    
- `-w`: activa el servidor proxy WPAD (muy útil en redes grandes).    
- `-wf`: activa WPAD y fingerprinting.    
- `-v`: modo verboso (muestra más info en pantalla).    
- `-F` y `-P`: fuerzan autenticación NTLM o Basic, pero pueden generar prompts visibles (usar con precaución).

##### Resumen – Uso de hashes capturados con Responder

- **Responder** debe dejarse ejecutando (por ejemplo, en una sesión `tmux`) mientras seguimos con otras tareas de enumeración para maximizar la recolección de hashes.   
- **NTLMv2** es el tipo de hash más común que captura Responder. Se **crackea con Hashcat** usando el modo `5600`.    
- También pueden aparecer hashes **NTLMv1** u otros tipos. Para identificar el formato exacto y el modo adecuado en Hashcat, se puede consultar la página oficial de Hashcat example hashes.
- Los hashes obtenidos con Responder se guardan automáticamente en `/usr/share/Responder/logs/`

_Importante_: NTLMv2 no sirve para técnicas como pass the hash, por lo que debe crackearse offline para obtener la contraseña en claro. Para ello tiramos de hashcat o john the ripper. El módulo de hashcat correspondiente para romper hashes NTLMv2 es `5600`

## Desde Windows

El envenenamiento de LLMNR y NBT-NS también es posible desde un equipo con Windows.  
En la sección anterior utilizamos **Responder** para capturar hashes.  
En esta sección exploraremos la herramienta **Inveigh** e intentaremos capturar otro conjunto de credenciales.
##### Inveigh

Si terminamos utilizando un equipo con Windows como máquina de ataque, si el cliente nos proporciona una máquina Windows desde la que realizar pruebas, o si comprometemos una máquina Windows con privilegios de administrador local mediante otro vector de ataque y queremos escalar aún más nuestro acceso, la herramienta **Inveigh** funciona de forma similar a **Responder**, pero está escrita en **PowerShell y C#**.

Inveigh puede escuchar tráfico tanto IPv4 como IPv6, y cubrir varios protocolos, incluyendo:  
**LLMNR, DNS, mDNS, NBNS, DHCPv6, ICMPv6, HTTP, HTTPS, SMB, LDAP, WebDAV y Proxy Auth.**

La herramienta está disponible en el directorio `C:\Tools` de la máquina Windows proporcionada como equipo de ataque.

Podemos comenzar con la versión de PowerShell con el siguiente comando, y luego listar todos los parámetros posibles. Existe una wiki que documenta todos los parámetros y cómo se usa la herramienta.

```powershell-session
PS C:\htb> Import-Module .\Inveigh.ps1
PS C:\htb> (Get-Command Invoke-Inveigh).Parameters

Key                     Value
---                     -----
ADIDNSHostsIgnore       System.Management.Automation.ParameterMetadata
KerberosHostHeader      System.Management.Automation.ParameterMetadata
ProxyIgnore             System.Management.Automation.ParameterMetadata
PcapTCP                 System.Management.Automation.ParameterMetadata
PcapUDP                 System.Management.Automation.ParameterMetadata
SpooferHostsReply       System.Management.Automation.ParameterMetadata
SpooferHostsIgnore      System.Management.Automation.ParameterMetadata
SpooferIPsReply         System.Management.Automation.ParameterMetadata
SpooferIPsIgnore        System.Management.Automation.ParameterMetadata
WPADDirectHosts         System.Management.Automation.ParameterMetadata
WPADAuthIgnore          System.Management.Automation.ParameterMetadata
ConsoleQueueLimit       System.Management.Automation.ParameterMetadata
ConsoleStatus           System.Management.Automation.ParameterMetadata
ADIDNSThreshold         System.Management.Automation.ParameterMetadata
ADIDNSTTL               System.Management.Automation.ParameterMetadata
DNSTTL                  System.Management.Automation.ParameterMetadata
HTTPPort                System.Management.Automation.ParameterMetadata
HTTPSPort               System.Management.Automation.ParameterMetadata
KerberosCount           System.Management.Automation.ParameterMetadata
LLMNRTTL                System.Management.Automation.ParameterMetadata

<SNIP>
```

Empecemos con LLMNR y NBNS spoofind, e imprimirlo en la consola para escribirlo en un archivo. Dejamos el resto de configuraciones por defecto, como se puede ver aquí:

```powershell-session
PS C:\htb> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
...SNIP...
```

Vemos que inmediatamente obtenemos requests LLMNR y mDNS. 

![[inveigh.png]]
##### Inveigh en C# (InveighZero)

La versión original de Inveigh está escrita en PowerShell y **ya no recibe actualizaciones**.  
El autor de la herramienta mantiene actualmente la versión en **C#**, que combina el código en C# del PoC original con un **port en C# de la mayor parte del código de la versión en PowerShell**.

Antes de poder usar esta versión en C#, hay que compilar el ejecutable.  
Para ahorrar tiempo, se ha incluido una copia tanto de la versión PowerShell como de la **versión ya compilada en C#** en la carpeta `C:\Tools` del host de pruebas en el laboratorio.  
Aun así, merece la pena realizar el ejercicio (y seguir la buena práctica) de compilarla uno mismo usando **Visual Studio**.

Vamos a ejecutar la versión en C# con los parámetros por defecto y comenzar a capturar hashes.

```powershell-session
PS C:\htb> .\Inveigh.exe

[*] Inveigh 2.0.4 [Started 2022-02-28T20:03:28 | PID 6276]
[+] Packet Sniffer Addresses [IP 172.16.5.25 | IPv6 fe80::dcec:2831:712b:c9a3%8]
...SNIP...
```

Como podemos ver, la herramienta se inicia mostrando qué opciones están activadas por defecto y cuáles no.  
Las opciones marcadas con `[+]` están **activadas por defecto**, mientras que las que aparecen con `[ ]` están **desactivadas**.

La salida en consola también nos indica qué funciones están desactivadas y, por tanto, **no están enviando respuestas** (por ejemplo, `mDNS` en el ejemplo anterior).

También aparece el mensaje:  
**"Press ESC to enter/exit interactive console"**, que resulta muy útil mientras se ejecuta la herramienta.  
Esta consola interactiva permite acceder a las credenciales y hashes capturados, detener Inveigh, y más.

Podemos pulsar la tecla `ESC` para entrar en la consola interactiva mientras Inveigh está en ejecución.

```powershell-session
<SNIP>

[+] [20:10:24] LLMNR(A) request [academy-ea-web0] from 172.16.5.125 [response sent]
[+] [20:10:24] LLMNR(A) request [academy-ea-web0] from fe80::f098:4f63:8384:d1d0%8 [response sent]
[-] [20:10:24] LLMNR(AAAA) request [academy-ea-web0] from fe80::f098:4f63:8384:d1d0%8 [type ignored]
[-] [20:10:24] LLMNR(AAAA) request [academy-ea-web0] from 172.16.5.125 [type ignored]
[-] [20:10:24] LLMNR(AAAA) request [academy-ea-web0] from fe80::f098:4f63:8384:d1d0%8 [type ignored]
[-] [20:10:24] LLMNR(AAAA) request [academy-ea-web0] from 172.16.5.125 [type ignored]
[-] [20:10:24] LLMNR(AAAA) request [academy-ea-web0] from fe80::f098:4f63:8384:d1d0%8 [type ignored]
[-] [20:10:24] LLMNR(AAAA) request [academy-ea-web0] from 172.16.5.125 [type ignored]
[.] [20:10:24] TCP(1433) SYN packet from 172.16.5.125:61310
[.] [20:10:24] TCP(1433) SYN packet from 172.16.5.125:61311
C(0:0) NTLMv1(0:0) NTLMv2(3:9)> HELP
```

Si le damos a `HELP` se nos presentan varias opciones, en especial, `GET NTLMV2UNIQUE` que nos permite ver hashes únicos capturados. También podemos escribir `GET NTLMV2USERNAMES` y ver qué usuarios hemos coleccionado. Esto es útil si queremos una lista de usuarios para realizar enumeración adicional y ver cuáles merecen la pena crackear offline con Hashcat. 

### Remediación 

> *Esto nos servirá para explicarlo en auditorías*

MITRE ATT&CK enumera esta técnica con el ID: **T1557.001**, **Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning y SMB Relay**.

Existen varias formas de mitigar este ataque. Para asegurarse de que estos ataques de suplantación no sean posibles, se puede **deshabilitar LLMNR y NBT-NS**.

**Advertencia:** siempre es recomendable probar lentamente un cambio significativo como este en el entorno antes de implementarlo por completo.  
Como pentesters, **podemos recomendar estas medidas de mitigación**, pero debemos **comunicar claramente a nuestros clientes** que prueben estos cambios a fondo para asegurarse de que **desactivar ambos protocolos no rompe funcionalidades de la red**.

Para **deshabilitar LLMNR** desde la Directiva de Grupo (GPO), hay que ir a:

> `Configuración del equipo → Plantillas administrativas → Red → Cliente DNS`  
> y activar la opción **"Desactivar la resolución de nombres por multidifusión"**.

![[inveight2.png]]
**NBT-NS no puede deshabilitarse mediante directiva de grupo (GPO)**, sino que **debe deshabilitarse localmente en cada equipo**.  
Para hacerlo, sigue estos pasos:

1. Abre el **Centro de redes y recursos compartidos** desde el **Panel de control**.    
2. Haz clic en **Cambiar configuración del adaptador**.    
3. Haz clic derecho sobre el adaptador de red en uso y selecciona **Propiedades**.    
4. Selecciona **Protocolo de Internet versión 4 (TCP/IPv4)** y pulsa en **Propiedades**.    
5. Pulsa el botón **Opciones avanzadas...**.    
6. Ve a la pestaña **WINS**.    
7. Selecciona la opción **Desactivar NetBIOS sobre TCP/IP**.

![[inveight3.png]]
Aunque no es posible **deshabilitar NBT-NS directamente mediante GPO**, sí se puede **crear un script de PowerShell** que se ejecute en el **inicio** a través de:

`Configuración del equipo --> Configuración de Windows --> Scripts (Inicio/Apagado) --> Inicio`

Y dentro, añadir un script como este:

```powershell
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}
```

En el **Editor de directivas de grupo local**, será necesario hacer doble clic en **Inicio**, ir a la pestaña **Scripts de PowerShell**, y seleccionar la opción **"Para esta GPO, ejecutar scripts en el siguiente orden"** para que se ejecuten **primero los scripts de PowerShell de Windows**.

Después, haz clic en **Agregar** y selecciona el script que desees aplicar.

> Para que los cambios surtan efecto, será necesario **reiniciar el sistema objetivo** o **reiniciar el adaptador de red**.

Para aplicar esto a todos los hosts de un dominio, podríamos **crear una GPO** usando la **Consola de Administración de Directivas de Grupo** en el **Controlador de Dominio**, y **alojar el script en el recurso compartido SYSVOL** dentro de la carpeta de scripts, llamándolo mediante su ruta UNC, por ejemplo:

```
\\inlanefreight.local\SYSVOL\INLANEFREIGHT.LOCAL\scripts
```

Una vez aplicada la GPO a unidades organizativas (OU) específicas y **reiniciados los hosts**, el script se ejecutará en el siguiente arranque y **desactivará NBT-NS**, siempre que el script siga existiendo en el recurso SYSVOL y sea accesible por los hosts a través de la red.

![[inveight4.png]]