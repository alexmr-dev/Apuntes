> El Sistema de Nombres de Dominio (DNS) es una parte integral de Internet. Por ejemplo, a través de nombres de dominio, como academy.hackthebox.com o www.hackthebox.com, podemos llegar a los servidores web a los que el proveedor de hosting ha asignado una o más direcciones IP específicas. DNS es un sistema para resolver nombres de computadoras en direcciones IP, y no tiene una base de datos central. 
 
De manera simplificada, podemos imaginarlo como una biblioteca con muchos directorios telefónicos diferentes. La información está distribuida entre miles de servidores de nombres. Los servidores DNS distribuidos globalmente traducen los nombres de dominio en direcciones IP y, de este modo, controlan qué servidor puede alcanzar un usuario a través de un dominio particular. Existen varios tipos de servidores DNS que se utilizan en todo el mundo:

| **Tipo de servidor**                    | **Descripción**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Servidor raíz DNS**                   | Los servidores raíz de DNS son responsables de los dominios de nivel superior (TLD). Como última instancia, solo se les solicita si el servidor de nombres no responde. Así, un servidor raíz es una interfaz central entre los usuarios y el contenido en Internet, ya que vincula el dominio con la dirección IP. La Corporación de Internet para la Asignación de Nombres y Números (ICANN) coordina el trabajo de los servidores de nombres raíz. Existen 13 servidores raíz de este tipo alrededor del mundo. |
| **Servidor de nombres autoritativo**    | Los servidores de nombres autoritativos tienen autoridad sobre una zona particular. Solo responden a consultas de su área de responsabilidad, y su información es vinculante. Si un servidor de nombres autoritativo no puede responder a la consulta de un cliente, el servidor raíz de nombres toma el control en ese momento.                                                                                                                                                                                   |
| **Servidor de nombres no autoritativo** | Los servidores de nombres no autoritativos no son responsables de una zona DNS particular. En cambio, recopilan información sobre zonas DNS específicas, lo que se realiza mediante consultas DNS recursivas o iterativas.                                                                                                                                                                                                                                                                                         |
| **Servidor DNS de caché**               | Los servidores DNS de caché almacenan información de otros servidores de nombres durante un período específico. El servidor de nombres autoritativo determina la duración de este almacenamiento.                                                                                                                                                                                                                                                                                                                  |
| **Servidor de reenvío**                 | Los servidores de reenvío realizan una sola función: reenvían las consultas DNS a otro servidor DNS.                                                                                                                                                                                                                                                                                                                                                                                                               |
| **Resolver**                            | Los resolvers no son servidores DNS autoritativos, pero realizan la resolución de nombres localmente en la computadora o en el enrutador.                                                                                                                                                                                                                                                                                                                                                                          |
Se utilizan diferentes registros DNS para las consultas DNS, que tienen múltiples tareas.

| **Registro DNS** | **Descripción**                                                                                                                                                                                                                                                                  |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A**            | Devuelve una dirección IPv4 del dominio solicitado como resultado.                                                                                                                                                                                                               |
| **AAAA**         | Devuelve una dirección IPv6 del dominio solicitado.                                                                                                                                                                                                                              |
| **MX**           | Devuelve los servidores de correo responsables como resultado.                                                                                                                                                                                                                   |
| **NS**           | Devuelve los servidores DNS (servidores de nombres) del dominio.                                                                                                                                                                                                                 |
| **TXT**          | Este registro puede contener información diversa. El todoterreno puede ser utilizado, por ejemplo, para validar la Consola de Búsqueda de Google o validar certificados SSL. Además, se configuran entradas SPF y DMARC para validar el tráfico de correo y protegerlo del spam. |
| **CNAME**        | Este registro funciona como un alias para otro nombre de dominio. Si quieres que el dominio www.hackthebox.eu apunte a la misma IP que hackthebox.eu, crearías un registro A para hackthebox.eu y un registro CNAME para www.hackthebox.eu.                                      |
| **PTR**          | El registro PTR funciona al revés (búsqueda inversa). Convierte direcciones IP en nombres de dominio válidos.                                                                                                                                                                    |
| **SOA**          | Proporciona información sobre la zona DNS correspondiente y la dirección de correo electrónico del contacto administrativo.                                                                                                                                                      |
El registro SOA está localizado en un archivo en la zona de dominio y especifica quién es responsable de la operación del dominio y cómo la información DNS es utilizada.

### Configuración por defecto

Existen múltiples tipos de configuración para DNS. Todos los servidores DNS trabajan con 3 tipos de archivos de configuración:
1. Archivos locales de configuración
2. Archivos de zona
3. Archivos de resolución inversa de zona.

El servidor DNS Bind9 se usa con mucha frecuencia en distribuciones basadas en Linux. Su archivo de configuración local (named.conf) está aproximadamente dividido en dos secciones: primero, la sección de opciones para configuraciones generales y, en segundo lugar, las entradas de zona para los dominios individuales. Los archivos de configuración local suelen ser:

- named.conf.local
- named.conf.options    
- named.conf.log    

Contiene el RFC asociado donde podemos personalizar el servidor según nuestras necesidades y nuestra estructura de dominio con las zonas individuales para diferentes dominios. El archivo de configuración named.conf está dividido en varias opciones que controlan el comportamiento del servidor de nombres. Se hace una distinción entre opciones globales y opciones de zona.

### Configuración local de DNS

```shell-session
root@bind9:~# cat /etc/bind/named.conf.local

//
// Do any local configuration here
//

// Consider adding the 1918 zones here, if they are not used in your
// organization
//include "/etc/bind/zones.rfc1918";
zone "domain.com" {
    type master;
    file "/etc/bind/db.domain.com";
    allow-update { key rndc-key; };
};
```

En este archivo, podemos definir las diferentes zonas. Estas zonas se dividen en archivos individuales, que en la mayoría de los casos están destinados principalmente a un solo dominio. Las excepciones son los servidores DNS de proveedores de servicios de Internet (ISP) y servidores DNS públicos. Además, muchas opciones diferentes amplían o reducen la funcionalidad. Podemos consultar estas opciones en la documentación de Bind9.

### Archivos de zona (Zone Files)

Un archivo de zona es un archivo de texto que describe una zona DNS con el formato de archivo BIND. En otras palabras, es un punto de delegación en el árbol DNS. El formato de archivo BIND es el formato de archivo de zona preferido en la industria y ahora está bien establecido en el software de servidores DNS. Un archivo de zona describe completamente una zona. Debe haber exactamente un registro SOA y al menos un registro NS. El registro de recurso SOA generalmente se encuentra al principio de un archivo de zona. El objetivo principal de estas reglas globales es mejorar la legibilidad de los archivos de zona. Un error de sintaxis generalmente resulta en que todo el archivo de zona sea considerado inutilizable. El servidor de nombres se comporta de manera similar, como si esta zona no existiera. Responde a las consultas DNS con un mensaje de error SERVFAIL.

```shell-session
root@bind9:~# cat /etc/bind/db.domain.com

;
; BIND reverse data file for local loopback interface
;
$ORIGIN domain.com
$TTL 86400
(...)
```

Para que la dirección IP sea resuelta a partir del Nombre de Dominio Completo (FQDN), el servidor DNS debe tener un archivo de búsqueda inversa. En este archivo, el nombre del equipo (FQDN) se asigna al último octeto de una dirección IP, que corresponde al host respectivo, utilizando un registro PTR. Los registros PTR son responsables de la traducción inversa de direcciones IP a nombres, como ya hemos visto en la tabla anterior.
### Archivos de resolución inversa de zona

```shell-session
root@bind9:~# cat /etc/bind/db.10.129.14

;
; BIND reverse data file for local loopback interface
;
$ORIGIN 14.129.10.in-addr.arpa
$TTL 86400
@     IN     SOA    dns1.domain.com.     hostmaster.domain.com. (
                    2001062501 ; serial
                    21600      ; refresh after 6 hours
                    3600       ; retry after 1 hour
                    604800     ; expire after 1 week
                    86400 )    ; minimum TTL of 1 day

      IN     NS     ns1.domain.com.
      IN     NS     ns2.domain.com.

5    IN     PTR    server1.domain.com.
7    IN     MX     mx.domain.com.
...SNIP...
```

### Configuración peligrosa

Hay muchas formas en las que un servidor DNS puede ser atacado. Por ejemplo, una lista de vulnerabilidades apuntando al servidor BIND9 se pueden encontrar en [CVEDetails](https://www.cvedetails.com/product/144/ISC-Bind.html?vendor_id=64). Algunas de las configuraciones a continuación pueden llevar a esas vulnerabilidades, entre otras. 

| **Opción**          | **Descripción**                                                                         |
| ------------------- | --------------------------------------------------------------------------------------- |
| **allow-query**     | Define qué hosts tienen permitido enviar solicitudes al servidor DNS.                   |
| **allow-recursion** | Define qué hosts tienen permitido enviar solicitudes recursivas al servidor DNS.        |
| **allow-transfer**  | Define qué hosts tienen permitido recibir transferencias de zona desde el servidor DNS. |
| **zone-statistics** | Recopila datos estadísticos de las zonas.                                               |

### Footprinting al servicio DNS

El footprinting en los servidores DNS se realiza como resultado de las solicitudes que enviamos. Por lo tanto, lo primero que podemos hacer es consultar al servidor DNS sobre qué otros servidores de nombres se conocen. Hacemos esto utilizando el registro NS y la especificación del servidor DNS que queremos consultar mediante el carácter @. Esto se debe a que, si existen otros servidores DNS, también podemos utilizarlos y consultar los registros. Sin embargo, otros servidores DNS pueden estar configurados de manera diferente y, además, pueden ser permanentes para otras zonas.
##### Enumeración por fuerza bruta de subdominios

```shell-session
amr251@htb[/htb]$ for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done

ns.inlanefreight.htb.   604800  IN      A       10.129.34.136
mail1.inlanefreight.htb. 604800 IN      A       10.129.18.201
app.inlanefreight.htb.  604800  IN      A       10.129.18.15
```

Existen muchas herramientas para esto, y prácticamente todas funcionan de la misma manera. Una herramienta poderosa para hacer la enumeración es [DNSEnum](https://github.com/fwaeytens/dnsenum) o `dnsrecon`

```bash
dnsrecon -d <Dominio> -a 
```

##### Toma de dominios y enumeración de subdominios

Consiste en registrar un nombre de dominio inexistente para obtener el control sobre otro dominio. Si los atacantes encuentran un dominio expirado, pueden reclamar ese dominio para realizar ataques adicionales, como alojar contenido malicioso en un sitio web o enviar correos electrónicos de phishing aprovechando el dominio reclamado.

La toma de dominio también es posible con subdominios, lo que se denomina toma de subdominio. El registro de nombre canónico (CNAME) de un DNS se utiliza para mapear diferentes dominios a un dominio principal. Muchas organizaciones utilizan servicios de terceros como AWS, GitHub, Akamai, Fastly y otras redes de distribución de contenido (CDN) para alojar su contenido. En este caso, suelen crear un subdominio y hacer que apunte a esos servicios. Por ejemplo:

```shell-session
sub.target.com.   60   IN   CNAME   anotherdomain.com
```

##### Enumeración de subdominios

Antes de realizar una toma de subdominio deberíamos enumerar subdominios para un dominio objetivo con herramientas como Subfinder, DNSdumpster, sublist3r o gobuster:

```bash
gobuster dns -d inlanefreight.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt 
```

```bash
subfinder -d xirio-online.com -v
```

Otra alternativa excelente es subsurte, que nos permite usar nuestros propios resolvers y realizar puros ataques de fuerza bruta durante un pentesting interno en hosts a los que no tenemos acceso a Internet.

```shell-session
amr251@htb[/htb]$ git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
amr251@htb[/htb]$ cd subbrute
amr251@htb[/htb]$ echo "ns1.inlanefreight.com" > ./resolvers.txt
amr251@htb[/htb]$ ./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt

Warning: Fewer than 16 resolvers per process, consider adding more nameservers to resolvers.txt.
inlanefreight.com
ns2.inlanefreight.com
www.inlanefreight.com
ms1.inlanefreight.com
support.inlanefreight.com

<SNIP>
```

A veces, las configuraciones físicas internas están mal aseguradas, lo que podemos aprovechar para cargar nuestras herramientas desde una memoria USB. Otro escenario sería que hayamos accedido a un host interno mediante pivoting y queramos trabajar desde allí. Por supuesto, existen otras alternativas, pero no está de más conocer formas y posibilidades alternativas.

La herramienta ha encontrado cuatro subdominios asociados con inlanefreight.com. Usando el comando `nslookup` o `host`, podemos enumerar los registros CNAME de esos subdominios.

```shell-session
amr251@htb[/htb]# host support.inlanefreight.com

support.inlanefreight.com is an alias for inlanefreight.s3.amazonaws.com
```

El subdominio _support_ tiene un registro de alias que apunta a un bucket de AWS S3. Sin embargo, la URL [https://support.inlanefreight.com](https://support.inlanefreight.com) muestra un error _NoSuchBucket_, lo que indica que el subdominio es potencialmente vulnerable a una toma de subdominio. Ahora, podemos tomar el control del subdominio creando un bucket de AWS S3 con el mismo nombre que el subdominio.

![[xml.png]]

### DNS Spoofing

El DNS spoofing también se conoce como envenenamiento de caché DNS (_DNS Cache Poisoning_). Este ataque consiste en alterar registros DNS legítimos con información falsa para redirigir el tráfico en línea hacia un sitio web fraudulento. Ejemplos de rutas de ataque para el envenenamiento de caché DNS son los siguientes:

Un atacante podría interceptar la comunicación entre un usuario y un servidor DNS para redirigir al usuario a un destino fraudulento en lugar de uno legítimo, realizando un ataque de Hombre en el Medio (_Man-in-the-Middle_, MITM).

Explotar una vulnerabilidad encontrada en un servidor DNS podría darle al atacante el control sobre dicho servidor para modificar los registros DNS.

##### Envenenamiento de la caché del DNS local

Desde la perspectiva de una red local, un atacante también puede realizar envenenamiento de caché DNS utilizando herramientas MITM como Ettercap o Bettercap. Para explotar el envenenamiento de caché DNS mediante Ettercap, primero debemos editar el archivo `/etc/ettercap/etter.dns` para mapear el nombre de dominio objetivo (por ejemplo, _inlanefreight.com_) que se desea suplantar y la dirección IP del atacante (por ejemplo, _192.168.225.110_) a la que se desea redirigir al usuario:

```shell-session
amr251@htb[/htb]# cat /etc/ettercap/etter.dns

inlanefreight.com      A   192.168.225.110
*.inlanefreight.com    A   192.168.225.110
```

Después, arrancamos la herramienta `Ettercap` y escaneamos hosts dentro de la red navegando a `Hosts > Scan for Hosts`. Una vez completado, añadimos la IP objetivo (por ejemplo, 192.168.152.129) a Target1 y la puerta de enlace por defecto a Target2

![[ettercap.png| 600]]

Activamos `dns_spoof` navegando a `Plugins > Manage Plugins`. Esto envía a la máquina objetivo responses falsas DNS que resolverán `inlanefreight.com` en la IP 192.168.225.110

![[ettercap2.png| 600]]

Después de un ataque exitoso de spoof DNS, si un usuario víctima que viene desde la máquina objetivo `192.168.152.129` visita el dominio de `inlanefreight.com`, será redirigido a una web falsa con IP 192.168.225.110

![[dns_spoofing.png| 600]]