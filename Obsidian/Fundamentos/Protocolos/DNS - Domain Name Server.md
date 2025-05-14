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

#### DIG - NS Query

```shell-session
amr251@htb[/htb]$ dig ns inlanefreight.htb @10.129.14.128

; <<>> DiG 9.16.1-Ubuntu <<>> ns inlanefreight.htb @10.129.14.128
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 45010
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 2
```

#### DIG - Version Query

```shell-session
amr251@htb[/htb]$ dig CH TXT version.bind 10.129.120.85

; <<>> DiG 9.10.6 <<>> CH TXT version.bind
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 47786
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
```

#### DIG - Any Query

```shell-session
amr251@htb[/htb]$ dig any inlanefreight.htb @10.129.14.128

; <<>> DiG 9.16.1-Ubuntu <<>> any inlanefreight.htb @10.129.14.128
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 7649
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 2
```

#### DIG - Zona de transferencia AXRF 

La transferencia de zona (AXFR) es el proceso de copiar archivos de zona DNS entre servidores para asegurar que todos los servidores tengan la misma información. El servidor principal (master) contiene los datos originales, mientras que los servidores secundarios (slave) los obtienen para mejorar la confiabilidad y distribuir la carga. Los cambios en la zona generalmente solo se realizan en el servidor principal. Los servidores secundarios sincronizan sus datos mediante la transferencia de zona y verifican los números de serie del registro SOA para detectar discrepancias.

```shell-session
amr251@htb[/htb]$ dig axfr inlanefreight.htb @10.129.14.128

; <<>> DiG 9.16.1-Ubuntu <<>> axfr inlanefreight.htb @10.129.14.128
;; global options: +cmd
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
inlanefreight.htb.      604800  IN      TXT     "MS=ms97310371"
...SNIP..
```

Si el administrador usó una subred para la opción allow-transfer con fines de prueba o como una solución provisional, o la configuró en "any", cualquiera podría consultar todo el archivo de zona en el servidor DNS. Además, se podrían consultar otras zonas, lo que incluso podría mostrar direcciones IP internas y nombres de host.

#### DIG - Zona de transferencia AXFR - Interna

```shell-session
amr251@htb[/htb]$ dig axfr internal.inlanefreight.htb @10.129.14.128

; <<>> DiG 9.16.1-Ubuntu <<>> axfr internal.inlanefreight.htb @10.129.14.128
;; global options: +cmd
internal.inlanefreight.htb. 604800 IN   SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
internal.inlanefreight.htb. 604800 IN   TXT     "MS=ms97310371"
internal.inlanefreight.htb. 604800 IN   TXT     "atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
internal.inlanefreight.htb. 604800 IN   TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
internal.inlanefreight.htb. 604800 IN   NS      ns.inlanefreight.htb.

...SNIP...
```

### Enumeración por fuerza bruta de subdominios

```shell-session
amr251@htb[/htb]$ for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done

ns.inlanefreight.htb.   604800  IN      A       10.129.34.136
mail1.inlanefreight.htb. 604800 IN      A       10.129.18.201
app.inlanefreight.htb.  604800  IN      A       10.129.18.15
```

Existen muchas herramientas para esto, y prácticamente todas funcionan de la misma manera. Una herramienta poderosa para hacer la enumeración es [DNSEnum](https://github.com/fwaeytens/dnsenum)

a