> Es un protocolo de administración remota que le permite a los usuarios controlar y modificar sus servidores remotos a través de Internet a través de un mecanismo de autenticación. Proporciona un mecanismo para autenticar un usuario remoto, transferir entradas desde el cliente al host y retransmitir la salida de vuelta al cliente. El servicio se creó como un reemplazo seguro para el Telnet sin cifrar y utiliza técnicas criptográficas para garantizar que todas las comunicaciones hacia y desde el servidor remoto sucedan de manera encriptada.

El puerto por defecto de este protocolo es el **22**.

### ¿Cómo funciona SSH?

SSH permite establecer una conexión segura a través de una red utilizando encriptación. El proceso de conexión se realiza mediante dos fases: autenticación y comunicación.

1. **Autenticación**: El cliente se autentica ante el servidor utilizando uno de los métodos de autenticación disponibles (contraseña o clave pública).
2. **Comunicación encriptada**: Una vez autenticado, toda la comunicación entre el cliente y el servidor se cifra utilizando criptografía simétrica para evitar la interceptación.

Hay dos tipos de cifrados, el simétrico y el asimétrico. El cifrado simétrico es una forma de cifrado en la que se utiliza una **clave secreta** tanto para el cifrado como para el descifrado de un mensaje, tanto por el cliente como por el host. Efectivamente, cualquiera que tenga la clave puede descifrar el mensaje que se transfiere.

![[ssh_func.png|600 ]]

El cifrado simétrico a menudo se llama **clave compartida** (shared key) o **cifrado secreto compartido**. Normalmente sólo hay una clave que se utiliza, o a veces un par de claves donde una clave se puede calcular fácilmente con la otra clave. Existen varios códigos cifrados simétricos, incluyendo, pero no limitado a, AES (Advanced Encryption Standard), CAST128, Blowfish, etc. Antes de establecer una conexión segura, el cliente y un host deciden qué cifrado usar, publicando una lista de cifrados soportados por orden de preferencia. El cifrado preferido de entre los soportados por los clientes que está presente en la lista del host se utiliza como el cifrado bidireccional.

#### Cifrado asimétrico

A diferencia del cifrado simétrico, el cifrado asimétrico utiliza dos claves separadas para el cifrado y el descifrado. Estas dos claves se conocen como la **clave pública** (public key) y la **clave privada** (private key). Juntas, estas claves forman el par de **claves pública-privada** (public-private key pair).

![[ssh_func_asim.png|600]]

### Comandos básicos 

**1. Conexión al servidor**: Para conectar a un servidor remoto mediante SSH:

```bash
ssh usuario@direccion_ip_del_servidor
```

Si el servidor está usando un puerto diferente al por defecto (22):

```bash
ssh -p [puerto] usuario@direccion_ip_del_servidor
```

**2. Conexión con una clave privada**: Si el servidor está configurado para usar autenticación con clave pública y privada, puedes especificar tu archivo de clave privada con `-i`:

```bash
ssh -i /ruta/a/tu/id_rsa usuario@direccion_ip_del_servidor
```

### Uso de claves públicas y privadas

En SSH, se utiliza un par de claves: una **clave pública** y una **clave privada**. El proceso de autenticación funciona de la siguiente manera:

1. **Clave Pública**: Se almacena en el servidor remoto, en el archivo `authorized_keys`. Esta clave puede ser compartida libremente.
    
2. **Clave Privada**: Se guarda en el cliente (tu máquina local) y **nunca** debe ser compartida. Solo tú debes tener acceso a ella.

Durante la conexión, el servidor desafía al cliente para que demuestre que posee la clave privada correspondiente a la clave pública almacenada en el servidor. Si el cliente puede demostrarlo, la autenticación es exitosa y se establece la sesión.

### Generación de claves

Para generar un par de claves SSH en tu máquina local, puedes usar el siguiente comando:

```bash
ssh-keygen -t rsa -b 2048
```

Este comando generará dos archivos:

- **id_rsa**: Este es el archivo de la clave privada.
- **id_rsa.pub**: Este es el archivo de la clave pública.

Cuando se ejecuta el comando, se te pedirá que ingreses un nombre para los archivos y una frase de paso (opcional) para proteger la clave privada. Una vez que hayas generado el par de claves, puedes agregar la **clave pública** (`id_rsa.pub`) al archivo `~/.ssh/authorized_keys` en el servidor remoto para permitir la autenticación sin contraseña.

### Archivos SSH importantes

- **`id_rsa`**: Este archivo contiene la **clave privada**. No debe ser compartido ni transferido a otros sistemas.
- **`id_rsa.pub`**: Este archivo contiene la **clave pública**. Se debe copiar en el archivo `authorized_keys` del servidor remoto para permitir el acceso mediante clave pública.
- **`authorized_keys`**: Este archivo en el servidor remoto contiene las claves públicas autorizadas para acceder al sistema sin necesidad de contraseña. Cada clave pública en este archivo está asociada con un cliente autorizado.
### Formas de acceso

1. **Autenticación por contraseña**: Este es el método tradicional donde el cliente debe ingresar una contraseña para autenticar la conexión SSH. El servidor solicitará la contraseña

```bash
ssh usuario@direccion_ip_del_servidor
```

2. **Autenticación por clave pública/privada**: Utiliza un par de claves (como se describió anteriormente). El servidor verifica que la clave pública almacenada en el archivo `authorized_keys` corresponda con la clave privada del cliente.

```bash
ssh -i /ruta/a/tu/id_rsa usuario@direccion_ip_del_servidor
```

3. **Autenticación mediante agentes SSH (ssh-agent)**: Puedes usar un agente SSH para gestionar las claves privadas en lugar de tener que proporcionar la clave cada vez que te conectas. El agente mantiene las claves privadas en memoria.

```bash
eval $(ssh-agent)
ssh-add /ruta/a/tu/id_rsa
```

### Comandos dentro de SSH

Cuando te conectas a un servidor remoto con SSH, puedes ejecutar diversos comandos en el servidor. Algunos de los comandos más comunes son:

**Obtener archivos del servidor**: Puedes usar el comando `scp` (secure copy) para transferir archivos entre tu máquina local y el servidor remoto. Para copiar un archivo desde el servidor remoto a tu máquina local:

```bash
scp usuario@direccion_ip_del_servidor:/ruta/al/archivo /ruta/local
```

Este es el uso básico de `scp`, pero hay muchas formas de trabajar con este comando. veamos en una tabla algunos ejemplos:

| **Comando**                                                                                                               | **Descripción**                                                                                                                             |
| ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `scp usuario@direccion_ip:/ruta/remota/del/archivo /ruta/local`                                                           | Copiar un archivo desde el servidor remoto a tu máquina local.                                                                              |
| `scp -i /ruta/a/tu/id_rsa usuario@direccion_ip:/ruta/remota/del/archivo /ruta/local`                                      | Copiar un archivo desde el servidor remoto a tu máquina local usando una clave privada para la autenticación.                               |
| `scp -P puerto usuario@direccion_ip:/ruta/remota/del/archivo /ruta/local`                                                 | Copiar un archivo desde el servidor remoto a tu máquina local especificando un puerto diferente al estándar (22).                           |
| `scp -i /ruta/a/tu/id_rsa -P puerto usuario@direccion_ip:/ruta/remota/del/archivo /ruta/local`                            | Copiar un archivo desde el servidor remoto a tu máquina local usando una clave privada y un puerto específico.                              |
| `scp -r usuario@direccion_ip:/ruta/remota/del/directorio /ruta/local`                                                     | Copiar un directorio completo desde el servidor remoto a tu máquina local.                                                                  |
| `scp -r -i id_rsa usuario@direccion_ip:/ruta/remota/del/directorio /ruta/local`                                           | Copiar un directorio completo desde el servidor remoto a tu máquina local usando una clave privada para la autenticación.                   |
| `scp -r -i id_rsa -P puerto usuario@direccion_ip:/ruta/remota/del/directorio /ruta/local`                                 | Copiar un directorio completo desde el servidor remoto a tu máquina local usando una clave privada y especificando un puerto.               |
| `scp usuario@direccion_ip:/ruta/remota/del/archivo usuario@direccion_ip:/ruta/del/destino`                                | Copiar un archivo desde un servidor remoto a otro servidor remoto.                                                                          |
| `scp -i /ruta/a/tu/id_rsa usuario@direccion_ip:/ruta/remota/del/archivo usuario@direccion_ip:/ruta/del/destino`           | Copiar un archivo desde un servidor remoto a otro servidor remoto usando una clave privada para la autenticación.                           |
| `scp -i /ruta/a/tu/id_rsa -P puerto usuario@direccion_ip:/ruta/remota/del/archivo usuario@direccion_ip:/ruta/del/destino` | Copiar un archivo desde un servidor remoto a otro servidor remoto especificando un puerto y usando una clave privada para la autenticación. |

