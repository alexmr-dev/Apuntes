---

---
-----
> El Sistema de Archivos de Red (NFS, por sus siglas en inglés) es un sistema de archivos de red desarrollado por Sun Microsystems y tiene el mismo propósito que [[SMB - Server Message Block]]. Su objetivo es acceder a sistemas de archivos a través de una red como si fueran locales. Sin embargo, utiliza un protocolo completamente diferente. NFS se utiliza entre sistemas Linux y Unix. Esto significa que los clientes NFS no pueden comunicarse directamente con los servidores SMB. **NFS** es un estándar de Internet que regula los procedimientos en un sistema de archivos distribuido. Mientras que la versión 3.0 del protocolo NFS (NFSv3), que ha estado en uso durante muchos años, autentica la computadora cliente, esto cambia con NFSv4. Aquí, al igual que con el protocolo SMB de Windows, el usuario debe autenticarse.

### Configuración por defecto

El archivo `/etc/exports` contiene una tabla de archivos de sistema físicos en un servidor NFS accesible por los clientes. El archivo de exportaciones predeterminado también contiene algunos ejemplos de cómo configurar las comparticiones NFS. Primero, se especifica la carpeta y se pone a disposición de otros, luego los derechos que tendrán sobre esta compartición NFS se asignan a un host o una subred. Finalmente, se pueden agregar opciones adicionales a los hosts o subredes.

| Opción           | Descripción                                                                                                                                          |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| rw               | Permisos de lectura y escritura.                                                                                                                     |
| ro               | Permisos solo de lectura.                                                                                                                            |
| sync             | Transferencia de datos síncrona. (Un poco más lenta)                                                                                                 |
| async            | Transferencia de datos asíncrona. (Un poco más rápida)                                                                                               |
| secure           | No se utilizarán puertos superiores a 1024.                                                                                                          |
| insecure         | Se utilizarán puertos superiores a 1024.                                                                                                             |
| no_subtree_check | Esta opción desactiva la comprobación de los árboles de subdirectorios.                                                                              |
| root_squash      | Asigna todos los permisos de archivos del UID/GID de root (0) al UID/GID de anónimo, lo que impide que root acceda a los archivos en un montaje NFS. |

### ExportFS

```shell-session
root@nfs:~# echo '/mnt/nfs  10.129.14.0/24(sync,no_subtree_check)' >> /etc/exports
root@nfs:~# systemctl restart nfs-kernel-server 
root@nfs:~# exportfs

/mnt/nfs      	10.129.14.0/24
```

Con esto, hemos compartido la carpeta `/mnt/nfs` a la subnet `10.129.14.0/24` con la configuración vista arriba. Esto significa que todos los hosts en la red tendrán acceso a montar (mount) este NFS e inspeccionar el contenido de dicho directorio.

### Configuración peligrosa
| Opción             | Descripción                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| rw                 | Permisos de lectura y escritura.                                             |
| insecure           | Se utilizarán puertos superiores a 1024.                                    |
| nohide             | Si se montó otro sistema de archivos debajo de un directorio exportado, este directorio se exporta por su propia entrada de exportaciones. |
| no_root_squash     | Todos los archivos creados por root se mantienen con el UID/GID 0.           |
### Footprinting al servicio

Cuando hacemos footprinting al servicio NFS, los puertos TCP **111** y **2049** son esenciales. Podemos recolectar información del servicio NFS vía RPC. El script `rpcinfo` de nmap (NSE) recopila una lista de todos los servicios RPC que se están ejecutando, sus nombres y descripciones, además de los puertos que usan. Esto nos permite comprobar si el target está conectado a la red en todos los puertos requeridos. Además, para **NFS** , nmap tiene vasrios scripts NSE que pueden ser usados para los escaneos. Por ejemplo:

```shell-session
amr251@htb[/htb]$ sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-19 17:37 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00021s latency).

PORT     STATE SERVICE VERSION
111/tcp  open  rpcbind 2-4 (RPC #100000)
...
```

Una vez hemos descubierto un servicio NFS, podemos montarlo en nuestra máquina local. Para esto, podemos crear una carpeta vacía donde se montará el NFS share. Una vez montado, podemos navegar por él y ver los contenidos.

```bash
$ showmount -e 10.129.14.128
```

Lo montamos:

```shell-session
amr251@htb[/htb]$ mkdir target-NFS
amr251@htb[/htb]$ sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
amr251@htb[/htb]$ cd target-NFS
amr251@htb[/htb]$ tree .

.
└── mnt
    └── nfs
        ├── id_rsa
        ├── id_rsa.pub
        └── nfs.share

2 directories, 3 files
```

Ahora ya podemos listar lo que queramos dentro de nuestra carpeta local. Recordar desmontar después de terminar:

```bash
sudo umount ./target-NFS
```