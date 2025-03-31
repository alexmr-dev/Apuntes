---

---
----
- Tags: #bash #TCP/IP #UDP
------
## ¿Qué es Netcat? 

> Una herramienta versátil de red para leer y escribir datos a través de conexiones TCP o UDP.
## Sintaxis básica

Modo cliente (connect to somewhere):
```none
nc [opciones] [dirección IP/nombre del host] [puerto]
```

Modo servidor (listen for inbound):
```none
nc -l -p port [opciones] [nombre del host] [puerto]
```

## Opciones y parámetros principales
 
 - **`-l`**: Escucha de conexiones entrantes (modo servidor). 
 - **`-z`**: Escaneo de puertos sin enviar datos. 
 - **`-v`**: Modo verbose, muestra detalles de la conexión. 
 - **`-p`**: Especifica el puerto. 
 - **`-e`**: Ejecuta un comando o shell en la conexión.
 - **`-n`**: Forzar uso de IPs, deshabilitando DNS

## Casos de uso comunes

#### Pruebas de conectividad 

1. **Escanear un puerto específico**: ```bash nc -zv IP PUERTO```
2. **Ponerse en modo escucha en un puerto**: ```nc -nvlp 443```
3. 