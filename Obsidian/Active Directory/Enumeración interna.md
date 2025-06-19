
Es habitual comenzar una auditoría **desde un host Linux sin credenciales de dominio**. Muchas organizaciones prefieren ver qué se puede lograr desde una posición ciega, lo que simula escenarios reales como:

- Un atacante que compromete la red desde Internet (phishing, RCE, VPN expuesta...).    
- Acceso físico (invitado malicioso, acceso a un puerto LAN).    
- Acceso Wi-Fi desde fuera del edificio.    
- Un empleado desleal o comprometido.    

🟡 **Según el resultado**, el cliente puede decidir facilitarte:
- Un **host unido al dominio**, o    
- Unas **credenciales limitadas** para acelerar y ampliar la auditoría.

| Punto clave                      | Descripción |
|----------------------------------|-------------|
| **Usuarios de AD (AD Users)**    | Enumerar cuentas válidas que puedan ser objetivo de ataques como password spraying o ASREPRoasting. |
| **Equipos unidos al dominio**    | Especialmente los críticos: Controladores de Dominio, servidores de ficheros, SQL, web, correo (Exchange), etc. |
| **Servicios clave**              | Detectar servicios como Kerberos (88/TCP), LDAP (389/TCP), NetBIOS (137/139), DNS (53), SMB (445), que indiquen entorno Windows-AD. |
| **Equipos y servicios vulnerables** | Buscar “quick wins” — hosts con vulnerabilidades explotables que te permitan obtener acceso inicial (SMB abierto, RCE conocida, credenciales por defecto, etc.). |

🛠️ **Importante**: guarda los resultados de las herramientas (`nmap`, `smbclient`, `crackmapexec`, etc.) y capturas clave. Todo lo que documentes aquí puede justificar el acceso posterior o elevar la criticidad del informe.

### 🎯 TTPs (Tácticas, Técnicas y Procedimientos) para enumerar Active Directory

Enumerar un entorno de Active Directory **sin un plan claro puede ser abrumador**. Hay **una enorme cantidad de datos** en AD y si lo haces todo de golpe, puedes perder información relevante o duplicar trabajo inútil.

🔸 Lo recomendable es **trabajar por etapas**, desarrollando tu propia **metodología repetible** a medida que ganes experiencia. Aunque cada pentester tiene su estilo, el flujo inicial suele seguir una misma lógica.

##### 🧭 Metodología general propuesta

1. **🎯 Establece un plan**    
    - Define claramente qué vas a buscar en cada fase.        
    - No te limites a una sola herramienta, prueba varias para ver diferencias, sintaxis y resultados.
        
2. **🔎 Detección pasiva de hosts**    
    - Escucha el entorno sin generar tráfico activo (por ejemplo: ARP, mDNS, LLMNR).        
    - Ideal en escenarios stealth o con restricciones.
        
3. **📡 Validación activa de hosts detectados**    
    - Escaneos activos (`nmap`, `smbclient`, `ldapsearch`, etc.).        
    - Identificar servicios, nombres de máquina, posibles vulnerabilidades.
        
4. **🔍 Recolección de información interesante**    
    - Consultas LDAP, detección de sesiones activas, shares abiertos, SPNs, GPOs, etc.        
    - Guardar todo lo que tenga potencial de explotación o acceso a datos internos.
        
5. **🧠 Revisión y planificación**    
    - Evalúa lo obtenido: ¿tenemos ya una cuenta de usuario o credenciales válidas?        
    - Si es así, comenzar con **enumeración autenticada** desde tu host atacante (Linux) o pivotar a una máquina unida al dominio.

En auditorías black-box, conviene **escuchar primero la red** con herramientas como **Wireshark** o **tcpdump**, antes de lanzar escaneos.
Aunque en redes conmutadas solo vemos el tráfico del dominio de broadcast, podemos identificar:
- IPs activas vía **ARP**    
- Nombres de host mediante **mDNS/LLMNR**    
- Tráfico que indica presencia de **Active Directory** (LDAP, Kerberos)   

Esto ayuda a entender la red sin generar ruido y planificar los siguientes pasos.

