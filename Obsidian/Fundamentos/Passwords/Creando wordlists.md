> Dado que muchas personas prefieren mantener sus contraseñas lo más simples posible, a pesar de las políticas de seguridad, es posible crear reglas para generar contraseñas débiles. Según estadísticas de WPengine, la mayoría de las contraseñas no superan los diez caracteres.

Hashcat permite crear listas de contraseñas personalizadas aplicando **reglas de mutación** sobre palabras base.
### Reglas básicas de mutación (Hashcat)

| Función | Descripción                                         |
| ------- | --------------------------------------------------- |
| `:`     | No hace nada (mantiene la palabra original)         |
| `l`     | Convierte todas las letras a minúsculas             |
| `u`     | Convierte todas las letras a mayúsculas             |
| `c`     | Capitaliza la primera letra, el resto en minúsculas |
| `sXY`   | Sustituye todas las apariciones de `X` por `Y`      |
| `$!`    | Añade el carácter `!` al final de la palabra        |
### Reglas - Hashcat

```shell-session
amr251@htb[/htb]$ hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
amr251@htb[/htb]$ cat mut_password.list

password
Password
passw0rd
Passw0rd
p@ssword
P@ssword
P@ssw0rd
password!
Password!
passw0rd!
p@ssword!
Passw0rd!
P@ssword!
p@ssw0rd!
P@ssw0rd!
```

**Hashcat** y **John the Ripper** incluyen listas de reglas preconstruidas que se pueden usar para generar contraseñas o descifrarlas. Una de las más utilizadas es la regla **`best64.rule`**, ya que con frecuencia produce buenos resultados. `dive.rule` es otro conjunto de reglas poderoso. 

Podemos usar otra herramienta llamada `CeWL` para escanear palabras potenciales de una compañía y guardarlas en una lista aparte. Al crear esta lista, es posible especificar algunos **parámetros clave**, como por ejemplo:

- **`-d`**: Nivel de profundidad del spider (rastreo).
- **`-m`**: Longitud mínima de las palabras extraídas.
- **`--lowercase`**: Almacena las palabras encontradas en minúsculas.
- **`-w`**: Archivo donde se guardarán los resultados.

```shell-session
amr251@htb[/htb]$ cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
amr251@htb[/htb]$ wc -l inlane.wordlist

326
```

Aquí hay un resumen de comandos para mutaciones de contraseñas:

|**Comando**|**Descripción**|
|---|---|
|`cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist`|Genera un diccionario a partir de palabras clave encontradas en un sitio web.|
|`hashcat --force password.list -r custom.rule --stdout > mut_password.list`|Genera una lista de contraseñas basadas en reglas con Hashcat.|
|`./username-anarchy -i /path/to/listoffirstandlastnames.txt`|Utiliza la herramienta username-anarchy para generar posibles nombres de usuario a partir de una lista de nombres y apellidos.|
|`curl -s https://fileinfo.com/filetypes/compressed \| html2text \| awk '{print tolower($1)}' \| grep "\." \| tee -a compressed_ext.txt`|Usa comandos de Linux para extraer extensiones de archivos comprimidos desde la web.|
