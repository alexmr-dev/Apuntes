> Cosas de redes en un futuro aquí...

### Transferir archivos

La forma más común es usar `wget` o `scp`, una vez tengamos credenciales ssh válidas en el host remoto. Podemos obtener un archivo con `scp` de esta forma:

```shell-session
amr251@htb[/htb]$ scp linenum.sh user@remotehost:/tmp/linenum.sh

user@remotehost's password: *********
linenum.sh
```

Sin embargo, en ocasiones no podremos obtener el archivo de forma convencional por algunos motivos como por ejemplo, que el host tiene activada una protección de firewall que nos impide descargar un archivo. En este caso, podemos utilizar `base64` para encodear el fichero en base64 y después, decodear lo obtenido en local. Veamos este ejemplo:

```shell-session
amr251@htb[/htb]$ base64 shell -w 0

f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU
```

Ahora, copiamos el string obtenido y usando `base64 -d <...>; echo` lo decodeamos. 

Validar el archivo es importante para comprobar que lo que hemos descargado tiene la integridad en todo momento. Podemos usar `md5` para comprobar que los hashes coinciden. Es decir, usar `md5 archivo` en el host remoto y luego, en local, y verificar que son idénticos. 