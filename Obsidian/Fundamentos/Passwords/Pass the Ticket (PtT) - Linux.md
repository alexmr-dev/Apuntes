> Aunque no es común, los equipos **Linux** pueden conectarse a **Active Directory** para proporcionar una gestión de identidades centralizada e integrarse con los sistemas de la organización, permitiendo a los usuarios tener una única identidad para autenticarse tanto en equipos Linux como Windows. Un equipo Linux conectado a **Active Directory** comúnmente utiliza **Kerberos** como sistema de autenticación. Supongamos que este es el caso y logramos comprometer un equipo Linux conectado a Active Directory. En ese caso, podríamos intentar encontrar **tickets Kerberos** para suplantar a otros usuarios y ganar más acceso a la red. Un sistema Linux puede configurarse de diversas maneras para almacenar **tickets Kerberos**.

Un equipo Linux no conectado a Active Directory también puede usar **tickets Kerberos** en scripts o para autenticarse en la red. No es necesario estar unido al dominio para usar tickets Kerberos en un equipo Linux.

### Kerberos en Linux

Tanto **Windows** como **Linux** utilizan el mismo proceso para solicitar un **Ticket Granting Ticket (TGT)** y un **Service Ticket (TGS)**. Sin embargo, la forma en que almacenan la información del ticket puede variar dependiendo de la distribución de Linux y su implementación.

En la mayoría de los casos, los equipos Linux almacenan los tickets Kerberos como archivos **ccache** en el directorio `/tmp`. De forma predeterminada, la ubicación del ticket Kerberos se guarda en la variable de entorno **KRB5CCNAME**. Otro uso común de Kerberos en Linux es con **archivos keytab**. Un **keytab** es un archivo que contiene pares de **principales Kerberos** y **claves cifradas** (que se derivan de la contraseña de Kerberos). Puedes usar un archivo **keytab** para autenticarte en varios sistemas remotos utilizando Kerberos sin necesidad de introducir una contraseña. Sin embargo, cuando cambias tu contraseña, debes volver a crear todos tus archivos **keytab**.

