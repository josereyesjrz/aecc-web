# aecc-web
Development of the new AECC website. Project for software engineering class.

# Para resetear la base de datos
`cd database/`

`sqlite3 database.db < schema.sql`

en el archivo de database.

# Requirements

## Usar python2.7

`braintree`

`flask`

`flask-wtf`

`flask-gravatar`

`itsdangerous`

`flask-mail`

`scrypt`

`python-dotenv`


Para instalarlos:
`pip install -r requirement.txt`

Tmabién necesita instalar:
`sqlite3`

# Antes de correr el website
`$ export APP_MAIL_USERNAME='InsertEmailAddressHere'`
`$ export APP_MAIL_PASSWORD='InsertEmailPasswordHere'`

# Error al instalar scrypt
Algo parecido a:
`scrypt-1.1.6/lib/crypto/crypto_aesctr.c:38:25: fatal error: openssl/aes.h: Datei oder Verzeichnis nicht gefunden
#include <openssl/aes.h>  `
Installe libssl-dev:
`sudo apt-get install libssl-dev`
[Explicación](https://askubuntu.com/questions/647143/problems-installing-scrypt-0-7-1-on-ubuntu-into-a-virtual-environment)

