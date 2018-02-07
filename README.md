# aecc-web
Development of the new AECC website. Project for software engineering class.

# Usar python2.7

Usar "pip install -r requirement.txt"
`pip install Flask`

`pip install Flask-WTF`

`pip install Flask-Gravatar`

# Para encriptar passwords
`pip install passlib`

# Para email confirmation
pip install itsdangerous
pip install Flask-Mail

# Antes de correr el website
$ export APP_MAIL_USERNAME='InsertEmailAddressHere'
$ export APP_MAIL_PASSWORD='InsertEmailPasswordHere'

#Si te sale un error como este(paso en ubuntu 17.10)  
`scrypt-1.1.6/lib/crypto/crypto_aesctr.c:38:25: fatal error: openssl/aes.h: Datei oder Verzeichnis nicht gefunden
#include <openssl/aes.h>  `
utiliza  este comando
`sudo apt-get install libssl-dev`
explicacion
https://askubuntu.com/questions/647143/problems-installing-scrypt-0-7-1-on-ubuntu-into-a-virtual-environment