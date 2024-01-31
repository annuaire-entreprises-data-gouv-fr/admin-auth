#!/bin/sh

openssl genrsa > privkey.pem
openssl req -new -x509 -key privkey.pem -config ext.conf > fullchain.pem
