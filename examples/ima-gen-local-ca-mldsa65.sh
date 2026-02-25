#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later

GENKEY=ima-local-ca.genkey

cat << __EOF__ >$GENKEY
[ req ]
distinguished_name = req_distinguished_name
prompt = no
string_mask = utf8only
x509_extensions = v3_ca

[ req_distinguished_name ]
O = IMA-CA
CN = IMA/EVM certificate signing key
emailAddress = ca@ima-ca

[ v3_ca ]
basicConstraints=CA:TRUE
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
keyUsage = cRLSign, keyCertSign
__EOF__

openssl req -new -x509 -utf8 -days 3650 -batch -config $GENKEY \
		-outform DER -out ima-local-ca.x509 -keyout ima-local-ca.priv \
		-newkey mldsa65

openssl x509 -inform DER -in ima-local-ca.x509 -out ima-local-ca.pem
