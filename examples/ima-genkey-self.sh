#!/bin/sh

GENKEY=x509_evm.genkey

cat << __EOF__ >$GENKEY
[ req ]
default_bits = 1024
distinguished_name = req_distinguished_name
prompt = no
string_mask = utf8only
x509_extensions = myexts

[ req_distinguished_name ]
O = `hostname`
CN = `whoami` signing key
emailAddress = `whoami`@`hostname`

[ myexts ]
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
__EOF__

openssl req -x509 -new -nodes -utf8 -sha1 -days 3650 -batch -config $GENKEY \
		-outform DER -out x509_evm.der -keyout privkey_evm.pem

openssl rsa -pubout -in privkey_evm.pem -out pubkey_evm.pem

