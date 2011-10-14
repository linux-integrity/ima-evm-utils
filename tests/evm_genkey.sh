#!/bin/sh

keyctl add user kmk "testing123" @u
key=`keyctl add encrypted evm-key "new user:kmk 32" @u`
keyctl print $key >/etc/keys/evm-key

keyctl list @u

