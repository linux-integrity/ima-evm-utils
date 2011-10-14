#!/bin/sh

# import EVM HMAC key
keyctl clear @u
keyctl add user kmk "testing123" @u
keyctl add encrypted evm-key "load `cat /etc/keys/evm-key`" @u

# import Moule public key
mod_id=`keyctl newring _module @u`
evmctl import /etc/keys/pubkey_evm.pem $mod_id

# import IMA public key
ima_id=`keyctl newring _ima @u`
evmctl import /etc/keys/pubkey_evm.pem $ima_id

# import EVM public key
evm_id=`keyctl newring _evm @u`
evmctl import /etc/keys/pubkey_evm.pem $evm_id

# enable EVM
echo "1" > /sys/kernel/security/evm

# enable module checking
echo "1" > /sys/kernel/security/ima/module_check

