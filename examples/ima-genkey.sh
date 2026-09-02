#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later

DIR=$(dirname "$0")

cd "${DIR}" 1>/dev/null || exit 1

. ./functions

#default key algorithm
keyalgo=rsa:2048

if [ "$1" = "-?" ] || [ "$1" = "--help" ]; then
	cat <<_EOF_
Create an EVM/IMA file signing key with a given algorithm.

Usage: $0 [options] keyalgo [filename suffix]

The following key algorithms are supported:
  ${SUPPORTED_ALGORITHMS}

Providing a filename suffix will prevent the certificate from being
overwritten.

The following options are supported:
    -?, --help  : Display this help screen and exit


_EOF_
	exit 0
fi

if [ "$1" != "" ]; then
	keyalgo="$1"
fi

if [ "$2" != "" ]; then
	keyname_prefix="$2"
	if [ -z ${keyname_prefix} ]; then
		ima_gen_signing_key "${keyalgo}"
	else
		ima_gen_signing_key "${keyalgo}" "${keyname_prefix}"
	fi
else
	ima_gen_signing_key "${keyalgo}"
fi
exit $?
