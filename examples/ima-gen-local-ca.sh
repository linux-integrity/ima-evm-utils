#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later

DIR=$(dirname "$0")

cd "${DIR}" 1>/dev/null || exit 1

. ./functions

#default key algorithm
keyalgo=rsa:2048

if [ "$1" = "-?" ] || [ "$1" = "--help" ]; then
	cat <<_EOF_
Create a local CA with a given key algorithm.

Usage: $0 [options] keyalgo

The following key algorithms are supported:
  ${SUPPORTED_ALGORITHMS}

The following options are supported:
    -?, --help  : Display this help screen and exit

_EOF_
	exit 0
fi

if [ "$1" != "" ]; then
	keyalgo="$1"
fi

ima_gen_localca "${keyalgo}"
exit $?
