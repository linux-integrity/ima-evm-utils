#!/bin/sh

verbose=""
if [ "$1" = "-v" ] ; then
	verbose="-v"
	shift 1
fi

dir=${1:-/lib/modules}

echo "Signing modules: $dir"

find $dir -name "*.ko" -type f -exec evmctl sign --imasig $verbose '{}' \;

