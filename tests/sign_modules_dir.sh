#!/bin/sh

verbose=""
if [ "$1" = "-v" ] ; then
	verbose="-v"
	shift 1
fi

dir=${1:-/lib/modules}

echo "Signing modules: $dir"

find $dir -name "*.ko" -type f -uid 0 -exec evmctl sign --imasig '{}' \;
find $dir ! -name "*.ko" -type f -uid 0 -exec evmctl sign --imahash '{}' \;

