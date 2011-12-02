#!/bin/sh

verbose=""
if [ "$1" = "-v" ] ; then
	verbose="-v"
	shift 1
fi

dir=${1:-/}

echo "Label: $dir"

find $dir \( -fstype rootfs -o -fstype ext3 -o -fstype ext4 \) -type f -exec evmctl sign --imahash $verbose '{}' \;

