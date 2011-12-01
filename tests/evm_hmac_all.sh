#!/bin/sh

verbose=""
if [ "$1" = "-v" ] ; then
	verbose="-v"
	shift 1
fi

dir=${1:-/}

echo "Label: $dir"

find $dir \( -fstype rootfs -o -fstype ext3 -o -fstype ext4 \)  \( -type f -o -type d \) -uid 0 -exec evmctl hmac --imahash $verbose '{}' \;

