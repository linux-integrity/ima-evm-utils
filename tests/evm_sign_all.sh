#!/bin/sh

verbose=""
if [ "$1" = "-v" ] ; then
	verbose="-v"
	shift 1
fi

dir=${1:-/}

echo "Label: $dir"

find $dir \( -fstype rootfs -o -fstype ext3 -o -fstype ext4 \) ! -path "/lib/modules/*" -type f -uid 0 -exec evmctl sign --imahash $verbose '{}' \;
find /lib/modules ! -name "*.ko" -type f -uid 0 -exec evmctl sign --imahash $verbose '{}' \;
# security.ima needs to have signature for modules
find /lib/modules -name "*.ko" -type f -uid 0 -exec evmctl sign --imasig $verbose '{}' \;

