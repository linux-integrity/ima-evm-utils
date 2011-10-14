#!/bin/sh

dir=${1:-/}

echo "Fixing dir: $dir"

find $dir \( -fstype rootfs -o -fstype ext3 -o -fstype ext4 \) -type f -uid 0 -exec openclose '{}' \;

