#!/bin/sh

git clone https://git.kernel.org/pub/scm/linux/kernel/git/ebiggers/fsverity-utils.git
cd fsverity-utils
CC=gcc make -j$(nproc)
cd ..
