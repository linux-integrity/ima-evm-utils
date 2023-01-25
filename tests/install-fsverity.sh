#!/bin/sh

git clone https://git.kernel.org/pub/scm/fs/fsverity/fsverity-utils.git
cd fsverity-utils
CC=gcc make -j$(nproc)
cd ..
