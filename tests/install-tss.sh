#!/bin/sh

set -ex
git clone https://github.com/kgoldman/ibmtss
cd ibmtss
autoreconf -i && ./configure --disable-tpm-1.2 --disable-hwtpm && make -j"$(nproc)" && sudo make install
cd ..
rm -rf ibmtss
