#!/bin/sh

set -ex
git clone https://git.code.sf.net/p/ibmtpm20tss/tss
cd tss
autoreconf -i && ./configure --disable-tpm-1.2 --disable-hwtpm && make -j$(nproc) && sudo make install
cd ..
rm -rf tss
