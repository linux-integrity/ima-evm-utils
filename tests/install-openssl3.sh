#!/bin/bash

set -ex

if [ -z "$COMPILE_SSL" ]; then
    echo "Missing \$COMPILE_SSL!" >&2
    exit 1
fi

version=${COMPILE_SSL}

wget --no-check-certificate https://github.com/openssl/openssl/archive/refs/tags/${version}.tar.gz
tar --no-same-owner -xzf ${version}.tar.gz
cd openssl-${version}

if [ "$VARIANT" = "i386" ]; then
	echo "32-bit compilation"
	FLAGS="-m32 linux-generic32"
fi

./Configure $FLAGS no-engine no-dynamic-engine --prefix=/opt/openssl3 --openssldir=/opt/openssl3
# Uncomment for debugging
# perl configdata.pm --dump | grep engine
make -j$(nproc)
# only install apps and library
sudo make install_sw

cd ..
rm -rf ${version}.tar.gz
rm -rf openssl-${version}
