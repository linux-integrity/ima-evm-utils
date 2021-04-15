#!/bin/sh
set -ex

version=1637

wget --no-check-certificate https://sourceforge.net/projects/ibmswtpm2/files/ibmtpm${version}.tar.gz/download
mkdir ibmtpm$version
cd ibmtpm$version
tar --no-same-owner -xvzf ../download
cd src
make -j$(nproc)
sudo cp tpm_server /usr/local/bin/
cd ../..
