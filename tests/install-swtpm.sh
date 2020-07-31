#!/bin/sh

set -ex
wget https://sourceforge.net/projects/ibmswtpm2/files/ibmtpm1332.tar.gz/download
mkdir ibmtpm1332
cd ibmtpm1332
tar -xvzf ../download
cd src
make -j$(nproc)
sudo cp tpm_server /usr/local/bin/
cd ../..
