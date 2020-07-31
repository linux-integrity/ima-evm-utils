#!/bin/sh

git clone https://github.com/tpm2-software/tpm2-tss.git
cd tpm2-tss
./bootstrap
./configure
make -j$(nproc)
sudo make install
sudo ldconfig
cd ..
rm -rf tpm2-tss

git clone https://github.com/tpm2-software/tpm2-tools.git
cd tpm2-tools
./bootstrap && ./configure --prefix=/usr
make -j$(nproc)
sudo make install
cd ..
rm -rf tpm2-tools
