#!/bin/sh -ex

# No need to run via sudo if we already have permissions.
# Also, some distros do not have sudo configured for root:
#   `root is not in the sudoers file.  This incident will be reported.'
if [ -w /usr/local/bin ]; then
	SUDO=
else
	SUDO=sudo
fi

version=1637

wget --no-check-certificate https://sourceforge.net/projects/ibmswtpm2/files/ibmtpm${version}.tar.gz/download
mkdir ibmtpm$version
cd ibmtpm$version
tar --no-same-owner -xvzf ../download
cd src
make -j$(nproc)
$SUDO cp tpm_server /usr/local/bin/
cd ../..
