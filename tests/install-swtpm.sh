#!/bin/bash -ex

# No need to run via sudo if we already have permissions.
# Also, some distros do not have sudo configured for root:
#   `root is not in the sudoers file.  This incident will be reported.'
if [ -w /usr/local/bin ]; then
	SUDO=
else
	SUDO=sudo
fi

git clone https://git.code.sf.net/p/ibmswtpm2/tpm2
pushd tpm2/src 1>/dev/null || exit 1
make -j"$(nproc)"
$SUDO cp tpm_server /usr/local/bin/
popd 1>/dev/null
