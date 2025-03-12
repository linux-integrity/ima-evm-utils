#!/bin/sh
# Copyright (c) 2020 Petr Vorel <pvorel@suse.cz>
set -e

if [ -z "$CC" ]; then
	echo "missing \$CC!" >&2
	exit 1
fi

# Install crb for tss2-devel and tpm2-tss-devel on CentOS stream 9
if [ -f /etc/centos-release ]; then
	yum -y install dnf-plugins-core
	yum -y config-manager --set-enabled crb
fi

case "$TSS" in
ibmtss) TSS="tss2-devel";;
tpm2-tss) TSS="tpm2-tss-devel";;
'') echo "Missing TSS!" >&2; exit 1;;
*) echo "Unsupported TSS: '$TSS'!" >&2; exit 1;;
esac

# ibmswtpm2 requires gcc
[ "$CC" = "gcc" ] || CC="gcc $CC"

yum -y install \
	$CC $TSS \
	asciidoc \
	attr \
	autoconf \
	automake \
	diffutils \
	docbook-xsl \
	e2fsprogs \
	git-core \
	gnutls-utils \
	gzip \
	keyutils-libs-devel \
	kmod \
	libattr-devel \
	libtool \
	libxslt \
	make \
	openssl \
	openssl-devel \
	openssl-pkcs11 \
	pkg-config \
	procps \
	sudo \
	util-linux \
	vim-common \
	wget \
	which \
	zstd \
	systemd \
	keyutils \
	e2fsprogs \
	acl \
	libcap

yum -y install docbook5-style-xsl || true
yum -y install swtpm || true

# SoftHSM is available via EPEL on CentOS
if [ -f /etc/centos-release ]; then
	yum -y install epel-release
fi
yum -y install softhsm || true
yum -y install softhsm pkcs11-provider || true
# openssl-devel-engine is available on Fedora and not on CentOS, but CentOS
# in future might split the package too.
yum -y install openssl-devel-engine || true

# haveged is available via EPEL on CentOS stream8.
yum -y install haveged || true

./tests/install-fsverity.sh
./tests/install-mount-idmapped.sh
