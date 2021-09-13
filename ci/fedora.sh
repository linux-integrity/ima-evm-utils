#!/bin/sh
# Copyright (c) 2020 Petr Vorel <pvorel@suse.cz>
set -e

if [ -z "$CC" ]; then
	echo "missing \$CC!" >&2
	exit 1
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
	gnutls-utils \
	gzip \
	keyutils-libs-devel \
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
	vim-common \
	wget \
	which

yum -y install docbook5-style-xsl || true
yum -y install swtpm || true

# SoftHSM is available via EPEL on CentOS
if [ -f /etc/centos-release ]; then
	yum -y install epel-release
fi
yum -y install softhsm || true