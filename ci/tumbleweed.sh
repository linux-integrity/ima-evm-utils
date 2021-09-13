#!/bin/sh
# Copyright (c) 2020 Petr Vorel <pvorel@suse.cz>
set -ex

if [ -z "$CC" ]; then
	echo "missing \$CC!" >&2
	exit 1
fi

case "$TSS" in
ibmtss) TSS="ibmtss-devel";;
tpm2-tss) TSS="tpm2-0-tss-devel";;
'') echo "Missing TSS!" >&2; exit 1;;
*) echo "Unsupported TSS: '$TSS'!" >&2; exit 1;;
esac

# clang has some gcc dependency
[ "$CC" = "gcc" ] || CC="gcc $CC"

zypper --non-interactive install --force-resolution --no-recommends \
	$CC $TSS \
	asciidoc \
	attr \
	autoconf \
	automake \
	diffutils \
	docbook_5 \
	docbook5-xsl-stylesheets \
	gzip \
	ibmswtpm2 \
	keyutils-devel \
	libattr-devel \
	libopenssl-devel \
	libtool \
	make \
	openssl \
	pkg-config \
	procps \
	sudo \
	vim \
	wget \
	which \
	xsltproc

zypper --non-interactive install --force-resolution --no-recommends \
	gnutls openssl-engine-libp11 softhsm || true

if [ -f /usr/lib/ibmtss/tpm_server -a ! -e /usr/local/bin/tpm_server ]; then
	ln -s /usr/lib/ibmtss/tpm_server /usr/local/bin
fi
