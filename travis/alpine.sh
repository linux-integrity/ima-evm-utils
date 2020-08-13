#!/bin/sh
# Copyright (c) 2020 Petr Vorel <pvorel@suse.cz>
set -ex

if [ -z "$CC" ]; then
	echo "missing \$CC!" >&2
	exit 1
fi

case "$TSS" in
ibmtss) echo "No IBM TSS package, will be installed from git" >&2; TSS=;;
tpm2-tss) TSS="tpm2-tss-dev";;
'') echo "Missing TSS!" >&2; exit 1;;
*) echo "Unsupported TSS: '$TSS'!" >&2; exit 1;;
esac

# ibmswtpm2 requires gcc
[ "$CC" = "gcc" ] || CC="gcc $CC"

apk update

apk add \
	$CC $TSS \
	asciidoc \
	attr \
	attr-dev \
	autoconf \
	automake \
	diffutils \
	docbook-xml \
	docbook-xsl \
	keyutils-dev \
	libtool \
	libxslt \
	linux-headers \
	make \
	musl-dev \
	openssl \
	openssl-dev \
	pkgconfig \
	procps \
	sudo \
	wget \
	which \
	xxd

if [ ! "$TSS" ]; then
	apk add git
	../tests/install-tss.sh
fi
