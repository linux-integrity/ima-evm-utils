#!/bin/sh -ex
# SPDX-License-Identifier: GPL-2.0-only
#
# Install build env for ALT Linux

apt-get update -y

# rpm-build brings basic build environment with gcc, make, autotools, etc.
apt-get install -y \
		$CC \
		$TSS \
		asciidoc \
		attr \
		e2fsprogs \
		fsverity-utils-devel \
		gnutls-utils \
		libattr-devel \
		libkeyutils-devel \
		libp11 \
		libssl-devel \
		openssl \
		openssl-gost-engine \
		rpm-build \
		softhsm \
		util-linux \
		wget \
		xsltproc \
		xxd \
	&& control openssl-gost enabled

# apt-get install -y pkcs11-provider || true
