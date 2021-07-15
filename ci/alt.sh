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
		docbook-style-xsl \
		libattr-devel \
		libkeyutils-devel \
		libssl-devel \
		openssl \
		openssl-gost-engine \
		rpm-build \
		wget \
		xsltproc \
		xxd \
	&& control openssl-gost enabled
