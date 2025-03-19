#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# ima-evm-utils kernel tests bash functions
#
# Copyright (C) 2025 Huawei Technologies Duesseldorf GmbH
#
# Author: Roberto Sassu <roberto.sassu@huawei.com>

RET_INVALID_RULE=$((0x0001))
RET_RULE_OVERLAP=$((0x0002))
RET_SAME_RULE_EXISTS=$((0x0004))

export PATH=$PWD/../../src:$PWD/..:$PWD:$PATH
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH
. ../functions.sh

get_xattr() {
	local format="hex"

	if [ "$1" = "security.selinux" ]; then
		format="text"
	fi

	getfattr -n "$1" -e "$format" -d "$2" 2> /dev/null | awk -F "=" \
		'$1 == "'"$1"'" {if ("'"$format"'" == "hex") {
					v=substr($2, 3);
				 } else {
					split($2, temp, "\"");
					v=temp[2]
				 };
				 print v}'
}

check_load_ima_rule() {
	local result new_policy color
	local new_rule="$1"
	local key_path="$2"
	local mountpoint="$3"

	echo -e "$new_rule\n$(cat /sys/kernel/security/ima/policy)" | ima_policy_check.awk
	result=$?

	if [ $((result & RET_INVALID_RULE)) -eq $RET_INVALID_RULE ]; then
		echo "${RED}Invalid rule${NORM}"
		return "$HARDFAIL"
	fi

	if [ $((result & RET_RULE_OVERLAP)) -eq $RET_RULE_OVERLAP ]; then
		color=${YELLOW}
		if [ -n "$TST_ENV" ]; then
			color=${RED}
		fi

		echo "${color}Possible interference with existing IMA policy rule${NORM}"
		if [ -n "$TST_ENV" ]; then
			return "$HARDFAIL"
		fi
	fi

	if [ $((result & RET_SAME_RULE_EXISTS)) -eq $RET_SAME_RULE_EXISTS ]; then
		return "$OK"
	fi

	if ! new_policy=$(mktemp -p "$mountpoint"); then
		echo "${RED}Failed to create temporary file for IMA policy${NORM}"
		return "$FAIL"
	fi

	echo "$new_rule" > "$new_policy"
	if ! evmctl sign -o -a sha256 --imasig --key "$key_path" "$new_policy" &> /dev/null; then
		echo "${RED}Failed to sign IMA policy${NORM}"
		return "$FAIL"
	fi

	if ! echo "$new_policy" > /sys/kernel/security/ima/policy; then
		rm -f "$new_policy"
		echo "${RED}Failed to set IMA policy${NORM}"
		return "$FAIL"
	fi
	rm -f "${new_policy}"

	return "$OK"
}

get_private_key() {
	local key_path
	local key_path_copy="$1"

	if [ -n "$TST_KEY_PATH" ]; then
		if [ "${TST_KEY_PATH:0:1}" != "/" ]; then
			echo "${RED}Absolute path required for the kernel signing key${NORM}"
			return "$FAIL"
		fi

		if [ ! -f "$TST_KEY_PATH" ]; then
			echo "${RED}Kernel signing key not found in $TST_KEY_PATH${NORM}"
			return "$FAIL"
		fi

		key_path="$TST_KEY_PATH"
	elif [ -f "$PWD/../../signing_key.pem" ]; then
		key_path="$PWD/../../signing_key.pem"
	elif [ -f "$PWD/../../signing_key.der" ]; then
		key_path="$PWD/../../signing_key.der"
	elif [ -f "/lib/modules/$(uname -r)/source/certs/signing_key.pem" ]; then
		key_path="/lib/modules/$(uname -r)/source/certs/signing_key.pem"
	elif [ -f "/lib/modules/$(uname -r)/build/certs/signing_key.pem" ]; then
		key_path="/lib/modules/$(uname -r)/build/certs/signing_key.pem"
	else
		echo "${CYAN}Kernel signing key not found${NORM}"
		return "$SKIP"
	fi

	if openssl pkey -inform der -in "$key_path" -text &> /dev/null; then
		openssl pkey -in "$key_path" -out "$key_path_copy" -outform pem
	else
		cat "$key_path" > "$key_path_copy"
	fi

	result=$?
	if [ $result -ne 0 ]; then
		echo "${RED}Failed to convert/copy the kernel signing key${NORM}"
		return "$FAIL"
	fi

	return "$OK"
}

load_public_key() {
	local key_path="$1"
	local keyring="$2"
	local cert_path cert_path_der

	if [ -n "$TST_CERT_PATH" ]; then
		if [ "${TST_CERT_PATH:0:1}" != "/" ]; then
			echo "${RED}Absolute path required for the kernel certificate${NORM}"
			return "$FAIL"
		fi

		if [ ! -f "$TST_CERT_PATH" ]; then
			echo "${RED}Kernel certificate not found in $TST_CERT_PATH${NORM}"
			return "$FAIL"
		fi

		cert_path="$TST_CERT_PATH"
	else
		cert_path="$key_path"
	fi

	# We must always filter the cert, since the kernel rejects key+cert in DER form.
	if ! cert_path_der=$(mktemp); then
		echo "${RED}Failed to create temporary file for the kernel certificate${NORM}"
		return "$FAIL"
	fi

	if ! openssl x509 -in "$cert_path" -out "$cert_path_der" -outform der; then
		echo "${RED}Failed to convert the kernel certificate${NORM}"
		return "$FAIL"
	fi

	if ! keyctl padd asymmetric pubkey %keyring:"$keyring" < "$cert_path_der" &> /dev/null; then
		echo "${RED}Kernel public key cannot be added to the $keyring keyring${NORM}"
		rm -f "$cert_path_der"
		return "$FAIL"
	fi

	rm -f "$cert_path_der"
	return "$OK"
}
