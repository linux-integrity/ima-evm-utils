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
