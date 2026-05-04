#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later

DIR=$(dirname "$0")

cd "${DIR}" 1>/dev/null || exit 1

. ./functions
ima_gen_signing_key_selfsigned rsa:2048
exit $?
