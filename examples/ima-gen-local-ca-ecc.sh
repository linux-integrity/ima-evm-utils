#!/bin/sh

DIR=$(dirname "$0")

cd "${DIR}" 1>/dev/null || exit 1

. ./functions
ima_gen_localca prime256v1
exit $?
