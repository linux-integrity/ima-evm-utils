#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# ima-evm-utils tests bash functions
#
# Copyright (C) 2020 Vitaly Chikunov <vt@altlinux.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# Tests accounting
declare -i testspass=0 testsfail=0 testsskip=0

# Exit codes (compatible with automake)
declare -r OK=0
declare -r FAIL=1
declare -r HARDFAIL=99 # hard failure no matter testing mode
declare -r SKIP=77

# You can set env VERBOSE=1 to see more output from evmctl
VERBOSE=${VERBOSE:-0}
V=vvvv
V=${V:0:$VERBOSE}
V=${V:+-$V}

# Exit if env FAILEARLY is defined.
# Used in expect_{pass,fail}.
exit_early() {
  if [ "$FAILEARLY" ]; then
    exit "$1"
  fi
}

# Require particular executables to be present
_require() {
  ret=
  for i; do
    if ! type $i; then
      echo "$i is required for test"
      ret=1
    fi
  done
  [ $ret ] && exit "$HARDFAIL"
}

# Non-TTY output is never colored
if [ -t 1 ]; then
     RED=$'\e[1;31m'
   GREEN=$'\e[1;32m'
  YELLOW=$'\e[1;33m'
    BLUE=$'\e[1;34m'
    CYAN=$'\e[1;36m'
    NORM=$'\e[m'
  export RED GREEN YELLOW BLUE CYAN NORM
fi

# Test mode determined by TFAIL variable:
#   undefined: to success testing
#   defined: failure testing
TFAIL=
TMODE=+ # mode character to prepend running command in log
declare -i TNESTED=0 # just for sanity checking

# Run positive test (one that should pass) and account its result
expect_pass() {
  local -i ret

  if [ $TNESTED -gt 0 ]; then
    echo $RED"expect_pass should not be run nested"$NORM
    testsfail+=1
    exit "$HARDFAIL"
  fi
  TFAIL=
  TMODE=+
  TNESTED+=1
  [ "$VERBOSE" -gt 1 ] && echo "____ START positive test: $*"
  "$@"
  ret=$?
  [ "$VERBOSE" -gt 1 ] && echo "^^^^ STOP ($ret) positive test: $*"
  TNESTED+=-1
  case $ret in
    0)  testspass+=1 ;;
    77) testsskip+=1 ;;
    99) testsfail+=1; exit_early 1 ;;
    *)  testsfail+=1; exit_early 2 ;;
  esac
  return $ret
}

# Eval negative test (one that should fail) and account its result
expect_fail() {
  local ret

  if [ $TNESTED -gt 0 ]; then
    echo $RED"expect_fail should not be run nested"$NORM
    testsfail+=1
    exit "$HARDFAIL"
  fi

  TFAIL=yes
  TMODE=-
  TNESTED+=1
  [ "$VERBOSE" -gt 1 ] && echo "____ START negative test: $*"
  "$@"
  ret=$?
  [ "$VERBOSE" -gt 1 ] && echo "^^^^ STOP ($ret) negative test: $*"
  TNESTED+=-1
  case $ret in
    0)  testsfail+=1; exit_early 3 ;;
    77) testsskip+=1 ;;
    99) testsfail+=1; exit_early 4 ;;
    *)  testspass+=1 ;;
  esac
  # Restore defaults (as in positive tests)
  # for tests to run without wrappers
  TFAIL=
  TMODE=+
  return $ret
}

# return true if current test is positive
_test_expected_to_pass() {
  [ ! $TFAIL ]
}

# return true if current test is negative
_test_expected_to_fail() {
  [ $TFAIL ]
}

# Show blank line and color following text to red
# if it's real error (ie we are in expect_pass mode).
color_red_on_failure() {
  if _test_expected_to_pass; then
    echo "$RED"
    COLOR_RESTORE=true
  fi
}

# For hard errors
color_red() {
  echo "$RED"
  COLOR_RESTORE=true
}

color_restore() {
  [ $COLOR_RESTORE ] && echo "$NORM"
  COLOR_RESTORE=
}

ADD_DEL=
ADD_TEXT_FOR=
# _evmctl_run should be run as `_evmctl_run ... || return'
_evmctl_run() {
  local op=$1 out=$1-$$.out
  local text_for=${FOR:+for $ADD_TEXT_FOR}
  # Additional parameters:
  # ADD_DEL: additional files to rm on failure
  # ADD_TEXT_FOR: append to text as 'for $ADD_TEXT_FOR'

  cmd="evmctl $V $EVMCTL_ENGINE $*"
  echo $YELLOW$TMODE "$cmd"$NORM
  $cmd >"$out" 2>&1
  ret=$?

  # Shell special and signal exit codes (except 255)
  if [ $ret -ge 126 ] && [ $ret -lt 255 ]; then
    color_red
    echo "evmctl $op failed hard with ($ret) $text_for"
    sed 's/^/  /' "$out"
    color_restore
    rm "$out" $ADD_DEL
    ADD_DEL=
    ADD_TEXT_FOR=
    return "$HARDFAIL"
  elif [ $ret -gt 0 ]; then
    color_red_on_failure
    echo "evmctl $op failed" ${TFAIL:+properly} "with ($ret) $text_for"
    # Show evmctl output only in verbose mode or if real failure.
    if _test_expected_to_pass || [ "$VERBOSE" ]; then
      sed 's/^/  /' "$out"
    fi
    color_restore
    rm "$out" $ADD_DEL
    ADD_DEL=
    ADD_TEXT_FOR=
    return "$FAIL"
  elif _test_expected_to_fail; then
    color_red
    echo "evmctl $op wrongly succeeded $text_for"
    sed 's/^/  /' "$out"
    color_restore
  else
    [ "$VERBOSE" ] && sed 's/^/  /' "$out"
  fi
  rm "$out"
  ADD_DEL=
  ADD_TEXT_FOR=
  return "$OK"
}

# Extract xattr $attr from $file into $out file skipping $pref'ix
_extract_xattr() {
  local file=$1 attr=$2 out=$3 pref=$4

  getfattr -n "$attr" -e hex "$file" \
    | grep "^$attr=" \
    | sed "s/^$attr=$pref//" \
    | xxd -r -p > "$out"
}

# Test if xattr $attr in $file matches $prefix
# Show error and fail otherwise.
_test_xattr() {
  local file=$1 attr=$2 prefix=$3
  local text_for=${ADD_TEXT_FOR:+ for $ADD_TEXT_FOR}

  if ! getfattr -n "$attr" -e hex "$file" | egrep -qx "$attr=$prefix"; then
    color_red_on_failure
    echo "Did not find expected hash$text_for:"
    echo "    $attr=$prefix"
    echo ""
    echo "Actual output below:"
    getfattr -n "$attr" -e hex "$file" | sed 's/^/    /'
    color_restore
    rm "$file"
    ADD_TEXT_FOR=
    return "$FAIL"
  fi
  ADD_TEXT_FOR=
}

# Try to enable gost-engine if needed.
_enable_gost_engine() {
  # Do not enable if it's already working (enabled by user)
  if ! openssl md_gost12_256 /dev/null >/dev/null 2>&1 \
    && openssl engine gost >/dev/null 2>&1; then
    export EVMCTL_ENGINE="--engine gost"
    export OPENSSL_ENGINE="-engine gost"
  fi
}

# Show test stats and exit into automake test system
# with proper exit code (same as ours). Do cleanups.
_report_exit_and_cleanup() {
  if [ -n "${WORKDIR}" ]; then
    rm -rf "${WORKDIR}"
  fi

  if [ $testsfail -gt 0 ]; then
    echo "================================="
    echo " Run with FAILEARLY=1 $0 $*"
    echo " To stop after first failure"
    echo "================================="
  fi
  [ $testspass -gt 0 ] && echo -n "$GREEN" || echo -n "$NORM"
  echo -n "PASS: $testspass"
  [ $testsskip -gt 0 ] && echo -n "$YELLOW" || echo -n "$NORM"
  echo -n " SKIP: $testsskip"
  [ $testsfail -gt 0 ] && echo -n "$RED" || echo -n "$NORM"
  echo " FAIL: $testsfail"
  echo "$NORM"
  if [ $testsfail -gt 0 ]; then
    exit "$FAIL"
  elif [ $testspass -gt 0 ]; then
    exit "$OK"
  else
    exit "$SKIP"
  fi
}

# Setup SoftHSM for local testing by calling the softhsm_setup script.
# Use the provided workdir as the directory where SoftHSM will store its state
# into.
# Upon successfully setting up SoftHSM, this function sets the global variables
# OPENSSL_ENGINE and OPENSSL_KEYFORM so that the openssl command line tool can
# use SoftHSM. Also the PKCS11_KEYURI global variable is set to the test key's
# pkcs11 URI.
_softhsm_setup() {
  local workdir="$1"

  local msg

  export SOFTHSM_SETUP_CONFIGDIR="${workdir}/softhsm"
  export SOFTHSM2_CONF="${workdir}/softhsm/softhsm2.conf"

  mkdir -p "${SOFTHSM_SETUP_CONFIGDIR}"

  msg=$(./softhsm_setup setup 2>&1)
  if [ $? -eq 0 ]; then
    echo "softhsm_setup setup succeeded: $msg"
    PKCS11_KEYURI=$(echo $msg | sed -n 's|^keyuri: \(.*\)|\1|p')

    export EVMCTL_ENGINE="--engine pkcs11"
    export OPENSSL_ENGINE="-engine pkcs11"
    export OPENSSL_KEYFORM="-keyform engine"
  else
    echo "softhsm_setup setup failed: ${msg}"
  fi
}

# Tear down the SoftHSM setup and clean up the environment
_softhsm_teardown() {
  ./softhsm_setup teardown &>/dev/null
  rm -rf "${SOFTHSM_SETUP_CONFIGDIR}"
  unset SOFTHSM_SETUP_CONFIGDIR SOFTHSM2_CONF PKCS11_KEYURI \
    EVMCTL_ENGINE OPENSSL_ENGINE OPENSSL_KEYFORM
}