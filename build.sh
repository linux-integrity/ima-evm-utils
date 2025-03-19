#!/bin/sh
# Copyright (c) 2020 Petr Vorel <pvorel@suse.cz>

if [ -n "$CI" ]; then
	# If we under CI only thing we can analyze is logs so better to enable
	# verbosity to a maximum.
	set -x
	# This is to make stdout and stderr synchronous in the logs.
	exec 2>&1

	mount -t securityfs -o rw securityfs /sys/kernel/security
fi

set -e

CC="${CC:-gcc}"
CFLAGS="${CFLAGS:--Wformat -Werror=format-security -Werror=implicit-function-declaration -Werror=return-type -fno-common}"
PREFIX="${PREFIX:-$HOME/ima-evm-utils-install}"

export LD_LIBRARY_PATH="$PREFIX/lib64:$PREFIX/lib:/usr/local/lib64:/usr/local/lib"
export PATH="$PREFIX/bin:/usr/local/bin:$PATH"

title()
{
	echo "===== $1 ====="
}

log_exit()
{
	local ret="${3:-$?}"
	local log="$1"
	local msg="$2"
	local prefix

	echo "=== $log ==="
	[ $ret -eq 0 ] || prefix="FAIL: "
	cat $log
	echo
	echo "$prefix$msg, see output of $log above"
	exit $ret
}

cd `dirname $0`

if [ "$COMPILE_SSL" ]; then
	echo "COMPILE_SSL: $COMPILE_SSL"
	export CFLAGS="-I/opt/openssl3/include $CFLAGS"
	export LD_LIBRARY_PATH="/opt/openssl3/lib64:/opt/openssl3/lib:$HOME/src/ima-evm-utils/src/.libs:$LD_LIBRARY_PATH"
	export LDFLAGS="-L/opt/openssl3/lib64 -L/opt/openssl3/lib $LDFLAGS"
	export PATH="/opt/openssl3/bin:$HOME/src/ima-evm-utils/src/.libs:$PATH"
fi

case "$VARIANT" in
	i386)
		echo "32-bit compilation"
		export CFLAGS="-m32 $CFLAGS" LDFLAGS="-m32 $LDFLAGS"
		export PKG_CONFIG_LIBDIR=/usr/lib/i386-linux-gnu/pkgconfig
		;;
	cross-compile)
		host="${CC%-gcc}"
		export CROSS_COMPILE="${host}-"
		host="--host=$host"
		echo "cross compilation: $host"
		echo "CROSS_COMPILE: '$CROSS_COMPILE'"
		;;
	*)
		if [ "$VARIANT" ]; then
			echo "Wrong VARIANT: '$VARIANT'" >&2
			exit 1
		fi
		echo "native build"
		;;
esac

title "compiler version"
$CC --version
echo "CFLAGS: '$CFLAGS'"
echo "LDFLAGS: '$LDFLAGS'"
echo "PREFIX: '$PREFIX'"

title "configure"
./autogen.sh
./configure --prefix=$PREFIX $host || log_exit config.log "configure failed"

title "make"
make -j$(nproc)
make install

title "test"
if [ "$VARIANT" = "cross-compile" ]; then
	echo "skip make check on cross compilation"
	exit 0
fi

ret=0
VERBOSE=1 make check || ret=$?

title "logs"
if [ $ret -eq 0 ]; then
	cd tests; make check_logs; cd ..
	exit 0
fi

if [ $ret -eq 77 ]; then
	msg="WARN: some tests skipped"
	ret=0
else
	msg="FAIL: tests exited: $ret"
fi

log_exit "tests/test-suite.log tests/kernel/test-suite.log" "$msg" $ret
