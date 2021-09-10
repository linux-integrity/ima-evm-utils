dnl Copyright (c) 2021 Bruno Meneguele <bmeneg@redhat.com>
dnl Check hash algorithm availability in the kernel
dnl
dnl $1 - $KERNEL_HEADERS

AC_DEFUN([AX_DEFAULT_HASH_ALGO], [
	HASH_INFO_HEADER="$1/include/uapi/linux/hash_info.h"

	AC_ARG_WITH([default_hash],
		AS_HELP_STRING([--with-default-hash=ALGORITHM], [specifies the default hash algorithm to be used]),
		[HASH_ALGO=$withval],
		[HASH_ALGO=sha256])

	AC_PROG_SED()
	HASH_ALGO="$(echo $HASH_ALGO | $SED 's/\(.*\)/\L\1\E/')"

	AC_CHECK_HEADER([$HASH_INFO_HEADER],
		[HAVE_HASH_INFO_HEADER=yes],
		[AC_MSG_WARN([$HASH_INFO_HEADER not found.])])

	if test "x$HAVE_HASH_INFO_HEADER" = "x"; then
		AC_MSG_RESULT([using $HASH_ALGO algorithm as default hash algorith])
		AC_DEFINE_UNQUOTED(DEFAULT_HASH_ALGO, "$HASH_ALGO", [Define default hash algorithm])
	else
		AC_PROG_GREP()
		$SED -n 's/HASH_ALGO_\(.*\),/\L\1\E/p' $HASH_INFO_HEADER | $GREP -w $HASH_ALGO > /dev/null
		have_hash=$?

		if test $have_hash -ne 0; then
			AC_MSG_ERROR([$HASH_ALGO algorithm specified, but not provided by the kernel], 1)
		else
			AC_MSG_NOTICE([using $HASH_ALGO as default hash algorithm])
			AC_DEFINE_UNQUOTED(DEFAULT_HASH_ALGO, "$HASH_ALGO", [Define default hash algorithm])
		fi
	fi
])
