# autoconf script

AC_PREREQ([2.65])
AC_INIT(ima-evm-utils, 1.4, zohar@linux.ibm.com)
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_HOST
AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
#AC_PROG_CXX
#AC_PROG_CPP
AC_PROG_INSTALL
#AC_PROG_LN_S
LT_INIT

# FIXME: Replace `main' with a function in `-lpthread':
#AC_CHECK_LIB([pthread], [main])

PKG_CHECK_MODULES(LIBCRYPTO, [libcrypto >= 0.9.8 ])
AC_SUBST(KERNEL_HEADERS)
AC_CHECK_HEADER(unistd.h)
AC_CHECK_HEADERS(openssl/conf.h)

# Intel TSS
AC_CHECK_LIB([tss2-esys], [Esys_Free])
AC_CHECK_LIB([tss2-rc], [Tss2_RC_Decode])
AM_CONDITIONAL([USE_PCRTSS], [test "x$ac_cv_lib_tss2_esys_Esys_Free" = "xyes"])

# IBM TSS include files
AC_CHECK_HEADER(ibmtss/tss.h, [], [], [[#define TPM_POSIX]])
AM_CONDITIONAL([USE_IBMTSS], [test "x$ac_cv_header_ibmtss_tss_h" = "xyes"])

AC_CHECK_HEADERS(sys/xattr.h, , [AC_MSG_ERROR([sys/xattr.h header not found. You need the c-library development package.])])
AC_CHECK_HEADERS(keyutils.h, , [AC_MSG_ERROR([keyutils.h header not found. You need the libkeyutils development package.])])

AC_ARG_WITH(kernel_headers, [AS_HELP_STRING([--with-kernel-headers=PATH],
	    [specifies the Linux kernel-headers package location or kernel root directory you want to use])],
	    [KERNEL_HEADERS="$withval"],
	    [KERNEL_HEADERS=/lib/modules/$(uname -r)/source])

AC_ARG_ENABLE([openssl_conf],
	      [AS_HELP_STRING([--disable-openssl-conf], [disable loading of openssl config by evmctl])],
	      [if test "$enable_openssl_conf" = "no"; then
		AC_DEFINE(DISABLE_OPENSSL_CONF, 1, [Define to disable loading of openssl config by evmctl.])
	      fi], [enable_openssl_conf=yes])

AC_ARG_ENABLE(sigv1,
	      AS_HELP_STRING([--enable-sigv1], [Build ima-evm-utils with signature v1 support]))
	AM_CONDITIONAL([CONFIG_SIGV1], [test "x$enable_sigv1" = "xyes"])
	AS_IF([test "$enable_sigv1"  != "yes"], [enable_sigv1="no"])

#debug support - yes for a while
PKG_ARG_ENABLE(debug, "yes", DEBUG, [Enable Debug support])
if test $pkg_cv_enable_debug = yes; then
	CFLAGS="$CFLAGS -g -O1 -Wall -Wstrict-prototypes -pipe"
else
	CFLAGS="$CFLAGS -Wall -Wstrict-prototypes -pipe -fomit-frame-pointer"
fi

EVMCTL_MANPAGE_DOCBOOK_XSL
AX_DEFAULT_HASH_ALGO([$KERNEL_HEADERS])

# for gcov
#CFLAGS="$CFLAGS -Wall -fprofile-arcs -ftest-coverage"
#CXXFLAGS="$CXXFLAGS -Wall -fprofile-arcs -ftest-coverage"
#LDFLAGS="$LDFLAGS -fprofile-arcs"
#DISTCLEANFILES="*.gcno *.gcda"

AC_CONFIG_FILES([Makefile
		src/Makefile
		tests/Makefile
		packaging/ima-evm-utils.spec
		])
AC_OUTPUT

# Give some feedback
echo
echo
echo	"Configuration:"
echo	"          debug: $pkg_cv_enable_debug"
echo	"   default-hash: $HASH_ALGO"
echo	"   openssl-conf: $enable_openssl_conf"
echo	"      tss2-esys: $ac_cv_lib_tss2_esys_Esys_Free"
echo	" tss2-rc-decode: $ac_cv_lib_tss2_rc_Tss2_RC_Decode"
echo    "         ibmtss: $ac_cv_header_ibmtss_tss_h"
echo    "         sigv1:  $enable_sigv1"
echo	"            doc: $have_doc"
echo
