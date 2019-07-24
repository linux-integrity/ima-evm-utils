# autoconf script

AC_PREREQ([2.65])
AC_INIT(ima-evm-utils, 1.2, zohar@linux.ibm.com)
AM_INIT_AUTOMAKE
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
AC_PROG_LIBTOOL
#AC_PROG_LN_S
LT_INIT

# FIXME: Replace `main' with a function in `-lpthread':
#AC_CHECK_LIB([pthread], [main])

# Checks for header files.
AC_HEADER_STDC

PKG_CHECK_MODULES(LIBCRYPTO, [libcrypto >= 0.9.8 ])
AC_SUBST(KERNEL_HEADERS)
AC_CHECK_HEADER(unistd.h)
AC_CHECK_HEADERS(openssl/conf.h)

AC_CHECK_PROG(TSSPCRREAD, [tsspcrread], yes, no)
if test "x$TSSPCRREAD" = "xyes"; then
	AC_DEFINE(HAVE_TSSPCRREAD, 1, [Define to 1 if you have tsspcrread binary installed])],
fi

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

#debug support - yes for a while
PKG_ARG_ENABLE(debug, "yes", DEBUG, [Enable Debug support])
if test $pkg_cv_enable_debug = yes; then
	CFLAGS="$CFLAGS -g -O1 -Wall -Wstrict-prototypes -pipe"
else
	CFLAGS="$CFLAGS -Wall -Wstrict-prototypes -pipe -fomit-frame-pointer"
fi

EVMCTL_MANPAGE_DOCBOOK_XSL

# for gcov
#CFLAGS="$CFLAGS -Wall -fprofile-arcs -ftest-coverage"
#CXXFLAGS="$CXXFLAGS -Wall -fprofile-arcs -ftest-coverage"
#LDFLAGS="$LDFLAGS -fprofile-arcs"
#DISTCLEANFILES="*.gcno *.gcda"

AC_CONFIG_FILES([Makefile
		src/Makefile
		packaging/ima-evm-utils.spec
		])
AC_OUTPUT

# Give some feedback
echo
echo
echo	"Configuration:"
echo	"          debug: $pkg_cv_enable_debug"
echo	"   openssl-conf: $enable_openssl_conf"
echo	"     tsspcrread: $TSSPCRREAD"
echo
