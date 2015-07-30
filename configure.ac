# autoconf script

AC_PREREQ([2.65])
AC_INIT(ima-evm-utils, 1.0, dmitry.kasatkin@huawei.com)
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
 
AC_CANONICAL_HOST

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

PKG_CHECK_MODULES(OPENSSL, [ openssl >= 0.9.8 ])
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LIBS)
AC_CHECK_HEADER(unistd.h)
AC_CHECK_HEADERS(openssl/conf.h)

AC_CHECK_HEADERS(attr/xattr.h, , [AC_MSG_ERROR([attr/xattr.h header not found. You need the libattr development package.])])
AC_CHECK_HEADERS(keyutils.h, , [AC_MSG_ERROR([keyutils.h header not found. You need the libkeyutils development package.])])

#debug support - yes for a while
PKG_ARG_ENABLE(debug, "yes", DEBUG, [Enable Debug support])
if test $pkg_cv_enable_debug = yes; then
	CFLAGS="$CFLAGS -g -O1 -Wall -Wstrict-prototypes -pipe"
else
	CFLAGS="$CFLAGS -Wall -Wstrict-prototypes -pipe -fomit-frame-pointer"
fi

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
echo	"	debug:	$pkg_cv_enable_debug"
echo

