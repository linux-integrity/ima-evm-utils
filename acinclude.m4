
AC_DEFUN([PKG_ARG_ENABLE],
	[
	AC_MSG_CHECKING(whether to enable $1)
	AC_ARG_ENABLE([$1], AS_HELP_STRING([--enable-$1], [enable $1 (default is $2)]),
	[pkg_cv_enable_$1=$enableval],	
	[AC_CACHE_VAL([pkg_cv_enable_$1], [pkg_cv_enable_$1=$2])])
	if test $pkg_cv_enable_$1 = yes; then
		AC_DEFINE([$3],, [$4])
	fi
	AC_MSG_RESULT([$pkg_cv_enable_$1])
	AM_CONDITIONAL($3, test $pkg_cv_enable_$1 = yes)
])

