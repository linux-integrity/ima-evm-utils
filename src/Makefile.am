lib_LTLIBRARIES = libimaevm.la

libimaevm_la_SOURCES = libimaevm.c
libimaevm_la_CPPFLAGS = $(AM_CPPFLAGS) $(LIBCRYPTO_CFLAGS)
# current[:revision[:age]]
# result: [current-age].age.revision
libimaevm_la_LDFLAGS = -version-info 1:0:0
libimaevm_la_LIBADD =  $(LIBCRYPTO_LIBS)

include_HEADERS = imaevm.h

nodist_libimaevm_la_SOURCES = hash_info.h
BUILT_SOURCES = hash_info.h
EXTRA_DIST = hash_info.gen
hash_info.h: Makefile
	$(srcdir)/hash_info.gen $(KERNEL_HEADERS) >$@

bin_PROGRAMS = evmctl

evmctl_SOURCES = evmctl.c
evmctl_CPPFLAGS = $(AM_CPPFLAGS) $(LIBCRYPTO_CFLAGS)
evmctl_LDFLAGS = $(LDFLAGS_READLINE)
evmctl_LDADD =  $(LIBCRYPTO_LIBS) -lkeyutils libimaevm.la

AM_CPPFLAGS = -I$(top_srcdir) -include config.h

CLEANFILES = hash_info.h
DISTCLEANFILES = @DISTCLEANFILES@
