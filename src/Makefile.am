lib_LTLIBRARIES = libimaevm.la

libimaevm_la_SOURCES = libimaevm.c
libimaevm_la_CPPFLAGS = $(OPENSSL_CFLAGS)
# current[:revision[:age]]
# result: [current-age].age.revision
libimaevm_la_LDFLAGS = -version-info 0:0:0
libimaevm_la_LIBADD =  $(OPENSSL_LIBS)

include_HEADERS = imaevm.h

nodist_libimaevm_la_SOURCES = hash_info.h
BUILT_SOURCES = hash_info.h
hash_info.h: Makefile
	./hash_info.gen $(KERNEL_HEADERS) >$@

bin_PROGRAMS = evmctl

evmctl_SOURCES = evmctl.c
evmctl_CPPFLAGS = $(OPENSSL_CFLAGS)
evmctl_LDFLAGS = $(LDFLAGS_READLINE)
evmctl_LDADD =  $(OPENSSL_LIBS) -lkeyutils libimaevm.la

INCLUDES = -I$(top_srcdir) -include config.h

CLEANFILES = hash_info.h
DISTCLEANFILES = @DISTCLEANFILES@

