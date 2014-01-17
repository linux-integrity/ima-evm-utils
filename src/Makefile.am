lib_LTLIBRARIES = libevm.la

libevm_la_SOURCES = libevm.c
libevm_la_CPPFLAGS = $(OPENSSL_CFLAGS)
# current[:revision[:age]]
# result: [current-age].age.revision
libevm_la_LDFLAGS = -version-info 0:0:0
libevm_la_LIBADD =  $(OPENSSL_LIBS)

bin_PROGRAMS = evmctl

evmctl_SOURCES = evmctl.c
evmctl_CPPFLAGS = $(OPENSSL_CFLAGS)
evmctl_LDFLAGS = $(LDFLAGS_READLINE)
evmctl_LDADD =  $(OPENSSL_LIBS) -lkeyutils libevm.la

INCLUDES = -I$(top_srcdir) -include config.h

DISTCLEANFILES = @DISTCLEANFILES@

