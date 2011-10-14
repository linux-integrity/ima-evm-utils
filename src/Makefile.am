
bin_PROGRAMS = evmctl

evmctl_SOURCES = evmctl.c
evmctl_CPPFLAGS = $(OPENSSL_CFLAGS)
evmctl_LDFLAGS = $(LDFLAGS_READLINE)
evmctl_LDADD =  $(OPENSSL_LIBS) -lkeyutils

INCLUDES = -I$(top_srcdir) -include config.h

DISTCLEANFILES = @DISTCLEANFILES@

