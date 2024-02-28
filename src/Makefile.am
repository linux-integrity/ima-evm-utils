lib_LTLIBRARIES = libimaevm.la

libimaevm_la_SOURCES = libimaevm.c
libimaevm_la_CPPFLAGS = $(AM_CPPFLAGS) $(LIBCRYPTO_CFLAGS)
# current[:revision[:age]]
# result: [current-age].age.revision
libimaevm_la_LDFLAGS = -version-info 4:0:0
libimaevm_la_LIBADD =  $(LIBCRYPTO_LIBS)

libimaevm_la_CFLAGS =

if CONFIG_SIGV1
libimaevm_la_CFLAGS += -DCONFIG_SIGV1
endif

if CONFIG_IMA_EVM_ENGINE
libimaevm_la_CFLAGS += -DCONFIG_IMA_EVM_ENGINE
endif

if CONFIG_IMA_EVM_PROVIDER
libimaevm_la_CFLAGS += -DCONFIG_IMA_EVM_PROVIDER
endif

include_HEADERS = imaevm.h

nodist_libimaevm_la_SOURCES = hash_info.h
BUILT_SOURCES = hash_info.h
EXTRA_DIST = hash_info.gen
hash_info.h: Makefile
	$(srcdir)/hash_info.gen $(KERNEL_HEADERS) >$@

bin_PROGRAMS = evmctl

evmctl_SOURCES = evmctl.c utils.c
evmctl_CPPFLAGS = $(AM_CPPFLAGS) $(LIBCRYPTO_CFLAGS)
evmctl_LDFLAGS = $(LDFLAGS_READLINE)
evmctl_LDADD =  $(LIBCRYPTO_LIBS) -lkeyutils libimaevm.la

evmctl_CFLAGS =

# Enable IMA signature version 1
if CONFIG_SIGV1
evmctl_CFLAGS += -DCONFIG_SIGV1
endif

# Enable "--engine" support
if CONFIG_IMA_EVM_ENGINE
evmctl_CFLAGS += -DCONFIG_IMA_EVM_ENGINE
endif

# Enable "--provider" support
if CONFIG_IMA_EVM_PROVIDER
evmctl_CFLAGS += -DCONFIG_IMA_EVM_PROVIDER
endif

# USE_PCRTSS uses the Intel TSS
if USE_PCRTSS
 evmctl_SOURCES += pcr_tss.c

# USE_IBMTSS uses the IBM TSS
else
if USE_IBMTSS
 evmctl_SOURCES += pcr_ibmtss.c
 evmctl_LDADD += -libmtss

# uses the IBM TSS command line utilities
else
 evmctl_SOURCES += pcr_tsspcrread.c

endif
endif

AM_CPPFLAGS = -I$(top_srcdir) -include config.h

CLEANFILES = hash_info.h tmp_hash_info.h
DISTCLEANFILES = @DISTCLEANFILES@
