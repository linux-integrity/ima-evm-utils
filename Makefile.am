SUBDIRS = src

EXTRA_DIST = autogen.sh

ACLOCAL_AMFLAGS = -I m4

SRCS = $(HOME)/rpmbuild/SOURCES
SPEC = $(PACKAGE_NAME).spec

pkgname = $(PACKAGE_NAME)-$(PACKAGE_VERSION)
tarname = $(pkgname).tar.gz

$(tarname):
	git archive --format=tar --prefix=$(pkgname)/ v$(PACKAGE_VERSION) $(FILES) | gzip >$@

tar: $(tarname)

rpm: $(tarname)
	cp $(tarname) $(SRCS)/
	rpmbuild -ba --nodeps $(SPEC)

.PHONY: $(tarname)
