SUBDIRS = src

doc_DATA =  examples/ima-genkey-self.sh examples/ima-genkey.sh examples/ima-gen-local-ca.sh
EXTRA_DIST = autogen.sh $(doc_DATA)

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
