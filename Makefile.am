SUBDIRS = src tests
if MANPAGE_DOCBOOK_XSL
dist_man_MANS = evmctl.1
endif

doc_DATA =  examples/ima-genkey-self.sh examples/ima-genkey.sh examples/ima-gen-local-ca.sh
EXTRA_DIST = autogen.sh $(doc_DATA)

CLEANFILES = *.html *.xsl

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

if MANPAGE_DOCBOOK_XSL
evmctl.1.html: README
	@asciidoc -o $@ $<

evmctl.1:
	asciidoc -d manpage -b docbook -o evmctl.1.xsl README
	xsltproc --nonet -o $@ $(MANPAGE_DOCBOOK_XSL) evmctl.1.xsl
	rm -f evmctl.1.xsl

rmman:
	rm -f evmctl.1

doc: evmctl.1.html rmman evmctl.1
endif

.PHONY: $(tarname)
