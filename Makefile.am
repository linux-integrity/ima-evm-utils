SUBDIRS = src
# does work on Ubuntu, but on Fedora different path to XSL stylesheets
#man_MANS = evmctl.1

doc_DATA =  examples/ima-genkey-self.sh examples/ima-genkey.sh examples/ima-gen-local-ca.sh
EXTRA_DIST = autogen.sh $(doc_DATA)

CLEANFILES = *.html *.1 *.xsl

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

# requires asciidoc, xslproc, docbook-xsl
MANPAGE_DOCBOOK_XSL = /usr/share/xml/docbook/stylesheet/docbook-xsl/manpages/docbook.xsl

evmctl.1.html: README
	@asciidoc -o $@ $<

evmctl.1.xsl: README
	@asciidoc -d manpage -b docbook -o $@ $<

evmctl.1: evmctl.1.xsl
	@xsltproc --nonet -o $@ $(MANPAGE_DOCBOOK_XSL) $<

doc: evmctl.1.html evmctl.1

.PHONY: $(tarname)
