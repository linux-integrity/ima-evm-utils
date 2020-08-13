dnl Copyright (c) 2018-2020 Petr Vorel <pvorel@suse.cz>
dnl Find docbook manpage stylesheet

AC_DEFUN([EVMCTL_MANPAGE_DOCBOOK_XSL], [
	AC_PATH_PROGS(XMLCATALOG, xmlcatalog)
	AC_ARG_WITH([xml-catalog],
		AC_HELP_STRING([--with-xml-catalog=CATALOG],
				[path to xml catalog to use]),,
				[with_xml_catalog=/etc/xml/catalog])
	XML_CATALOG_FILE="$with_xml_catalog"
	AC_SUBST([XML_CATALOG_FILE])
	AC_MSG_CHECKING([for XML catalog ($XML_CATALOG_FILE)])
	if test -f "$XML_CATALOG_FILE"; then
		have_xmlcatalog_file=yes
		AC_MSG_RESULT([found])
	else
		AC_MSG_RESULT([not found])
	fi
	if test "x${XMLCATALOG}" != "x" -a "x$have_xmlcatalog_file" = "xyes"; then
		DOCBOOK_XSL_URI="http://docbook.sourceforge.net/release/xsl/current"
		DOCBOOK_XSL_PATH="manpages/docbook.xsl"
		MANPAGE_DOCBOOK_XSL=$(${XMLCATALOG} ${XML_CATALOG_FILE} ${DOCBOOK_XSL_URI}/${DOCBOOK_XSL_PATH} | sed 's|^file:/\+|/|')
	fi
	if test "x${MANPAGE_DOCBOOK_XSL}" = "x"; then
		MANPAGE_DOCBOOK_XSL="/usr/share/xml/docbook/stylesheet/docbook-xsl/manpages/docbook.xsl"
	fi
	AC_SUBST(MANPAGE_DOCBOOK_XSL)
])
