dnl Copyright (c) 2018-2020 Petr Vorel <pvorel@suse.cz>
dnl Find docbook manpage stylesheet

AC_DEFUN([EVMCTL_MANPAGE_DOCBOOK_XSL], [
	DOCBOOK_XSL_URI="http://docbook.sourceforge.net/release/xsl/current"
	DOCBOOK_XSL_PATH="manpages/docbook.xsl"

	AC_PATH_PROGS(XMLCATALOG, xmlcatalog)
	AC_ARG_WITH([xml-catalog],
		AS_HELP_STRING([--with-xml-catalog=CATALOG],
				[path to xml catalog to use]),,
				[with_xml_catalog=/etc/xml/catalog])
	XML_CATALOG_FILE="$with_xml_catalog"
	AC_SUBST([XML_CATALOG_FILE])

	if test "x${XMLCATALOG}" = "x"; then
		AC_MSG_WARN([xmlcatalog not found, cannot search for $DOCBOOK_XSL_PATH])
	else
		AC_MSG_CHECKING([for XML catalog ($XML_CATALOG_FILE)])
		if test -f "$XML_CATALOG_FILE"; then
			have_xmlcatalog_file=yes
			AC_MSG_RESULT([found])
		else
			AC_MSG_RESULT([not found, cannot search for $DOCBOOK_XSL_PATH])
		fi
	fi

	if test "x${XMLCATALOG}" != "x" -a "x$have_xmlcatalog_file" = "xyes"; then
		MANPAGE_DOCBOOK_XSL=$(${XMLCATALOG} ${XML_CATALOG_FILE} ${DOCBOOK_XSL_URI}/${DOCBOOK_XSL_PATH} | sed 's|^file:/\+|/|')
	fi

	if test "x${MANPAGE_DOCBOOK_XSL}" = "x"; then
		MANPAGE_DOCBOOK_XSL="/usr/share/xml/docbook/stylesheet/docbook-xsl/manpages/docbook.xsl"
		AC_MSG_WARN([trying a default path for $DOCBOOK_XSL_PATH])
	fi

	if test -f "$MANPAGE_DOCBOOK_XSL"; then
		have_doc=yes
		AC_MSG_NOTICE([using $MANPAGE_DOCBOOK_XSL for generating doc])
	else
		AC_MSG_WARN([$DOCBOOK_XSL_PATH not found, generating doc will be skipped])
		MANPAGE_DOCBOOK_XSL=
		have_doc=no
	fi
	AM_CONDITIONAL(MANPAGE_DOCBOOK_XSL, test "x$have_doc" = xyes)

	AC_SUBST(MANPAGE_DOCBOOK_XSL)
])
