noinst_DATA = sf-wiki.html

sf-wiki.html:sf-wiki.md
	pandoc $+ -f markdown -t html > $@

CLEANFILES = sf-wiki.html
