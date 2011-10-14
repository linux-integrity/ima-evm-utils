#! /bin/sh

set -e

# new way
# strange, but need this for Makefile.am, because it has -I m4
test -d m4 || mkdir m4
autoreconf -f -i

# old way
#libtoolize --automake --copy --force
#aclocal
#autoconf --force
#autoheader --force
#automake --add-missing --copy --force-missing --gnu

