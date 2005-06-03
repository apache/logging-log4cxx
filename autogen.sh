#! /bin/sh
# Regenerate the files autoconf / automake

case `uname` in
      (Darwin)        LIBTOOLIZE=glibtoolize  ;;
      (*)             LIBTOOLIZE=libtoolize   ;;
esac
$LIBTOOLIZE --force --automake --copy

rm -f config.cache
rm -f config.log
aclocal -I .
autoconf
automake -a --copy
