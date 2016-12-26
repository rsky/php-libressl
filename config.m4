dnl $Id$
dnl config.m4 for extension libressl

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

dnl PHP_ARG_WITH(libressl, for libressl support,
dnl Make sure that the comment is aligned:
dnl [  --with-libressl             Include libressl support])

dnl Otherwise use enable:

dnl PHP_ARG_ENABLE(libressl, whether to enable libressl support,
dnl Make sure that the comment is aligned:
dnl [  --enable-libressl           Enable libressl support])

if test "$PHP_LIBRESSL" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-libressl -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/libressl.h"  # you most likely want to change this
  dnl if test -r $PHP_LIBRESSL/$SEARCH_FOR; then # path given as parameter
  dnl   LIBRESSL_DIR=$PHP_LIBRESSL
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for libressl files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       LIBRESSL_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$LIBRESSL_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the libressl distribution])
  dnl fi

  dnl # --with-libressl -> add include path
  dnl PHP_ADD_INCLUDE($LIBRESSL_DIR/include)

  dnl # --with-libressl -> check for lib and symbol presence
  dnl LIBNAME=libressl # you may want to change this
  dnl LIBSYMBOL=libressl # you most likely want to change this 

  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $LIBRESSL_DIR/$PHP_LIBDIR, LIBRESSL_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_LIBRESSLLIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong libressl lib version or lib not found])
  dnl ],[
  dnl   -L$LIBRESSL_DIR/$PHP_LIBDIR -lm
  dnl ])
  dnl
  dnl PHP_SUBST(LIBRESSL_SHARED_LIBADD)

  PHP_NEW_EXTENSION(libressl, libressl.c, $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1)
fi
