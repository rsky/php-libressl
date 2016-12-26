dnl $Id$
dnl config.m4 for extension libressl

PHP_ARG_WITH(libressl, for libressl support,
[  --with-libressl             Include libressl support])

if test "$PHP_LIBRESSL" != "no"; then
  dnl # --with-libressl -> check with-path
  SEARCH_PATH="/usr/local /usr"
  SEARCH_FOR="/include/tls.h"
  if test -r "$PHP_LIBRESSL$SEARCH_FOR"; then
    LIBRESSL_DIR=$PHP_LIBRESSL
  else # search default path list
    AC_MSG_CHECKING([for libressl files in default path])
    for i in $SEARCH_PATH ; do
      if test -r $i/$SEARCH_FOR; then
        LIBRESSL_DIR=$i
        AC_MSG_RESULT(found in $i)
      fi
    done
  fi

  if test -z "$LIBRESSL_DIR"; then
    AC_MSG_RESULT([not found])
    AC_MSG_ERROR([Please reinstall the libressl distribution])
  fi

  dnl # --with-libressl -> add include path
  PHP_ADD_INCLUDE($LIBRESSL_DIR/include)

  dnl # --with-libressl -> check for lib and symbol presence
  LIBTLSNAME=tls
  LIBTLSSYMBOL=tls_new

  PHP_CHECK_LIBRARY($LIBTLSNAME,$LIBTLSSYMBOL,
  [
    PHP_ADD_LIBRARY_WITH_PATH($LIBTLSNAME, $LIBRESSL_DIR/$PHP_LIBDIR, LIBRESSL_SHARED_LIBADD)
    AC_DEFINE(HAVE_LIBRESSL_LIBTLS,1,[ ])
  ],[
    AC_MSG_ERROR([wrong libtls lib version or lib not found])
  ],[
    -L$LIBRESSL_DIR/$PHP_LIBDIR
  ])

  LIBCRYPTONAME=crypto
  LIBCRYPTOSYMBOL=ENGINE_init

  PHP_CHECK_LIBRARY($LIBCRYPTONAME,$LIBCRYPTOSYMBOL,
  [
    PHP_ADD_LIBRARY_WITH_PATH($LIBCRYPTONAME, $LIBRESSL_DIR/$PHP_LIBDIR, LIBRESSL_SHARED_LIBADD)
    AC_DEFINE(HAVE_LIBRESSL_LIBCRYPTO,1,[ ])
  ],[
    AC_MSG_ERROR([wrong libcrypto lib version or lib not found])
  ],[
    -L$LIBRESSL_DIR/$PHP_LIBDIR
  ])

  PHP_SUBST(LIBRESSL_SHARED_LIBADD)

  PHP_NEW_EXTENSION(libressl, libressl.c tls.c crypto.c php_src_openssl.c, $ext_shared,,
                    -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1)
fi
