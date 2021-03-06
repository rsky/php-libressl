/*
  +----------------------------------------------------------------------+
  | PHP Version 7                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2016 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:                                                              |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <php.h>
#include <php_ini.h>
#include <ext/standard/info.h>
#include "php_libressl.h"

/* If you declare any globals in php_libressl.h uncomment this:
ZEND_DECLARE_MODULE_GLOBALS(libressl)
*/

/* True global resources - no need for thread safety here */
static int le_libressl;

/* {{{ Argument Information */

ZEND_BEGIN_ARG_INFO_EX(arginfo_libressl_encrypt, 0, 0, 4)
        ZEND_ARG_INFO(0, in)
        ZEND_ARG_INFO(0, out)
        ZEND_ARG_INFO(0, method)
        ZEND_ARG_INFO(0, password)
        ZEND_ARG_INFO(0, options)
        ZEND_ARG_INFO(0, iv)
        ZEND_ARG_INFO(1, tag)
        ZEND_ARG_INFO(0, aad)
        ZEND_ARG_INFO(0, tag_length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_libressl_decrypt, 0, 0, 4)
        ZEND_ARG_INFO(0, in) 
        ZEND_ARG_INFO(0, out)
        ZEND_ARG_INFO(0, method)
        ZEND_ARG_INFO(0, password)
        ZEND_ARG_INFO(0, options)
        ZEND_ARG_INFO(0, iv)
        ZEND_ARG_INFO(0, tag)
        ZEND_ARG_INFO(0, aad)
ZEND_END_ARG_INFO()

/* }}} */

/* {{{ PHP_INI
 */
/* Remove comments and fill if you need to have entries in php.ini
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("libressl.global_value",      "42", PHP_INI_ALL, OnUpdateLong, global_value, zend_libressl_globals, libressl_globals)
    STD_PHP_INI_ENTRY("libressl.global_string", "foobar", PHP_INI_ALL, OnUpdateString, global_string, zend_libressl_globals, libressl_globals)
PHP_INI_END()
*/
/* }}} */

/* Remove the following function when you have successfully modified config.m4
   so that your module can be compiled into PHP, it exists only for testing
   purposes. */

/* Every user-visible function in PHP should document itself in the source */
/* {{{ proto string confirm_libressl_compiled(string arg)
   Return a string to confirm that the module is compiled in */
PHP_FUNCTION(confirm_libressl_compiled)
{
	char *arg = NULL;
	size_t arg_len, len;
	zend_string *strg;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &arg, &arg_len) == FAILURE) {
		return;
	}

	strg = strpprintf(0, "Congratulations! You have successfully modified ext/%.78s/config.m4. Module %.78s is now compiled into PHP.", "libressl", arg);

	RETURN_STR(strg);
}
/* }}} */
/* The previous line is meant for vim and emacs, so it can correctly fold and
   unfold functions in source code. See the corresponding marks just before
   function definition, where the functions purpose is also documented. Please
   follow this convention for the convenience of others editing your code.
*/


/* {{{ php_libressl_init_globals
 */
/* Uncomment this function if you have INI entries
static void php_libressl_init_globals(zend_libressl_globals *libressl_globals)
{
	libressl_globals->global_value = 0;
	libressl_globals->global_string = NULL;
}
*/
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(libressl)
{
	/* If you have INI entries, uncomment these lines
	REGISTER_INI_ENTRIES();
	*/
	if (php_libressl_tls_startup(INIT_FUNC_ARGS_PASSTHRU) == FAILURE) {
		return FAILURE;
	}
	if (php_libressl_crypto_startup(INIT_FUNC_ARGS_PASSTHRU) == FAILURE) {
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(libressl)
{
	/* uncomment this line if you have INI entries
	UNREGISTER_INI_ENTRIES();
	*/
	if (php_libressl_crypto_shutdown(SHUTDOWN_FUNC_ARGS_PASSTHRU) == FAILURE) {
		return FAILURE;
	}
	if (php_libressl_tls_shutdown(SHUTDOWN_FUNC_ARGS_PASSTHRU) == FAILURE) {
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(libressl)
{
#if defined(COMPILE_DL_LIBRESSL) && defined(ZTS)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	if (php_libressl_tls_activate(INIT_FUNC_ARGS_PASSTHRU) == FAILURE) {
		return FAILURE;
	}
	if (php_libressl_crypto_activate(INIT_FUNC_ARGS_PASSTHRU) == FAILURE) {
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request end */
/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(libressl)
{
	if (php_libressl_crypto_deactivate(SHUTDOWN_FUNC_ARGS_PASSTHRU) == FAILURE) {
		return FAILURE;
	}
	if (php_libressl_tls_deactivate(SHUTDOWN_FUNC_ARGS_PASSTHRU) == FAILURE) {
		return FAILURE;
	}
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(libressl)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "libressl support", "enabled");
	php_info_print_table_end();

	/* Remove comments if you have entries in php.ini
	DISPLAY_INI_ENTRIES();
	*/
}
/* }}} */

/* {{{ libressl_functions[]
 *
 * Every user visible function must have an entry in libressl_functions[].
 */
const zend_function_entry libressl_functions[] = {
	PHP_FE(confirm_libressl_compiled,	NULL)		/* For testing, remove later. */
	PHP_FE(libressl_encrypt, arginfo_libressl_encrypt)
	PHP_FE(libressl_decrypt, arginfo_libressl_decrypt)
	PHP_FE_END
};
/* }}} */

/* {{{ libressl_module_entry
 */
zend_module_entry libressl_module_entry = {
	STANDARD_MODULE_HEADER,
	"libressl",
	libressl_functions,
	PHP_MINIT(libressl),
	PHP_MSHUTDOWN(libressl),
	PHP_RINIT(libressl),
	PHP_RSHUTDOWN(libressl),
	PHP_MINFO(libressl),
	PHP_LIBRESSL_VERSION,
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_LIBRESSL
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(libressl)
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
