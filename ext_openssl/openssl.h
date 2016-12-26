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
   | Authors: Stig Venaas <venaas@php.net>                                |
   |          Wez Furlong <wez@thebrainroom.com>                          |
   |          Sascha Kettler <kettler@gmx.net>                            |
   |          Pierre-Alain Joye <pierre@php.net>                          |
   |          Marc Delling <delling@silpion.de> (PKCS12 functions)        |
   |          Jakub Zelenka <bukka@php.net>                               |
   +----------------------------------------------------------------------+
 */

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"

/* OpenSSL includes */
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#define OPENSSL_ZERO_PADDING 2

/* number conversion flags checks */
#define PHP_OPENSSL_CHECK_NUMBER_CONVERSION(_cond, _name) \
	do { \
		if (_cond) { \
			php_error_docref(NULL, E_WARNING, #_name" is too long"); \
			RETURN_FALSE; \
		} \
	} while(0)
/* check if size_t can be safely casted to int */
#define PHP_OPENSSL_CHECK_SIZE_T_TO_INT(_var, _name) \
	PHP_OPENSSL_CHECK_NUMBER_CONVERSION(ZEND_SIZE_T_INT_OVFL(_var), _name)
/* check if long can be safely casted to int */
#define PHP_OPENSSL_CHECK_LONG_TO_INT(_var, _name) \
	PHP_OPENSSL_CHECK_NUMBER_CONVERSION(ZEND_LONG_EXCEEDS_INT(_var), _name)

/* {{{ php_openssl_store_errors */
void php_openssl_store_errors();

/* Cipher mode info */
struct php_openssl_cipher_mode {
	zend_bool is_aead;
	zend_bool is_single_run_aead;
	int aead_get_tag_flag;
	int aead_set_tag_flag;
	int aead_ivlen_flag;
};

void php_openssl_load_cipher_mode(struct php_openssl_cipher_mode *mode, const EVP_CIPHER *cipher_type);

int php_openssl_cipher_init(const EVP_CIPHER *cipher_type,
		EVP_CIPHER_CTX *cipher_ctx, struct php_openssl_cipher_mode *mode,
		char **ppassword, size_t *ppassword_len, zend_bool *free_password,
		char **piv, size_t *piv_len, zend_bool *free_iv,
		char *tag, int tag_len, zend_long options, int enc);

int php_openssl_cipher_update(const EVP_CIPHER *cipher_type,
		EVP_CIPHER_CTX *cipher_ctx, struct php_openssl_cipher_mode *mode,
		zend_string **poutbuf, int *poutlen, char *data, size_t data_len,
		char *aad, size_t aad_len, int enc);

/*
 * Local variables:
 * tab-width: 8
 * c-basic-offset: 8
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */

