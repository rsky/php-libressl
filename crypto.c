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
   |          Ryusuke Sekiyama <rsky0711@gmail.com> (stream support)      |
   +----------------------------------------------------------------------+
 */

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php_libressl.h"
#include "ext_openssl/openssl.h"
#include <Zend/zend_smart_str.h>

/* {{{ proto bool libressl_encrypt(stream in, stream out, string method, string password [, long
options=0 [, string $iv=''[, string &$tag = ''[, string $aad = ''[, long $tag_length = 16]]]]])
   Encrypts given data with given method and key, returns raw or base64 encoded string */
PHP_FUNCTION(libressl_encrypt)
{
    zval *in = NULL, *out = NULL;
    php_stream *in_stream, *out_stream;
    zend_long options = 0, tag_len = 16;
    char *method = "", *password = "", *iv = "", *aad = "";
    size_t method_len = 0, password_len = 0, iv_len = 0, aad_len = 0;
    zval *tag = NULL;
    const EVP_CIPHER *cipher_type;
    EVP_CIPHER_CTX *cipher_ctx;
    struct php_openssl_cipher_mode mode;
    int i = 0, outlen = 0;
    zend_string *outbuf = NULL;
    zend_bool free_iv = 0, free_password = 0;

    ZEND_PARSE_PARAMETERS_START(4, 9)
            Z_PARAM_RESOURCE(in)
            Z_PARAM_RESOURCE(out)
            Z_PARAM_STRING(method, method_len)
            Z_PARAM_STRING(password, password_len)
            Z_PARAM_LONG(options)
            Z_PARAM_STRING(iv, iv_len)
            Z_PARAM_ZVAL_EX(tag, 0, 1)
            Z_PARAM_STRING(aad, aad_len)
            Z_PARAM_LONG(tag_len)
    ZEND_PARSE_PARAMETERS_END();

    php_stream_from_zval(in_stream, in);
    php_stream_from_zval(out_stream, out);

    PHP_OPENSSL_CHECK_SIZE_T_TO_INT(password_len, password);
    PHP_OPENSSL_CHECK_SIZE_T_TO_INT(aad_len, aad);
    PHP_OPENSSL_CHECK_LONG_TO_INT(tag_len, tag_len);

    cipher_type = EVP_get_cipherbyname(method);
    if (!cipher_type) {
        php_error_docref(NULL, E_WARNING, "Unknown cipher algorithm");
        RETURN_FALSE;
    }

    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) {
        php_error_docref(NULL, E_WARNING, "Failed to create cipher context");
        RETURN_FALSE;
    }

    php_openssl_load_cipher_mode(&mode, cipher_type);

    if (php_openssl_cipher_init(cipher_type, cipher_ctx, &mode,
                                &password, &password_len, &free_password,
                                &iv, &iv_len, &free_iv, NULL, (int)tag_len, options, 1) == FAILURE) {
        RETVAL_FALSE;
    } else {
        while (!php_stream_eof(in_stream)) {
            char tmp[1024];
            size_t len = php_stream_read(in_stream, tmp, sizeof(tmp));
            if (outbuf) {
                php_stream_write(out_stream, ZSTR_VAL(outbuf), (size_t) outlen);
                zend_string_release(outbuf);
                outbuf = NULL;
            }
            if (php_openssl_cipher_update(cipher_type, cipher_ctx, &mode, &outbuf, &outlen,
                                          tmp, len, aad, aad_len, 1) == FAILURE) {
                RETVAL_FALSE;
                break;
            }
            RETVAL_TRUE;
        }
    }

    if (Z_TYPE_P(return_value) == IS_TRUE && outbuf) {
        if (EVP_EncryptFinal(cipher_ctx, (unsigned char *) ZSTR_VAL(outbuf) + outlen, &i)) {
            php_stream_write(out_stream, ZSTR_VAL(outbuf), (size_t) outlen + i);

            if (mode.is_aead && tag) {
                zend_string *tag_str = zend_string_alloc((size_t) tag_len, 0);

                if (EVP_CIPHER_CTX_ctrl(cipher_ctx, mode.aead_get_tag_flag, (int) tag_len, ZSTR_VAL(tag_str)) == 1) {
                    zval_dtor(tag);
                    ZSTR_VAL(tag_str)[tag_len] = '\0';
                    ZSTR_LEN(tag_str) = (size_t) tag_len;
                    ZVAL_NEW_STR(tag, tag_str);
                } else {
                    php_error_docref(NULL, E_WARNING, "Retrieving verification tag failed");
                    RETVAL_FALSE;
                }
            } else if (tag) {
                zval_dtor(tag);
                ZVAL_NULL(tag);
                php_error_docref(NULL, E_WARNING,
                                 "The authenticated tag cannot be provided for cipher that doesn not support AEAD");
            } else if (mode.is_aead) {
                php_error_docref(NULL, E_WARNING, "A tag should be provided when using AEAD mode");
                RETVAL_FALSE;
            }
        } else {
            RETVAL_FALSE;
        }
    }

    if (outbuf) {
        zend_string_release(outbuf);
    }
    if (free_password) {
        efree(password);
    }
    if (free_iv) {
        efree(iv);
    }
    EVP_CIPHER_CTX_cleanup(cipher_ctx);
    EVP_CIPHER_CTX_free(cipher_ctx);
}
/* }}} */
/* {{{ proto bool libressl_decrypt(stream in, stream out, string method, string password [, long
options=0 [, string $iv = ''[, string $tag = ''[, string $aad = '']]]])
   Takes raw or base64 encoded string and decrypts it using given method and key */
PHP_FUNCTION(libressl_decrypt)
{
    zval *in = NULL, *out = NULL;
    php_stream *in_stream, *out_stream;
    zend_long options = 0;
    char *method = "", *password = "", *iv = "", *tag = NULL, *aad = "";
    size_t method_len = 0, password_len = 0, iv_len = 0, tag_len = 0, aad_len = 0;
    const EVP_CIPHER *cipher_type;
    EVP_CIPHER_CTX *cipher_ctx;
    struct php_openssl_cipher_mode mode;
    int i = 0, outlen = 0;
    zend_string *outbuf = NULL;
    zend_bool free_iv = 0, free_password = 0;

    ZEND_PARSE_PARAMETERS_START(4, 8)
            Z_PARAM_RESOURCE(in)
            Z_PARAM_RESOURCE(out)
            Z_PARAM_STRING(method, method_len)
            Z_PARAM_STRING(password, password_len)
            Z_PARAM_LONG(options)
            Z_PARAM_STRING(iv, iv_len)
            Z_PARAM_STRING(tag, tag_len)
            Z_PARAM_STRING(aad, aad_len)
    ZEND_PARSE_PARAMETERS_END();

    php_stream_from_zval(in_stream, in);
    php_stream_from_zval(out_stream, out);

    if (!method_len) {
        php_error_docref(NULL, E_WARNING, "Unknown cipher algorithm");
        RETURN_FALSE;
    }

    PHP_OPENSSL_CHECK_SIZE_T_TO_INT(password_len, password);
    PHP_OPENSSL_CHECK_SIZE_T_TO_INT(aad_len, aad);
    PHP_OPENSSL_CHECK_SIZE_T_TO_INT(tag_len, tag);

    cipher_type = EVP_get_cipherbyname(method);
    if (!cipher_type) {
        php_error_docref(NULL, E_WARNING, "Unknown cipher algorithm");
        RETURN_FALSE;
    }

    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) {
        php_error_docref(NULL, E_WARNING, "Failed to create cipher context");
        RETURN_FALSE;
    }

    php_openssl_load_cipher_mode(&mode, cipher_type);

    if (php_openssl_cipher_init(cipher_type, cipher_ctx, &mode,
                                &password, &password_len, &free_password,
                                &iv, &iv_len, &free_iv, tag, (int) tag_len, options, 0) == FAILURE) {
        RETVAL_FALSE;
    }

    if (mode.is_single_run_aead) {
        smart_str str = {0};
        while (!php_stream_eof(in_stream)) {
            char tmp[1024];
            size_t len = php_stream_read(in_stream, tmp, sizeof(tmp));
            smart_str_appendl(&str, tmp, len);
        }
        if (php_openssl_cipher_update(cipher_type, cipher_ctx, &mode, &outbuf, &outlen,
                                      ZSTR_VAL(str.s), ZSTR_LEN(str.s), aad, aad_len, 0) == FAILURE) {
            RETVAL_FALSE;
        }
    } else {
        while (!php_stream_eof(in_stream)) {
            char tmp[1024];
            size_t len = php_stream_read(in_stream, tmp, sizeof(tmp));
            if (outbuf) {
                php_stream_write(out_stream, ZSTR_VAL(outbuf), (size_t) outlen);
                zend_string_release(outbuf);
                outbuf = NULL;
            }
            if (php_openssl_cipher_update(cipher_type, cipher_ctx, &mode, &outbuf, &outlen,
                                          tmp, len, aad, aad_len, 0) == FAILURE) {
                RETVAL_FALSE;
                break;
            }
            RETVAL_TRUE;
        }
        if (Z_TYPE_P(return_value) == IS_TRUE) {
            if (!EVP_DecryptFinal(cipher_ctx, (unsigned char *)ZSTR_VAL(outbuf) + outlen, &i)) {
                RETVAL_FALSE;
            }
        }
    }

    if (Z_TYPE_P(return_value) == IS_TRUE && outbuf) {
        php_stream_write(out_stream, ZSTR_VAL(outbuf), (size_t) outlen + i);
    } else {
        php_openssl_store_errors();
        RETVAL_FALSE;
    }

    if (outbuf) {
        zend_string_release(outbuf);
    }
    if (free_password) {
        efree(password);
    }
    if (free_iv) {
        efree(iv);
    }
    EVP_CIPHER_CTX_cleanup(cipher_ctx);
    EVP_CIPHER_CTX_free(cipher_ctx);
}
/* }}} */


/* {{{ PHP Module Functions */

int php_libressl_crypto_startup(INIT_FUNC_ARGS)
{
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    OpenSSL_add_all_algorithms();

    return SUCCESS;
}

int php_libressl_crypto_shutdown(SHUTDOWN_FUNC_ARGS)
{
    EVP_cleanup();

    return SUCCESS;
}

int php_libressl_crypto_activate(INIT_FUNC_ARGS)
{
    return SUCCESS;
}

int php_libressl_crypto_deactivate(SHUTDOWN_FUNC_ARGS)
{
    return SUCCESS;
}

/* }}} */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: fdm=marker
 * vim: noet sw=4 ts=4
 */
