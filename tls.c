#include "php_libressl.h"
#include <tls.h>

/* {{{ Class Globals */

static zend_class_entry *ce_tls;
static zend_class_entry *ce_tls_client;
static zend_class_entry *ce_tls_server;
static zend_class_entry *ce_tls_server_conn;
static zend_class_entry *ce_tls_config;
static zend_class_entry *ce_tls_util;

static zend_object_handlers tls_object_handlers;
static zend_object_handlers tls_config_object_handlers;

/* }}} */

/* {{{ Object Handler Prototypes */

static void php_tls_object_free_storage(zend_object *object);
static void php_tls_config_object_free_storage(zend_object *object);

static zend_object *php_tls_object_create(zend_class_entry *class_type);
static zend_object *php_tls_config_object_create(zend_class_entry *class_type);

/* }}} */

/* {{{ tls Method Prototypes */

static PHP_METHOD(Tls, getError);

static PHP_METHOD(Tls, configure);

static PHP_METHOD(Tls, handshake);
static PHP_METHOD(Tls, read);
static PHP_METHOD(Tls, write);
static PHP_METHOD(Tls, close);

static PHP_METHOD(Tls, peerCertProvided);
static PHP_METHOD(Tls, peerCertContainsName);

static PHP_METHOD(Tls, peerCertHash);
static PHP_METHOD(Tls, peerCertIssuer);
static PHP_METHOD(Tls, peerCertSubject);
static PHP_METHOD(Tls, peerCertNotBefore);
static PHP_METHOD(Tls, peerCertNotAfter);

static PHP_METHOD(Tls, connVersion);
static PHP_METHOD(Tls, connCipher);

typedef const char *(*_tls_str_func_t)(struct tls *);
typedef time_t(*_tls_time_func_t)(struct tls *);

static void php_tls_str_func(INTERNAL_FUNCTION_PARAMETERS, _tls_str_func_t func);
static void php_tls_time_func(INTERNAL_FUNCTION_PARAMETERS, _tls_time_func_t func);

/* }}} */

/* {{{ tls client Method Prototypes */

static PHP_METHOD(TlsClient, connect);
static PHP_METHOD(TlsClient, connectFds);
static PHP_METHOD(TlsClient, connectSocket);

/* }}} */

/* {{{ tls server Method Prototypes */

static PHP_METHOD(TlsServer, acceptFds);
static PHP_METHOD(TlsServer, acceptSocket);

/* }}} */

/* {{{ tls_config Method Prototypes */

static PHP_METHOD(TlsConfig, getError);

static PHP_METHOD(TlsConfig, setCaFile);
static PHP_METHOD(TlsConfig, setCaPath);
static PHP_METHOD(TlsConfig, setCa);

static PHP_METHOD(TlsConfig, setCertFile);
static PHP_METHOD(TlsConfig, setCert);

static PHP_METHOD(TlsConfig, setCiphers);
static PHP_METHOD(TlsConfig, setDheParams);
static PHP_METHOD(TlsConfig, setEcdheCurve);

static PHP_METHOD(TlsConfig, setKeyFile);
static PHP_METHOD(TlsConfig, setKey);

static PHP_METHOD(TlsConfig, setKeypairFile);
static PHP_METHOD(TlsConfig, setKeypair);

static PHP_METHOD(TlsConfig, setProtocols);
static PHP_METHOD(TlsConfig, setVerifyDepth);

static PHP_METHOD(TlsConfig, preferCiphersClient);
static PHP_METHOD(TlsConfig, preferCiphersServer);

static PHP_METHOD(TlsConfig, insecureNoVerifyCert);
static PHP_METHOD(TlsConfig, insecureNoVerifyName);
static PHP_METHOD(TlsConfig, insecureNoVerifyTime);
static PHP_METHOD(TlsConfig, verify);

static PHP_METHOD(TlsConfig, verifyClient);
static PHP_METHOD(TlsConfig, verifyClientOptional);

static PHP_METHOD(TlsConfig, clearKeys);
static PHP_METHOD(TlsConfig, parseProtocols);

typedef int(*_tls_config_str_func_t)(struct tls_config *, const char *);
typedef int(*_tls_config_mem_func_t)(struct tls_config *, const uint8_t *, size_t);
typedef void(*_tls_config_void_func_t)(struct tls_config *);

static void php_tls_config_path_setter(INTERNAL_FUNCTION_PARAMETERS, _tls_config_str_func_t func);
static void php_tls_config_mem_setter(INTERNAL_FUNCTION_PARAMETERS, _tls_config_mem_func_t func);
static void php_tls_config_str_setter(INTERNAL_FUNCTION_PARAMETERS, _tls_config_str_func_t func);
static void php_tls_config_void_func(INTERNAL_FUNCTION_PARAMETERS, _tls_config_void_func_t func);

/* }}} */

/* {{{ tls Utility Method Prototypes */

static PHP_METHOD(TlsUtil, loadFile);

/* }}} */

/* {{{ Argument Information */

ZEND_BEGIN_ARG_INFO_EX(arginfo_tls_none, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_tls_configure, 0, 0, 0)
{ "config", ZEND_NS_NAME("Tls", "Config"), IS_OBJECT, 0, 0, 0 },
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_tls_read, 0, 0, 0)
ZEND_ARG_TYPE_INFO(0, "length", IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_tls_write, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, "data", IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_tls_peer_cert_contains_name, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, "name", IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_tls_accept_fds, 0, 0, 2)
ZEND_ARG_TYPE_INFO(0, "fd_read", IS_LONG, 0)
ZEND_ARG_TYPE_INFO(0, "fd_write", IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_tls_accept_socket, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, "socket", IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_tls_connect, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, "host", IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, "port", IS_STRING, 1)
ZEND_ARG_TYPE_INFO(0, "servername", IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_tls_connect_fds, 0, 0, 2)
ZEND_ARG_TYPE_INFO(0, "fd_read", IS_LONG, 0)
ZEND_ARG_TYPE_INFO(0, "fd_write", IS_LONG, 0)
ZEND_ARG_TYPE_INFO(0, "servername", IS_STRING, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_tls_connect_socket, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, "socket", IS_LONG, 0)
ZEND_ARG_TYPE_INFO(0, "servername", IS_STRING, 1)
ZEND_END_ARG_INFO()

#define TLS_CONFIG_SINGLE_TYPED_ARG_INFO(name, type) \
ZEND_BEGIN_ARG_INFO_EX(arginfo_tls_config_##name, 0, 0, 1) \
ZEND_ARG_TYPE_INFO(0, name, type, 0) \
ZEND_END_ARG_INFO()
#define TLS_CONFIG_SINGLE_STRING_ARG_INFO(name) TLS_CONFIG_SINGLE_TYPED_ARG_INFO(name, IS_STRING)
#define TLS_CONFIG_SINGLE_LONG_ARG_INFO(name) TLS_CONFIG_SINGLE_TYPED_ARG_INFO(name, IS_LONG)

TLS_CONFIG_SINGLE_STRING_ARG_INFO(file)
TLS_CONFIG_SINGLE_STRING_ARG_INFO(path)
TLS_CONFIG_SINGLE_STRING_ARG_INFO(ca)
TLS_CONFIG_SINGLE_STRING_ARG_INFO(cert)
TLS_CONFIG_SINGLE_STRING_ARG_INFO(ciphers)
TLS_CONFIG_SINGLE_STRING_ARG_INFO(params)
TLS_CONFIG_SINGLE_STRING_ARG_INFO(name)
TLS_CONFIG_SINGLE_STRING_ARG_INFO(key)
TLS_CONFIG_SINGLE_LONG_ARG_INFO(protocols)
TLS_CONFIG_SINGLE_LONG_ARG_INFO(verify_depth)
TLS_CONFIG_SINGLE_STRING_ARG_INFO(protostr)

ZEND_BEGIN_ARG_INFO_EX(arginfo_tls_config_keypair_file, 0, 0, 2)
ZEND_ARG_TYPE_INFO(0, cert_file, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, ca_file,   IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_tls_config_keypair, 0, 0, 2)
ZEND_ARG_TYPE_INFO(0, cert, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, ca,   IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_tls_load_file, 0, 0, 1)
ZEND_ARG_TYPE_INFO(0, file,     IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, password, IS_STRING, 0)
ZEND_END_ARG_INFO()

/* }}} */

/* {{{ Function Tables */

static zend_function_entry tls_base_methods[] = {
        PHP_ME(Tls, getError,  arginfo_tls_none,      ZEND_ACC_PUBLIC)
        PHP_ME(Tls, configure, arginfo_tls_configure, ZEND_ACC_PUBLIC)
        PHP_ME(Tls, handshake, arginfo_tls_none,      ZEND_ACC_PUBLIC)
        PHP_ME(Tls, read,      arginfo_tls_read,      ZEND_ACC_PUBLIC)
        PHP_ME(Tls, write,     arginfo_tls_write,     ZEND_ACC_PUBLIC)
        PHP_ME(Tls, close,     arginfo_tls_none,      ZEND_ACC_PUBLIC)
        PHP_ME(Tls, peerCertProvided,  arginfo_tls_none, ZEND_ACC_PUBLIC)
        PHP_ME(Tls, peerCertContainsName, arginfo_tls_peer_cert_contains_name, ZEND_ACC_PUBLIC)
        PHP_ME(Tls, peerCertHash,      arginfo_tls_none, ZEND_ACC_PUBLIC)
        PHP_ME(Tls, peerCertIssuer,    arginfo_tls_none, ZEND_ACC_PUBLIC)
        PHP_ME(Tls, peerCertSubject,   arginfo_tls_none, ZEND_ACC_PUBLIC)
        PHP_ME(Tls, peerCertNotBefore, arginfo_tls_none, ZEND_ACC_PUBLIC)
        PHP_ME(Tls, peerCertNotAfter,  arginfo_tls_none, ZEND_ACC_PUBLIC)
        PHP_ME(Tls, connVersion,       arginfo_tls_none, ZEND_ACC_PUBLIC)
        PHP_ME(Tls, connCipher,        arginfo_tls_none, ZEND_ACC_PUBLIC)
        PHP_FE_END
};

static zend_function_entry tls_client_methods[] = {
        PHP_ME(TlsClient, connect,       arginfo_tls_connect,        ZEND_ACC_PUBLIC)
        PHP_ME(TlsClient, connectFds,    arginfo_tls_connect_fds,    ZEND_ACC_PUBLIC)
        PHP_ME(TlsClient, connectSocket, arginfo_tls_connect_socket, ZEND_ACC_PUBLIC)
        PHP_FE_END
};

static zend_function_entry tls_server_methods[] = {
        PHP_ME(TlsServer, acceptFds,    arginfo_tls_accept_fds,    ZEND_ACC_PUBLIC)
        PHP_ME(TlsServer, acceptSocket, arginfo_tls_accept_socket, ZEND_ACC_PUBLIC)
        PHP_FE_END
};

static zend_function_entry tls_config_methods[] = {
        PHP_ME(TlsConfig, getError,             arginfo_tls_none, ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, setCaFile,            arginfo_tls_config_file,    ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, setCaPath,            arginfo_tls_config_path,    ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, setCa,                arginfo_tls_config_ca,      ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, setCertFile,          arginfo_tls_config_file,    ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, setCert,              arginfo_tls_config_cert,    ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, setCiphers,           arginfo_tls_config_ciphers, ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, setDheParams,         arginfo_tls_config_params,  ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, setEcdheCurve,        arginfo_tls_config_name,    ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, setKeyFile,           arginfo_tls_config_file,    ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, setKey,               arginfo_tls_config_key,     ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, setKeypairFile,       arginfo_tls_config_keypair_file, ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, setKeypair,           arginfo_tls_config_keypair,      ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, setProtocols,         arginfo_tls_config_protocols,    ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, setVerifyDepth,       arginfo_tls_config_verify_depth, ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, preferCiphersClient,  arginfo_tls_none, ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, preferCiphersServer,  arginfo_tls_none, ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, insecureNoVerifyCert, arginfo_tls_none, ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, insecureNoVerifyName, arginfo_tls_none, ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, insecureNoVerifyTime, arginfo_tls_none, ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, verify,               arginfo_tls_none, ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, verifyClient,         arginfo_tls_none, ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, verifyClientOptional, arginfo_tls_none, ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, clearKeys,            arginfo_tls_none, ZEND_ACC_PUBLIC)
        PHP_ME(TlsConfig, parseProtocols,       arginfo_tls_config_protostr, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
        PHP_FE_END
};

static zend_function_entry tls_util_methods[] = {
        PHP_ME(TlsUtil, loadFile, arginfo_tls_load_file, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
        PHP_FE_END
};

/* }}} */

/* {{{ PHP Module Functions */

int php_libressl_tls_startup(INIT_FUNC_ARGS)
{
    zend_class_entry ce_base, ce_client, ce_server, ce_server_conn, ce_config, ce_util;

    if (tls_init() != 0) {
        return FAILURE;
    }

    memcpy(&tls_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    tls_object_handlers.offset = (int) XtOffsetOf(php_tls_obj, std);
    tls_object_handlers.free_obj = php_tls_object_free_storage;
    tls_object_handlers.clone_obj = NULL;

    memcpy(&tls_config_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    tls_config_object_handlers.offset = (int) XtOffsetOf(php_tls_config_obj, std);
    tls_config_object_handlers.free_obj = php_tls_config_object_free_storage;
    tls_config_object_handlers.clone_obj = NULL;

    INIT_NS_CLASS_ENTRY(ce_base, "Tls", "Tls", tls_base_methods);
    ce_base.create_object = php_tls_object_create;
    ce_tls = zend_register_internal_class(&ce_base);
    ce_tls->ce_flags |= ZEND_ACC_EXPLICIT_ABSTRACT_CLASS;

#define REGISTER_TLS_CLASS_CONST(const_name) \
    zend_declare_class_constant_long(ce_tls, #const_name, sizeof(#const_name)-1, TLS_##const_name);
    REGISTER_TLS_CLASS_CONST(API)
    REGISTER_TLS_CLASS_CONST(PROTOCOL_TLSv1_0)
    REGISTER_TLS_CLASS_CONST(PROTOCOL_TLSv1_1)
    REGISTER_TLS_CLASS_CONST(PROTOCOL_TLSv1_2)
    REGISTER_TLS_CLASS_CONST(PROTOCOL_TLSv1)
    REGISTER_TLS_CLASS_CONST(PROTOCOLS_ALL)
    REGISTER_TLS_CLASS_CONST(PROTOCOLS_DEFAULT)
    REGISTER_TLS_CLASS_CONST(WANT_POLLIN)
    REGISTER_TLS_CLASS_CONST(WANT_POLLOUT)

    INIT_NS_CLASS_ENTRY(ce_client, "Tls", "Client", tls_client_methods);
    ce_client.create_object = php_tls_object_create;
    ce_tls_client = zend_register_internal_class_ex(&ce_client, ce_tls);

    INIT_NS_CLASS_ENTRY(ce_server, "Tls", "Server", tls_server_methods);
    ce_server.create_object = php_tls_object_create;
    ce_tls_server = zend_register_internal_class_ex(&ce_server, ce_tls);

    INIT_NS_CLASS_ENTRY(ce_server_conn, "Tls", "ServerConnection", NULL);
    ce_server_conn.create_object = php_tls_object_create;
    ce_tls_server_conn = zend_register_internal_class_ex(&ce_server_conn, ce_tls);

    INIT_NS_CLASS_ENTRY(ce_config, "Tls", "Config", tls_config_methods);
    ce_config.create_object = php_tls_config_object_create;
    ce_tls_config = zend_register_internal_class(&ce_config);

    INIT_NS_CLASS_ENTRY(ce_util, "Tls", "Util", tls_util_methods);
    ce_tls_util = zend_register_internal_class(&ce_util);

    return SUCCESS;
}

int php_libressl_tls_shutdown(SHUTDOWN_FUNC_ARGS)
{
    return SUCCESS;
}

int php_libressl_tls_activate(INIT_FUNC_ARGS)
{
    return SUCCESS;
}

int php_libressl_tls_deactivate(SHUTDOWN_FUNC_ARGS)
{
    return SUCCESS;
}

/* }}} */

static void php_tls_object_free_storage(zend_object *object) /* {{{ */
{
    php_tls_obj *intern = php_tls_obj_from_obj(object);
    if (intern->ctx) {
        tls_free(intern->ctx);
    }
    zend_object_std_dtor(&intern->std);
}
/* }}} */

static void php_tls_config_object_free_storage(zend_object *object) /* {{{ */
{
    php_tls_config_obj *intern = php_tls_config_obj_from_obj(object);
    if (intern->config) {
        tls_config_free(intern->config);
    }
    zend_object_std_dtor(&intern->std);
}
/* }}} */

static zend_object *php_tls_object_create(zend_class_entry *class_type) /* {{{ */
{
    php_tls_obj *intern;

    intern = ecalloc(1, sizeof(php_tls_obj) + zend_object_properties_size(class_type));

    zend_object_std_init(&intern->std, class_type);
    object_properties_init(&intern->std, class_type);
    intern->std.handlers = &tls_object_handlers;

    if ((uintptr_t) class_type == (uintptr_t) ce_tls_server) {
        intern->ctx = tls_server();
    } else if ((uintptr_t) class_type == (uintptr_t) ce_tls_client) {
        intern->ctx = tls_client();
    } else {
        intern->ctx = NULL;
    }

    return &intern->std;
}
/* }}} */

static zend_object *php_tls_config_object_create(zend_class_entry *class_type) /* {{{ */
{
    php_tls_config_obj *intern;

    intern = ecalloc(1, sizeof(php_tls_obj) + zend_object_properties_size(class_type));

    zend_object_std_init(&intern->std, class_type);
    object_properties_init(&intern->std, class_type);
    intern->std.handlers = &tls_config_object_handlers;

    intern->config = tls_config_new();

    return &intern->std;
}
/* }}} */

/* {{{ proto string Tls\Tls::getError()
 */
static PHP_METHOD(Tls, getError)
{
    php_tls_obj *intern = php_tls_obj_from_zval(getThis());
    if (zend_parse_parameters_none() == SUCCESS) {
        const char *msg = tls_error(intern->ctx);
        if (msg) {
            RETURN_STRING(msg);
        } else {
            RETURN_NULL();
        }
    }
}
/* }}} */

/* {{{ proto string Tls\TlsConfig::getError()
 */
static PHP_METHOD(TlsConfig, getError)
{
    php_tls_config_obj *intern = php_tls_config_obj_from_zval(getThis());
    if (zend_parse_parameters_none() == SUCCESS) {
        const char *msg = tls_config_error(intern->config);
        if (msg) {
            RETURN_STRING(msg);
        } else {
            RETURN_NULL();
        }
    }
}
/* }}} */

static void php_tls_str_func(INTERNAL_FUNCTION_PARAMETERS, _tls_str_func_t func) /* {{{ */
{
    php_tls_obj *intern = php_tls_obj_from_zval(getThis());
    if (zend_parse_parameters_none() == SUCCESS) {
        const char *str = func(intern->ctx);
        if (str) {
            RETURN_STRING(str);
        } else {
            RETURN_NULL();
        }
    }
}
/* }}} */

static void php_tls_time_func(INTERNAL_FUNCTION_PARAMETERS, _tls_time_func_t func) /* {{{ */
{
    php_tls_obj *intern = php_tls_obj_from_zval(getThis());
    if (zend_parse_parameters_none() == SUCCESS) {
        time_t time_val = func(intern->ctx);
        RETURN_LONG(time_val);
    }
}
/* }}} */

/* {{{ proto void Tls\Tls::configure(Tls\Config config)
 */
static PHP_METHOD(Tls, configure)
{
    php_tls_obj *intern = php_tls_obj_from_zval(getThis());

    zval *_config = NULL;
    struct tls_config *config;

    ZEND_PARSE_PARAMETERS_START(0, 1)
            Z_PARAM_OPTIONAL
            Z_PARAM_OBJECT_OF_CLASS(_config, ce_tls_config)
    ZEND_PARSE_PARAMETERS_END();

    config = (_config) ? php_tls_config_obj_from_zval(_config)->config : NULL;
    tls_configure(intern->ctx, config);
}
/* }}} */

/* proto bool Tls\Tls::handshake() {{{
 */
static PHP_METHOD(Tls, handshake)
{
    php_tls_obj *intern = php_tls_obj_from_zval(getThis());
    if (zend_parse_parameters_none() == SUCCESS) {
        RETURN_BOOL(tls_handshake(intern->ctx) == 0);
    }
}
/* }}} */

/* proto string Tls\Tls::read([int length]) {{{
 */
static PHP_METHOD(Tls, read)
{
    php_tls_obj *intern = php_tls_obj_from_zval(getThis());
    zend_long length = 1024;
    char *buf;
    ssize_t read_len;

    ZEND_PARSE_PARAMETERS_START(0, 1)
            Z_PARAM_OPTIONAL
            Z_PARAM_LONG(length)
    ZEND_PARSE_PARAMETERS_END();

    if (length <= 0) {
        php_error_docref(NULL, E_WARNING, "Length parameter must be greater than 0");
        RETURN_NULL();
    }
    buf = (char *) emalloc(length);
    if (buf == NULL) {
        RETURN_NULL();
    }

    read_len = tls_read(intern->ctx, buf, (size_t) length);
    if (read_len >= 0) {
        RETVAL_STRINGL(buf, read_len);
    } else {
        RETVAL_NULL();
    }
    efree(buf);
}
/* }}} */

/* proto int Tls\Tls::write(string data) {{{
 */
static PHP_METHOD(Tls, write)
{
    php_tls_obj *intern = php_tls_obj_from_zval(getThis());
    zend_string *data = NULL;
    ssize_t write_len;

    ZEND_PARSE_PARAMETERS_START(1, 1)
            Z_PARAM_STR(data)
    ZEND_PARSE_PARAMETERS_END();

    write_len = tls_write(intern->ctx, ZSTR_VAL(data), ZSTR_LEN(data));
    RETURN_LONG(write_len);
}
/* }}} */

/* proto bool Tls\Tls::close() {{{
 */
static PHP_METHOD(Tls, close)
{
    php_tls_obj *intern = php_tls_obj_from_zval(getThis());
    if (zend_parse_parameters_none() == SUCCESS) {
        RETURN_BOOL(tls_close(intern->ctx) == 0);
    }
}
/* }}} */

/* proto bool Tls\Tls::peerCertProvided() {{{
 */
static PHP_METHOD(Tls, peerCertProvided)
{
    php_tls_obj *intern = php_tls_obj_from_zval(getThis());
    if (zend_parse_parameters_none() == SUCCESS) {
        RETURN_BOOL(tls_peer_cert_provided(intern->ctx) == 0);
    }
}
/* }}} */

/* proto bool Tls\Tls::peerCertContainsName(string name) {{{
 */
static PHP_METHOD(Tls, peerCertContainsName)
{
    php_tls_obj *intern = php_tls_obj_from_zval(getThis());
    zend_string *name = NULL;

    ZEND_PARSE_PARAMETERS_START(1, 1)
            Z_PARAM_STR(name)
    ZEND_PARSE_PARAMETERS_END();

    RETURN_BOOL(tls_peer_cert_contains_name(intern->ctx, ZSTR_VAL(name)) == 0);
}
/* }}} */

/* proto string Tls\Tls::peerCertHash() {{{
 */
static PHP_METHOD(Tls, peerCertHash)
{
    php_tls_str_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_peer_cert_hash);
}
/* }}} */

/* proto string Tls\Tls::peerCertIssuer() {{{
 */
static PHP_METHOD(Tls, peerCertIssuer)
{
    php_tls_str_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_peer_cert_issuer);
}
/* }}} */

/* proto string Tls\Tls::() {{{
 */
static PHP_METHOD(Tls, peerCertSubject)
{
    php_tls_str_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_peer_cert_subject);
}
/* }}} */

/* proto long Tls\Tls::peerCertNotBefore() {{{
 */
static PHP_METHOD(Tls, peerCertNotBefore)
{
    php_tls_time_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_peer_cert_notbefore);
}
/* }}} */

/* proto long Tls\Tls::peerCertNotAfter() {{{
 */
static PHP_METHOD(Tls, peerCertNotAfter)
{
    php_tls_time_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_peer_cert_notafter);
}
/* }}} */

/* proto string Tls\Tls::connVersion() {{{
 */
static PHP_METHOD(Tls, connVersion)
{
    php_tls_str_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_conn_version);
}
/* }}} */

/* proto string Tls\Tls::connCipher() {{{
 */
static PHP_METHOD(Tls, connCipher)
{
    php_tls_str_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_conn_cipher);
}
/* }}} */

static void handle_server_conn(INTERNAL_FUNCTION_PARAMETERS, struct tls *conn) /* {{{ */
{
    if (conn == NULL) {
        RETURN_NULL();
    }

    if (object_init_ex(return_value, ce_tls_server_conn) == SUCCESS) {
        php_tls_obj *server_conn = php_tls_obj_from_zval(return_value);
        server_conn->ctx = conn;
    } else {
        tls_free(conn);
        RETURN_NULL();
    }
}
/* }}} */

/* {{{ proto int Tls\Client::connect(string host[, string port[, string servername]])
 */
static PHP_METHOD(TlsClient, connect)
{
    php_tls_obj *intern = php_tls_obj_from_zval(getThis());

    zend_string *host_str = NULL, *port_str = NULL, *servername_str = NULL;
    const char *host, *port, *servername;
    int rv;

    ZEND_PARSE_PARAMETERS_START(1, 3)
            Z_PARAM_STR(host_str)
            Z_PARAM_OPTIONAL
            Z_PARAM_STR_EX(port_str, 1, 0)
            Z_PARAM_STR_EX(servername_str, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    host = ZSTR_VAL(host_str);
    port = (port_str) ? ZSTR_VAL(port_str) : NULL;
    servername = (servername_str) ? ZSTR_VAL(servername_str) : NULL;

    rv = tls_connect_servername(intern->ctx, host, port, servername);
    RETURN_LONG(rv);
}
/* }}} */

/* {{{ proto int Tls\Client::connect(string host[, string port[, string servername]])
 */
static PHP_METHOD(TlsClient, connectFds)
{
    php_tls_obj *intern = php_tls_obj_from_zval(getThis());

    zend_long fd_read = 0, fd_write = 0;
    zend_string *servername_str = NULL;
    const char *servername;
    int rv;

    ZEND_PARSE_PARAMETERS_START(2, 3)
            Z_PARAM_LONG(fd_read)
            Z_PARAM_LONG(fd_write)
            Z_PARAM_OPTIONAL
            Z_PARAM_STR_EX(servername_str, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    if (ZEND_LONG_INT_OVFL(fd_read) || fd_read < 0) {
        php_error_docref(NULL, E_WARNING, "fd_read is out of range");
        RETURN_NULL();
    }
    if (ZEND_LONG_INT_OVFL(fd_write) || fd_write < 0) {
        php_error_docref(NULL, E_WARNING, "fd_write is out of range");
        RETURN_NULL();
    }

    servername = (servername_str) ? ZSTR_VAL(servername_str) : NULL;
    rv = tls_connect_fds(intern->ctx, (int) fd_read, (int) fd_write, servername);
    RETURN_LONG(rv);
}
/* }}} */

/* {{{ proto int Tls\Client::connect(string host[, string port[, string servername]])
 */
static PHP_METHOD(TlsClient, connectSocket)
{
    php_tls_obj *intern = php_tls_obj_from_zval(getThis());

    zend_long sock = 0;
    zend_string *servername_str = NULL;
    const char *servername;
    int rv;

    ZEND_PARSE_PARAMETERS_START(1, 2)
            Z_PARAM_LONG(sock)
            Z_PARAM_OPTIONAL
            Z_PARAM_STR_EX(servername_str, 1, 0)
    ZEND_PARSE_PARAMETERS_END();

    if (ZEND_LONG_INT_OVFL(sock) || sock < 0) {
        php_error_docref(NULL, E_WARNING, "socket is out of range");
        RETURN_NULL();
    }

    servername = (servername_str) ? ZSTR_VAL(servername_str) : NULL;
    rv = tls_connect_socket(intern->ctx, (int) sock, servername);
    RETURN_LONG(rv);
}
/* }}} */

/* proto Tls\ServerConnection Tls\Server::acceptFds(int fd_read, int fd_write)
 */
static PHP_METHOD(TlsServer, acceptFds)
{
    php_tls_obj *intern = php_tls_obj_from_zval(getThis());

    zend_long fd_read = 0, fd_write = 0;

    struct tls *conn;

    ZEND_PARSE_PARAMETERS_START(2, 2)
            Z_PARAM_LONG(fd_read)
            Z_PARAM_LONG(fd_write)
    ZEND_PARSE_PARAMETERS_END();

    if (ZEND_LONG_INT_OVFL(fd_read) || fd_read < 0) {
        php_error_docref(NULL, E_WARNING, "fd_read is out of range");
        RETURN_NULL();
    }
    if (ZEND_LONG_INT_OVFL(fd_write) || fd_write < 0) {
        php_error_docref(NULL, E_WARNING, "fd_write is out of range");
        RETURN_NULL();
    }

    tls_accept_fds(intern->ctx, &conn, (int) fd_read, (int) fd_write);
    handle_server_conn(INTERNAL_FUNCTION_PARAM_PASSTHRU, conn);
}
/* }}} */

/* proto Tls\ServerConnection Tls\Server::acceptSocket(int socket)
 */
static PHP_METHOD(TlsServer, acceptSocket)
{
    php_tls_obj *intern = php_tls_obj_from_zval(getThis());

    zend_long sock = 0;

    struct tls *conn;

    ZEND_PARSE_PARAMETERS_START(1, 1)
            Z_PARAM_LONG(sock)
    ZEND_PARSE_PARAMETERS_END();

    if (ZEND_LONG_INT_OVFL(sock) || sock < 0) {
        php_error_docref(NULL, E_WARNING, "socket is out of range");
        RETURN_NULL();
    }

    tls_accept_socket(intern->ctx, &conn, (int) sock);
    handle_server_conn(INTERNAL_FUNCTION_PARAM_PASSTHRU, conn);
}
/* }}} */

static void php_tls_config_path_setter(INTERNAL_FUNCTION_PARAMETERS, _tls_config_str_func_t func) /* {{{ */
{
    php_tls_config_obj *intern = php_tls_config_obj_from_zval(getThis());

    zend_string *str = NULL;

    ZEND_PARSE_PARAMETERS_START(1, 1)
            Z_PARAM_PATH_STR(str)
    ZEND_PARSE_PARAMETERS_END();

    RETURN_BOOL(func(intern->config, ZSTR_VAL(str)) == 0);
}
/* }}} */

static void php_tls_config_mem_setter(INTERNAL_FUNCTION_PARAMETERS, _tls_config_mem_func_t func) /* {{{ */
{
    php_tls_config_obj *intern = php_tls_config_obj_from_zval(getThis());

    zend_string *str = NULL;

    ZEND_PARSE_PARAMETERS_START(1, 1)
            Z_PARAM_STR(str)
    ZEND_PARSE_PARAMETERS_END();

    RETURN_BOOL(func(intern->config, (const uint8_t *) ZSTR_VAL(str), ZSTR_LEN(str)) == 0);
}
/* }}} */

static void php_tls_config_str_setter(INTERNAL_FUNCTION_PARAMETERS, _tls_config_str_func_t func) /* {{{ */
{
    php_tls_config_obj *intern = php_tls_config_obj_from_zval(getThis());

    zend_string *str = NULL;

    ZEND_PARSE_PARAMETERS_START(1, 1)
            Z_PARAM_STR(str)
    ZEND_PARSE_PARAMETERS_END();

    RETURN_BOOL(func(intern->config, ZSTR_VAL(str)) == 0);
}
/* }}} */

static void php_tls_config_void_func(INTERNAL_FUNCTION_PARAMETERS, _tls_config_void_func_t func) /* {{{ */
{
    if (zend_parse_parameters_none() == SUCCESS) {
        func(php_tls_config_obj_from_zval(getThis())->config);
    }
}
/* }}} */

/* {{{ proto bool Tls\Config::setCaFile(string file)
 */
static PHP_METHOD(TlsConfig, setCaFile)
{
    php_tls_config_path_setter(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_set_ca_file);
}
/* }}} */

/* {{{ proto bool Tls\Config::setCaPath(string path)
 */
static PHP_METHOD(TlsConfig, setCaPath)
{
    php_tls_config_path_setter(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_set_ca_path);
}
/* }}} */

/* {{{ proto bool Tls\Config::setCa(string ca)
 */
static PHP_METHOD(TlsConfig, setCa)
{
    php_tls_config_mem_setter(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_set_ca_mem);
}
/* }}} */

/* {{{ proto bool Tls\Config::setCertFile(string file)
 */
static PHP_METHOD(TlsConfig, setCertFile)
{
    php_tls_config_path_setter(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_set_cert_file);
}
/* }}} */

/* {{{ proto bool Tls\Config::setCert(string cert)
 */
static PHP_METHOD(TlsConfig, setCert)
{
    php_tls_config_mem_setter(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_set_cert_mem);
}
/* }}} */

/* {{{ proto bool Tls\Config::setCiphers(string ciphers)
 */
static PHP_METHOD(TlsConfig, setCiphers)
{
    php_tls_config_str_setter(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_set_ciphers);
}
/* }}} */

/* {{{ proto bool Tls\Config::setDheParams(string params)
 */
static PHP_METHOD(TlsConfig, setDheParams)
{
    php_tls_config_str_setter(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_set_dheparams);
}
/* }}} */

/* {{{ proto bool Tls\Config::setEcdheCurve(string name)
 */
static PHP_METHOD(TlsConfig, setEcdheCurve)
{
    php_tls_config_str_setter(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_set_ecdhecurve);
}
/* }}} */

/* {{{ proto bool Tls\Config::setKeyFile(string file)
 */
static PHP_METHOD(TlsConfig, setKeyFile)
{
    php_tls_config_path_setter(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_set_key_file);
}
/* }}} */

/* {{{ proto bool Tls\Config::setKey(string key)
 */
static PHP_METHOD(TlsConfig, setKey)
{
    php_tls_config_mem_setter(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_set_key_mem);
}
/* }}} */

/* {{{ proto bool Tls\Config::setKeypairFile(string cert_file, string key_file)
 */
static PHP_METHOD(TlsConfig, setKeypairFile)
{
    php_tls_config_obj *intern = php_tls_config_obj_from_zval(getThis());

    zend_string *cert = NULL, *ca = NULL;

    ZEND_PARSE_PARAMETERS_START(2, 2)
            Z_PARAM_PATH_STR(cert)
            Z_PARAM_PATH_STR(ca)
    ZEND_PARSE_PARAMETERS_END();

    RETURN_BOOL(tls_config_set_keypair_file(intern->config, ZSTR_VAL(cert), ZSTR_VAL(ca)) == 0);
}
/* }}} */

/* {{{ proto bool Tls\Config::setKeypair(string cert, string key)
 */
static PHP_METHOD(TlsConfig, setKeypair)
{
    php_tls_config_obj *intern = php_tls_config_obj_from_zval(getThis());

    zend_string *cert = NULL, *ca = NULL;

    ZEND_PARSE_PARAMETERS_START(2, 2)
            Z_PARAM_STR(cert)
            Z_PARAM_STR(ca)
    ZEND_PARSE_PARAMETERS_END();

    RETURN_BOOL(tls_config_set_keypair_mem(intern->config,
                                           (const uint8_t *) ZSTR_VAL(cert), ZSTR_LEN(cert),
                                           (const uint8_t *) ZSTR_VAL(ca), ZSTR_LEN(ca)) == 0);
}
/* }}} */

/* {{{ proto bool Tls\Config::setProtocols(int protocols)
 */
static PHP_METHOD(TlsConfig, setProtocols)
{
    php_tls_config_obj *intern = php_tls_config_obj_from_zval(getThis());

    zend_long protocols = 0;

    ZEND_PARSE_PARAMETERS_START(1, 1)
            Z_PARAM_LONG(protocols)
    ZEND_PARSE_PARAMETERS_END();

    if (ZEND_LONG_UINT_OVFL(protocols)) {
        php_error_docref(NULL, E_WARNING, "protocols is too long");
        RETURN_FALSE;
    } else {
        tls_config_set_protocols(intern->config, (uint32_t) protocols);
        RETURN_TRUE;
    }
}
/* }}} */

/* {{{ proto bool Tls\Config::setVerifyDepth(int verify_depth)
 */
static PHP_METHOD(TlsConfig, setVerifyDepth)
{
    php_tls_config_obj *intern = php_tls_config_obj_from_zval(getThis());

    zend_long verify_depth = 0;

    ZEND_PARSE_PARAMETERS_START(1, 1)
            Z_PARAM_LONG(verify_depth)
    ZEND_PARSE_PARAMETERS_END();

    if (ZEND_LONG_INT_OVFL(verify_depth)) {
        php_error_docref(NULL, E_WARNING, "verify_depth is too long");
        RETURN_FALSE;
    } else {
        tls_config_set_verify_depth(intern->config, (int) verify_depth);
        RETURN_TRUE;
    }
}
/* }}} */

/* {{{ proto void Tls\Config::preferCiphersClient()
 */
static PHP_METHOD(TlsConfig, preferCiphersClient)
{
    php_tls_config_void_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_prefer_ciphers_client);
}
/* }}} */

/* {{{ proto void Tls\Config::preferCiphersServer()
 */
static PHP_METHOD(TlsConfig, preferCiphersServer)
{
    php_tls_config_void_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_prefer_ciphers_server);
}
/* }}} */

/* {{{ proto void Tls\Config::insecureNoVerifyCert()
 */
static PHP_METHOD(TlsConfig, insecureNoVerifyCert)
{
    php_tls_config_void_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_insecure_noverifycert);
}
/* }}} */

/* {{{ proto void Tls\Config::insecureNoVerifyName()
 */
static PHP_METHOD(TlsConfig, insecureNoVerifyName)
{
    php_tls_config_void_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_insecure_noverifyname);
}
/* }}} */

/* {{{ proto void Tls\Config::insecureNoVerifyTime()
 */
static PHP_METHOD(TlsConfig, insecureNoVerifyTime)
{
    php_tls_config_void_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_insecure_noverifytime);
}
/* }}} */

/* {{{ proto void Tls\Config::verify()
 */
static PHP_METHOD(TlsConfig, verify)
{
    php_tls_config_void_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_verify);
}
/* }}} */

/* {{{ proto void Tls\Config::verifyClient()
 */
static PHP_METHOD(TlsConfig, verifyClient)
{
    php_tls_config_void_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_verify_client);
}
/* }}} */

/* {{{ proto void Tls\Config::verifyClientOptional()
 */
static PHP_METHOD(TlsConfig, verifyClientOptional)
{
    php_tls_config_void_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_verify_client_optional);
}
/* }}} */

/* {{{ proto void Tls\Config::clearKeys()
 */
static PHP_METHOD(TlsConfig, clearKeys)
{
    php_tls_config_void_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_clear_keys);
}
/* }}} */

/* {{{ proto int Tls\Config::parseProtocols(string protostr)
 */
static PHP_METHOD(TlsConfig, parseProtocols)
{
    zend_string *str = NULL;
    uint32_t protocols;

    ZEND_PARSE_PARAMETERS_START(1, 1)
            Z_PARAM_STR(str)
    ZEND_PARSE_PARAMETERS_END();

    if (tls_config_parse_protocols(&protocols, ZSTR_VAL(str)) == 0) {
        RETURN_LONG(protocols);
    } else {
        RETURN_FALSE;
    }
}
/* }}} */

/* {{{ proto string Tls\Util::loadFile(string file[, string password])
 */
static PHP_METHOD(TlsUtil, loadFile)
{
    zend_string *file = NULL, *password_str = NULL;
    char *password;
    uint8_t *data;
    size_t data_len;

    ZEND_PARSE_PARAMETERS_START(1, 2)
            Z_PARAM_PATH_STR(file)
            Z_PARAM_OPTIONAL
            Z_PARAM_STR(password_str)
    ZEND_PARSE_PARAMETERS_END();

    password = (password_str) ? ZSTR_VAL(password_str) : NULL;
    data = tls_load_file(ZSTR_VAL(file), &data_len, password);
    if (data) {
        RETURN_STRINGL((const char *) data, data_len);
    } else {
        php_error_docref(NULL, E_WARNING, "Unable to load file %s", ZSTR_VAL(file));
        RETURN_NULL();
    }
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
