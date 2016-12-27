#include "php_libressl.h"
#include <tls.h>

/* {{{ Class Globals */

static zend_class_entry *ce_tls;
static zend_class_entry *ce_tls_client;
static zend_class_entry *ce_tls_server;
static zend_class_entry *ce_tls_config;

static zend_object_handlers tls_object_handlers;
static zend_object_handlers tls_config_object_handlers;

/* }}} */

/* {{{ Object Handler Prototypes */

static void php_tls_object_free_storage(zend_object *object);
static void php_tls_config_object_free_storage(zend_object *object);

static zend_object *php_tls_object_create(zend_class_entry *class_type);
static zend_object *php_tls_config_object_create(zend_class_entry *class_type);

/* }}} */

/* {{{ tls_config Method Prototypes */

static PHP_METHOD(TLSConfig, setCaFile);
static PHP_METHOD(TLSConfig, setCaPath);
static PHP_METHOD(TLSConfig, setCa);

static PHP_METHOD(TLSConfig, setCertFile);
static PHP_METHOD(TLSConfig, setCert);

static PHP_METHOD(TLSConfig, setCiphers);
static PHP_METHOD(TLSConfig, setDheparams);
static PHP_METHOD(TLSConfig, setEcdhecurve);

static PHP_METHOD(TLSConfig, setKeyFile);
static PHP_METHOD(TLSConfig, setKey);

static PHP_METHOD(TLSConfig, setKeypairFile);
static PHP_METHOD(TLSConfig, setKeypair);

static PHP_METHOD(TLSConfig, setProtocols);
static PHP_METHOD(TLSConfig, setVerifyDepth);

static PHP_METHOD(TLSConfig, preferCiphersClient);
static PHP_METHOD(TLSConfig, preferCiphersServer);

static PHP_METHOD(TLSConfig, insecureNoverifycert);
static PHP_METHOD(TLSConfig, insecureNoverifyname);
static PHP_METHOD(TLSConfig, insecureNoverifytime);
static PHP_METHOD(TLSConfig, verify);

static PHP_METHOD(TLSConfig, verifyClient);
static PHP_METHOD(TLSConfig, verifyClientOptional);

static PHP_METHOD(TLSConfig, clearKeys);
static PHP_METHOD(TLSConfig, parseProtocols);

static void php_tls_config_path_setter(INTERNAL_FUNCTION_PARAMETERS, int(*callback)(struct tls_config *, const char *));
static void php_tls_config_mem_setter(INTERNAL_FUNCTION_PARAMETERS, int(*callback)(struct tls_config *, const uint8_t *, size_t));
static void php_tls_config_str_setter(INTERNAL_FUNCTION_PARAMETERS, int(*callback)(struct tls_config *, const char *));
static void php_tls_config_void_func(INTERNAL_FUNCTION_PARAMETERS, void(*callback)(struct tls_config *));

/* }}} */

/* {{{ Argument Information */

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

ZEND_BEGIN_ARG_INFO_EX(arginfo_tls_config_none, 0, 0, 0)
ZEND_END_ARG_INFO()


/* }}} */

/* {{{ Function Tables */

static zend_function_entry tls_base_methods[] = {
       PHP_FE_END
};

static zend_function_entry tls_client_methods[] = {
        PHP_FE_END
};

static zend_function_entry tls_server_methods[] = {
        PHP_FE_END
};

static zend_function_entry tls_config_methods[] = {
        PHP_ME(TLSConfig, setCaFile,            arginfo_tls_config_file, 0)
        PHP_ME(TLSConfig, setCaPath,            arginfo_tls_config_path, 0)
        PHP_ME(TLSConfig, setCa,                arginfo_tls_config_ca, 0)
        PHP_ME(TLSConfig, setCertFile,          arginfo_tls_config_file, 0)
        PHP_ME(TLSConfig, setCert,              arginfo_tls_config_cert, 0)
        PHP_ME(TLSConfig, setCiphers,           arginfo_tls_config_ciphers, 0)
        PHP_ME(TLSConfig, setDheparams,         arginfo_tls_config_params, 0)
        PHP_ME(TLSConfig, setEcdhecurve,        arginfo_tls_config_name, 0)
        PHP_ME(TLSConfig, setKeyFile,           arginfo_tls_config_file, 0)
        PHP_ME(TLSConfig, setKey,               arginfo_tls_config_key, 0)
        PHP_ME(TLSConfig, setKeypairFile,       arginfo_tls_config_keypair_file, 0)
        PHP_ME(TLSConfig, setKeypair,           arginfo_tls_config_keypair, 0)
        PHP_ME(TLSConfig, setProtocols,         arginfo_tls_config_protocols, 0)
        PHP_ME(TLSConfig, setVerifyDepth,       arginfo_tls_config_verify_depth, 0)
        PHP_ME(TLSConfig, preferCiphersClient,  arginfo_tls_config_none, 0)
        PHP_ME(TLSConfig, preferCiphersServer,  arginfo_tls_config_none, 0)
        PHP_ME(TLSConfig, insecureNoverifycert, arginfo_tls_config_none, 0)
        PHP_ME(TLSConfig, insecureNoverifyname, arginfo_tls_config_none, 0)
        PHP_ME(TLSConfig, insecureNoverifytime, arginfo_tls_config_none, 0)
        PHP_ME(TLSConfig, verify,               arginfo_tls_config_none, 0)
        PHP_ME(TLSConfig, verifyClient,         arginfo_tls_config_none, 0)
        PHP_ME(TLSConfig, verifyClientOptional, arginfo_tls_config_none, 0)
        PHP_ME(TLSConfig, clearKeys,            arginfo_tls_config_none, 0)
        PHP_ME(TLSConfig, parseProtocols,       arginfo_tls_config_protostr, ZEND_ACC_STATIC)
        PHP_FE_END
};

/* }}} */

/* {{{ PHP Module Functions */

int php_libressl_tls_startup(INIT_FUNC_ARGS)
{
    zend_class_entry ce_base, ce_client, ce_server, ce_config;

    tls_init();

    memcpy(&tls_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    tls_object_handlers.offset = (int) XtOffsetOf(php_tls_obj, std);
    tls_object_handlers.free_obj = php_tls_object_free_storage;
    tls_object_handlers.clone_obj = NULL;

    memcpy(&tls_config_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    tls_config_object_handlers.offset = (int) XtOffsetOf(php_tls_config_obj, std);
    tls_config_object_handlers.free_obj = php_tls_config_object_free_storage;
    tls_config_object_handlers.clone_obj = NULL;

    INIT_NS_CLASS_ENTRY(ce_base, "TLS", "TLS", tls_base_methods);
    ce_base.create_object = NULL;
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

    INIT_NS_CLASS_ENTRY(ce_client, "TLS", "Client", tls_client_methods);
    ce_client.create_object = php_tls_object_create;
    ce_tls_client = zend_register_internal_class_ex(&ce_client, ce_tls);

    INIT_NS_CLASS_ENTRY(ce_server, "TLS", "Server", tls_server_methods);
    ce_server.create_object = php_tls_object_create;
    ce_tls_server = zend_register_internal_class_ex(&ce_server, ce_tls);

    INIT_NS_CLASS_ENTRY(ce_config, "TLS", "Config", tls_config_methods);
    ce_config.create_object = php_tls_config_object_create;
    ce_tls_config = zend_register_internal_class(&ce_config);

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

    if (class_type == ce_tls_server) {
        intern->ctx = tls_server();
    } else {
        intern->ctx = tls_client();
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
    intern->std.handlers = &tls_object_handlers;

    intern->config = tls_config_new();

    return &intern->std;
}
/* }}} */

static void php_tls_config_path_setter(INTERNAL_FUNCTION_PARAMETERS, int(*callback)(struct tls_config *, const char *)) /* {{{ */
{
    zval *self = getThis();
    php_tls_config_obj *intern;
    intern = php_tls_config_obj_from_obj(Z_OBJ_P(self));

    zend_string *str = NULL;

    ZEND_PARSE_PARAMETERS_START(1, 1)
            Z_PARAM_PATH_STR(str)
    ZEND_PARSE_PARAMETERS_END();

    RETVAL_BOOL(callback(intern->config, ZSTR_VAL(str)) == 0);
}
/* }}} */

static void php_tls_config_mem_setter(INTERNAL_FUNCTION_PARAMETERS, int(*callback)(struct tls_config *, const uint8_t *, size_t)) /* {{{ */
{
    zval *self = getThis();
    php_tls_config_obj *intern;
    intern = php_tls_config_obj_from_obj(Z_OBJ_P(self));

    zend_string *str = NULL;

    ZEND_PARSE_PARAMETERS_START(1, 1)
            Z_PARAM_STR(str)
    ZEND_PARSE_PARAMETERS_END();

    RETVAL_BOOL(callback(intern->config, (const uint8_t *) ZSTR_VAL(str), ZSTR_LEN(str)) == 0);
}
/* }}} */

static void php_tls_config_str_setter(INTERNAL_FUNCTION_PARAMETERS, int(*callback)(struct tls_config *, const char *)) /* {{{ */
{
    zval *self = getThis();
    php_tls_config_obj *intern;
    intern = php_tls_config_obj_from_obj(Z_OBJ_P(self));

    zend_string *str = NULL;

    ZEND_PARSE_PARAMETERS_START(1, 1)
            Z_PARAM_STR(str)
    ZEND_PARSE_PARAMETERS_END();

    RETVAL_BOOL(callback(intern->config, ZSTR_VAL(str)) == 0);
}
/* }}} */

static void php_tls_config_void_func(INTERNAL_FUNCTION_PARAMETERS, void(*callback)(struct tls_config *)) /* {{{ */
{
    if (zend_parse_parameters_none() == SUCCESS) {
        php_tls_config_obj *intern = php_tls_config_obj_from_obj(Z_OBJ_P(getThis()));
        callback(intern->config);
    }
}
/* }}} */

/* {{{ proto bool TLS\Config::setCaFile(string file)
 */
static PHP_METHOD(TLSConfig, setCaFile)
{
    php_tls_config_path_setter(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_set_ca_file);
}
/* }}} */

/* {{{ proto bool TLS\Config::setCaPath(string path)
 */
static PHP_METHOD(TLSConfig, setCaPath)
{
    php_tls_config_path_setter(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_set_ca_path);
}
/* }}} */

/* {{{ proto bool TLS\Config::setCa(string ca)
 */
static PHP_METHOD(TLSConfig, setCa)
{
    php_tls_config_mem_setter(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_set_ca_mem);
}
/* }}} */

/* {{{ proto bool TLS\Config::setCertFile(string file)
 */
static PHP_METHOD(TLSConfig, setCertFile)
{
    php_tls_config_path_setter(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_set_cert_file);
}
/* }}} */

/* {{{ proto bool TLS\Config::setCert(string cert)
 */
static PHP_METHOD(TLSConfig, setCert)
{
    php_tls_config_mem_setter(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_set_cert_mem);
}
/* }}} */

/* {{{ proto bool TLS\Config::setCiphers(string ciphers)
 */
static PHP_METHOD(TLSConfig, setCiphers)
{
    php_tls_config_str_setter(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_set_ciphers);
}
/* }}} */

/* {{{ proto bool TLS\Config::setDheparams(string params)
 */
static PHP_METHOD(TLSConfig, setDheparams)
{
    php_tls_config_str_setter(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_set_dheparams);
}
/* }}} */

/* {{{ proto bool TLS\Config::setEcdhecurve(string name)
 */
static PHP_METHOD(TLSConfig, setEcdhecurve)
{
    php_tls_config_str_setter(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_set_ecdhecurve);
}
/* }}} */

/* {{{ proto bool TLS\Config::setKeyFile(string file)
 */
static PHP_METHOD(TLSConfig, setKeyFile)
{
    php_tls_config_path_setter(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_set_key_file);
}
/* }}} */

/* {{{ proto bool TLS\Config::setKey(string key)
 */
static PHP_METHOD(TLSConfig, setKey)
{
    php_tls_config_mem_setter(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_set_key_mem);
}
/* }}} */

/* {{{ proto bool TLS\Config::setKeypairFile(String cert_file, String key_file)
 */
static PHP_METHOD(TLSConfig, setKeypairFile)
{
    zval *self = getThis();
    php_tls_config_obj *intern;
    intern = php_tls_config_obj_from_obj(Z_OBJ_P(self));

    zend_string *cert = NULL, *ca = NULL;

    ZEND_PARSE_PARAMETERS_START(2, 2)
            Z_PARAM_PATH_STR(cert)
            Z_PARAM_PATH_STR(ca)
    ZEND_PARSE_PARAMETERS_END();

    RETURN_BOOL(tls_config_set_keypair_file(intern->config, ZSTR_VAL(cert), ZSTR_VAL(ca)) == 0);
}
/* }}} */

/* {{{ proto bool TLS\Config::setKeypair(string cert, string key)
 */
static PHP_METHOD(TLSConfig, setKeypair)
{
    zval *self = getThis();
    php_tls_config_obj *intern;
    intern = php_tls_config_obj_from_obj(Z_OBJ_P(self));

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

/* {{{ proto bool TLS\Config::setProtocols(int protocols)
 */
static PHP_METHOD(TLSConfig, setProtocols)
{
    zval *self = getThis();
    php_tls_config_obj *intern;
    intern = php_tls_config_obj_from_obj(Z_OBJ_P(self));

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

/* {{{ proto bool TLS\Config::setVerifyDepth(int verify_depth)
 */
static PHP_METHOD(TLSConfig, setVerifyDepth)
{
    zval *self = getThis();
    php_tls_config_obj *intern;
    intern = php_tls_config_obj_from_obj(Z_OBJ_P(self));

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

/* {{{ proto void TLS\Config::preferCiphersClient()
 */
static PHP_METHOD(TLSConfig, preferCiphersClient)
{
    php_tls_config_void_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_prefer_ciphers_client);
}
/* }}} */

/* {{{ proto void TLS\Config::preferCiphersServer()
 */
static PHP_METHOD(TLSConfig, preferCiphersServer)
{
    php_tls_config_void_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_prefer_ciphers_server);
}
/* }}} */

/* {{{ proto void TLS\Config::insecureNoverifycert()
 */
static PHP_METHOD(TLSConfig, insecureNoverifycert)
{
    php_tls_config_void_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_insecure_noverifycert);
}
/* }}} */

/* {{{ proto void TLS\Config::insecureNoverifyname()
 */
static PHP_METHOD(TLSConfig, insecureNoverifyname)
{
    php_tls_config_void_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_insecure_noverifyname);
}
/* }}} */

/* {{{ proto void TLS\Config::insecureNoverifytime()
 */
static PHP_METHOD(TLSConfig, insecureNoverifytime)
{
    php_tls_config_void_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_insecure_noverifytime);
}
/* }}} */

/* {{{ proto void TLS\Config::verify()
 */
static PHP_METHOD(TLSConfig, verify)
{
    php_tls_config_void_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_verify);
}
/* }}} */

/* {{{ proto void TLS\Config::verifyClient()
 */
static PHP_METHOD(TLSConfig, verifyClient)
{
    php_tls_config_void_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_verify_client);
}
/* }}} */

/* {{{ proto void TLS\Config::verifyClientOptional()
 */
static PHP_METHOD(TLSConfig, verifyClientOptional)
{
    php_tls_config_void_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_verify_client_optional);
}
/* }}} */

/* {{{ proto void TLS\Config::clearKeys()
 */
static PHP_METHOD(TLSConfig, clearKeys)
{
    php_tls_config_void_func(INTERNAL_FUNCTION_PARAM_PASSTHRU, tls_config_clear_keys);
}
/* }}} */

/* {{{ proto int TLS\Config::parseProtocols(string protostr)
 */
static PHP_METHOD(TLSConfig, parseProtocols)
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

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: fdm=marker
 * vim: noet sw=4 ts=4
 */
