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
        PHP_FE_END
};

/* }}} */
/* {{{ PHP Module Functions */

int php_libressl_tls_startup(INIT_FUNC_ARGS)
{
    zend_class_entry ce_base, ce_client, ce_server, ce_config;

    memcpy(&tls_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    /*
    tls_object_handlers.offset = XtOffset(php_tls_obj, std);
    tls_object_handlers.free_obj = tls_object_free_storage;
    tls_object_handlers.clone_obj = NULL;
    */

    memcpy(&tls_config_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    /*
    tls_config_object_handlers.offset = XtOffset(php_tls_config_obj, std);
    tls_config_object_handlers.free_obj = tls_config_object_free_storage;
    tls_config_object_handlers.clone_obj = NULL;
    */

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
    ce_client.create_object = NULL; /* TODO */
    ce_tls_client = zend_register_internal_class_ex(&ce_client, ce_tls);

    INIT_NS_CLASS_ENTRY(ce_server, "TLS", "Server", tls_server_methods);
    ce_server.create_object = NULL; /* TODO */
    ce_tls_server = zend_register_internal_class_ex(&ce_server, ce_tls);

    INIT_NS_CLASS_ENTRY(ce_config, "TLS", "Config", tls_config_methods);
    ce_config.create_object = NULL; /* TODO */
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
