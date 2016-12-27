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

/* {{{ Object Handlers */

static void php_tls_object_free_storage(zend_object *object);
static void php_tls_config_object_free_storage(zend_object *object);

static zend_object *php_tls_object_create(zend_class_entry *class_type);
static zend_object *php_tls_config_object_create(zend_class_entry *class_type);

/* }}} */

/* {{{ PHP Module Functions */

int php_libressl_tls_startup(INIT_FUNC_ARGS)
{
    zend_class_entry ce_base, ce_client, ce_server, ce_config;

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

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: fdm=marker
 * vim: noet sw=4 ts=4
 */
