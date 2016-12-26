#include "php_libressl.h"
#include <openssl/crypto.h>

int php_libressl_crypto_startup(INIT_FUNC_ARGS)
{
    return SUCCESS;
}

int php_libressl_crypto_shutdown(SHUTDOWN_FUNC_ARGS)
{
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
