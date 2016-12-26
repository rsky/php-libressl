cmake_minimum_required(VERSION 3.5)
project(libressl)

set(LIBRESSL_INCLUDE_DIRECTORY /opt/libressl/include)
set(LIBRARY_INCLUDE_DIRECTORY /opt/local/include)
set(PHP_INCLUDE_DIRECTORY /opt/local/include/php71)

include_directories(${LIBRESSL_INCLUDE_DIRECTORY}
        ${LIBRARY_INCLUDE_DIRECTORY}
        ${PHP_INCLUDE_DIRECTORY}/php
        ${PHP_INCLUDE_DIRECTORY}/php/TSRM
        ${PHP_INCLUDE_DIRECTORY}/php/ZEND
        ${PHP_INCLUDE_DIRECTORY}/php/main)

set(SOURCE_FILES
        libressl.c
        crypto.c
        tls.c
        ext_openssl/openssl.c)

add_executable(ext_libretls ${SOURCE_FILES})
