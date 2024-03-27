#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include <wolfssl/ssl.h>

// TODO - Comment structure variables
typedef struct _server {
    ngtcp2_conn *conn;
    ngtcp2_crypto_conn_ref ref;

    int fd;

    // TODO - What if sockaddr isn't big enough to hold the bound address
    ngtcp2_sockaddr localsock;
    ngtcp2_socklen locallen;

    WOLFSSL* ssl;
    WOLFSSL_CTX* ctx;

    // TODO - Use these fields
    ngtcp2_callbacks *callbacks;
    ngtcp2_settings *settings;
} server;