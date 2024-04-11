#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include <wolfssl/ssl.h>

#include "connection.h"

// TODO - Comment structure variables
typedef struct _server {
    ngtcp2_conn *conn;
    ngtcp2_crypto_conn_ref ref;

    int fd;

    int connected;
    uint64_t stream_id;

    inflight_data *inflight_head;
    uint64_t sent_offset;

    ngtcp2_sockaddr localsock;
    ngtcp2_socklen locallen;

    WOLFSSL* ssl;
    WOLFSSL_CTX* ctx;

    int reply;
    uint8_t *reply_data;
    size_t reply_data_len;

    int debug;
} server;