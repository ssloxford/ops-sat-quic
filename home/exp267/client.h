#include <wolfssl/ssl.h>
#include <ngtcp2/ngtcp2.h>

#include "connection.h"

typedef struct _client {
    ngtcp2_conn *conn;
    ngtcp2_crypto_conn_ref ref;

    int fd;

    // TODO - Support multiple stream ids 
    uint64_t stream_id;

    inflight_data *inflight_head;
    uint64_t sent_offset;

    ngtcp2_sockaddr localsock, remotesock;
    ngtcp2_socklen locallen, remotelen;
    
    WOLFSSL* ssl;
    // *ctx to ensure the context is not deallocated
    WOLFSSL_CTX* ctx;

    int debug;
} client;