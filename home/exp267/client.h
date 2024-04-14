#ifndef CLIENT_H
#define CLIENT_H

#include <wolfssl/ssl.h>
#include <ngtcp2/ngtcp2.h>

#include "connection.h"

typedef struct _client {
    ngtcp2_conn *conn;
    ngtcp2_crypto_conn_ref ref;

    // The fd of the UDP socket being used
    int fd;

    // TODO - Support multiple stream ids 
    uint64_t stream_id;

    // A pointer to the head of currently in flight packets (sent but not acknowledged)
    inflight_data *inflight_head;
    uint64_t sent_offset;

    // Structures to store the local and remote addresses of the path being used
    ngtcp2_sockaddr_union localsock, remotesock;
    ngtcp2_socklen locallen, remotelen;
    
    WOLFSSL* ssl;
    WOLFSSL_CTX* ctx;

    // TODO - Maybe this could be a global variable instead?
    // Flag to determine if debugging code is on
    int debug;
} client;

#endif