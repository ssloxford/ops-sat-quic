#ifndef CLIENT_H
#define CLIENT_H

#include <wolfssl/ssl.h>
#include <ngtcp2/ngtcp2.h>

#include "connection.h"

typedef struct _client_settings {
    int debug;

    int input_fd;
} client_settings;

typedef struct _client {
    ngtcp2_conn *conn;
    ngtcp2_crypto_conn_ref ref;

    // The fd of the UDP socket being used
    int fd;

    // TODO - Support multiple stream ids 
    uint64_t stream_id;

    // A linked list of all data queued to be sent or inflight (send but not acknowledged)
    // Inflight_head and send_head are dummy header nodes for their respective queues
    data_node *inflight_head, *inflight_tail, *send_tail;
    uint64_t sent_offset;

    // Structures to store the local and remote addresses of the path being used
    ngtcp2_sockaddr_union localsock, remotesock;
    ngtcp2_socklen locallen, remotelen;
    
    WOLFSSL* ssl;
    WOLFSSL_CTX* ctx;

    client_settings *settings;
} client;

#endif