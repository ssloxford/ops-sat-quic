#ifndef CLIENT_H
#define CLIENT_H

#include <wolfssl/ssl.h>
#include <ngtcp2/ngtcp2.h>

#include "connection.h"

typedef struct _client_settings {
    int debug;

    int input_fd;

    int timing;
} client_settings;

typedef struct _client {
    ngtcp2_conn *conn;
    ngtcp2_crypto_conn_ref ref;

    // The fd of the UDP socket being used
    int fd;

    // Linked list of open streams, each with their own ack/send queue.
    stream *streams;

    // Structures to store the local and remote addresses of the path being used
    ngtcp2_sockaddr_union localsock, remotesock;
    ngtcp2_socklen locallen, remotelen;

    WOLFSSL* ssl;
    WOLFSSL_CTX* ctx;

    client_settings *settings;

    // Only used if settings->timing is set. Allows us to use the clock from utils and take deltas
    uint64_t initial_ts;
} client;

#endif