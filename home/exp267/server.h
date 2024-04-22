#ifndef SERVER_H
#define SERVER_H

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include <wolfssl/ssl.h>

#include <sys/socket.h>

#include "connection.h"

typedef struct _server_settings {
    int debug;

    int reply;

    // -1 if no output
    int output_fd;

    int timing;
} server_settings;

// Node in a linked list registering what stream to reply on when receiving data
typedef struct _reply_on {
    int64_t incoming_stream_id;

    int64_t outgoing_stream_id;

    struct _reply_on *next;
} reply_on;

typedef struct _server {
    ngtcp2_conn *conn;
    ngtcp2_crypto_conn_ref ref;

    int fd;

    int connected;
    
    stream *streams;

    struct sockaddr_storage localsock, remotesock;
    socklen_t locallen, remotelen;

    WOLFSSL* ssl;
    WOLFSSL_CTX* ctx;

    server_settings *settings;

    uint64_t initial_ts;
    reply_on *reply_stream;
} server;

#endif