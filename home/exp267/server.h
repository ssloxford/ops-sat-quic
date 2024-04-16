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

typedef struct _server {
    ngtcp2_conn *conn;
    ngtcp2_crypto_conn_ref ref;

    int fd;

    int connected;
    uint64_t stream_id;

    // A linked list of all data queued to be sent or inflight (sent but not acknowledged)
    // Inflight queue: (inflight_head, inflight_tail]
    // Send queue: (inflight_tail, send_tail]
    data_node *inflight_head, *inflight_tail, *send_tail;
    uint64_t sent_offset;

    struct sockaddr_storage localsock;
    socklen_t locallen;

    WOLFSSL* ssl;
    WOLFSSL_CTX* ctx;

    server_settings *settings;

    uint64_t initial_ts;
} server;

#endif