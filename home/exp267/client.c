#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_wolfssl.h>

#include <wolfssl/ssl.h>

#include "client.h"
#include "utils.h"
#include "errors.h"

static int handshake_completed_cb(ngtcp2_conn* conn, void* user_data) {
    fprintf(stdout, "Successfully completed handshake\n");
    return 0;
}

static int extend_max_local_streams_uni_cb(ngtcp2_conn *conn, uint64_t max_streams, void *user_data) {
    fprintf(stdout, "Starting call to extend_max_local_streams_uni_cb\n");

    int64_t stream_id = 1;
    int rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);
    if (rv < 0) {
        fprintf(stderr, "Failed to open new uni stream: %s\n", ngtcp2_strerror(rv));
        return ERROR_NEW_STREAM;
    }

    fprintf(stdout, "Successfully opened new uni stream\n");
    return 0;
}

static int client_wolfssl_init(client *c) {
    WOLFSSL_METHOD* method;

    int rv;

    wolfSSL_Init();

    c->ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (c->ctx == NULL) {
        fprintf(stderr, "Failed to create context\n");
        return ERROR_WOLFSSL_SETUP;
    };

    rv = ngtcp2_crypto_wolfssl_configure_client_context(c->ctx);
    if (rv != 0) {
        fprintf(stderr, "Failed to configure wolf context: %s\n", ngtcp2_strerror(rv));
        return ERROR_WOLFSSL_SETUP;
    }

    c->ssl = wolfSSL_new(c->ctx);
    if (c->ssl == NULL) {
        fprintf(stderr, "Failed to create ssl instance\n");
        return ERROR_WOLFSSL_SETUP;
    }

    // TODO - Unclear what these parts of the setup do. Experiment with combos & check openSSL docs
    wolfSSL_set_app_data(c->ssl, &c->ref);
    wolfSSL_set_connect_state(c->ssl);
    // QUIC version 1
    wolfSSL_set_quic_transport_version(c->ssl, TLSEXT_TYPE_quic_transport_parameters); 

    // TODO - Determine if there is further SSL setup

    return 0;
}

// Function code taken mostly from spaceQUIC
static int client_resolve_and_connect(client *c, const char *target_host, const char *target_port) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int rv, fd;

    // Documentation says that unused fields in hints (eg. next) must be 0/null
    memset(&hints, 0, sizeof(hints));

    // Look for available IPv4 UDP endpoints
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    // Should be redundant
    hints.ai_protocol = 0;

    rv = getaddrinfo(target_host, target_port, &hints, &result);
    if (rv != 0) {
        fprintf(stderr, "Failed to get address info for requested endpoint\n");
        return ERROR_HOST_LOOKUP;
    }

    // Result is the head of a linked list, with nodes of type addrinfo
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        // Attempt to open a file descriptor for current address info in results
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1)
            // If can't open a socket for it, move on
            continue;

        // Attempt to connect the created file descriptor to the address we've looked up
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            // Assign the path's remote addrlen. Must copy the value into the remote.addr pointer since rp will be deallocated
            c->remotelen = rp->ai_addrlen;
            memcpy(&c->remotesock, rp->ai_addr, rp->ai_addrlen);

            // Find the local address and copy that into path
            socklen_t len = sizeof(c->localsock);
            if (getsockname(fd, &c->localsock, &len) == -1)
                return ERROR_GET_SOCKNAME;
            c->locallen = len;

            // Exit the loop when the first successful connection is made
            break;
        }

        // If the connection was not made, close the fd and keep looking
        close(fd);
    }

    // Must manually deallocate the results from the lookup
    freeaddrinfo(result);

    // If the loop finished by getting to the end, rather than with a successful connection, return -1
    if (rp == NULL) {
        fprintf(stderr, "Could not connect to any returned addresses\n");
        return ERROR_COULD_NOT_OPEN_CONNECTION_FD;
    }

    // Save the fd of the open socket connected to the endpoint
    c->fd = fd;
    return 0;
}

static int client_ngtcp2_init(client *c) {
    struct ngtcp2_settings settings;
    struct ngtcp2_transport_params params;

    struct ngtcp2_cid dcid, scid;

    int rv;

    // Copied from https://github.com/ngtcp2/ngtcp2/blob/main/examples/simpleclient.c
    // Modified where noted
    ngtcp2_callbacks callbacks = {
        ngtcp2_crypto_client_initial_cb,
        NULL, /* recv_client_initial */
        ngtcp2_crypto_recv_crypto_data_cb,
        handshake_completed_cb, /* handshake_completed */ // Not provided by library
        NULL, /* recv_version_negotiation */
        ngtcp2_crypto_encrypt_cb,
        ngtcp2_crypto_decrypt_cb,
        ngtcp2_crypto_hp_mask_cb,
        NULL, /* recv_stream_data */
        NULL, /* acked_stream_data_offset */
        NULL, /* stream_open */
        NULL, /* stream_close */
        NULL, /* recv_stateless_reset */
        ngtcp2_crypto_recv_retry_cb,
        NULL, /* extend_max_local_streams_bidi */
        extend_max_local_streams_uni_cb, /* extend_max_local_streams_uni */ // Not provided by library
        rand_cb, // Not provided by library
        get_new_connection_id_cb, // Not provided by library
        NULL, /* remove_connection_id */
        ngtcp2_crypto_update_key_cb,
        NULL, /* path_validation */
        NULL, /* select_preferred_address */
        NULL, /* stream_reset */
        NULL, /* extend_max_remote_streams_bidi */
        NULL, /* extend_max_remote_streams_uni */
        NULL, /* extend_max_stream_data */
        NULL, /* dcid_status */
        NULL, /* handshake_confirmed */
        NULL, /* recv_new_token */
        ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        NULL, /* recv_datagram */
        NULL, /* ack_datagram */
        NULL, /* lost_datagram */
        ngtcp2_crypto_get_path_challenge_data_cb,
        NULL, /* stream_stop_sending */
        ngtcp2_crypto_version_negotiation_cb,
        NULL, /* recv_rx_key */
        NULL, /* recv_tx_key */
        NULL, /* early_data_rejected */
    };

    ngtcp2_settings_default(&settings);

    // Enable debugging
    settings.log_printf = debug_log;
    // Set initial timestamp. Exact value is unimportant
    settings.initial_ts = timestamp();

    ngtcp2_transport_params_default(&params);

    params.initial_max_streams_uni = 3;
    params.initial_max_streams_bidi = 3;
    // TODO - Do I need to set max_data?

    // Allocate random destination and source connection IDs
    dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
    if (rand_bytes(dcid.data, dcid.datalen) != 0) {
        fprintf(stderr, "Generating random DCID failed\n");
        return ERROR_DCID_GEN;
    }

    scid.datalen = 8;
    if (rand_bytes(scid.data, scid.datalen) != 0) {
        fprintf(stderr, "Generating random SCID failed\n");
        return ERROR_DCID_GEN;
    }

    // Resolve provided hostname and port, and create a socket connected to it. Return fd of socket
    rv = client_resolve_and_connect(c, DEFAULT_IP, SERVER_PORT);
    if (rv != 0) {
        fprintf(stderr, "Failed to resolve and connect to target socket: %d\n", rv);
        return rv;
    }

    struct ngtcp2_path path = {
        .local = {
            .addr = &c->localsock,
            .addrlen = c->locallen,
        },
        .remote = {
            .addr = &c->remotesock,
            .addrlen = c->remotelen,
        },
        .user_data = NULL
    };

    rv = ngtcp2_conn_client_new(&c->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, NULL, c);

    if (rv != 0) {
        fprintf(stderr, "FAILED TO CREATE NEW CONN!");
        return rv;
    }

    ngtcp2_conn_set_tls_native_handle(c->conn, c->ssl);

    return 0;
}

static ngtcp2_conn* get_conn (ngtcp2_crypto_conn_ref* ref) {
    client *data = (client*) ref->user_data;

    return data->conn;
}

static int client_init(client *c) {
    int rv;

    // Function from utils
    c->ref.get_conn = get_conn;
    c->ref.user_data = c;

    // TODO - Consider moving this to one of the other init funcs
    c->stream_id = -1;

    // Create the wolfSSL context and ssl instance and load it into the client struct
    rv = client_wolfssl_init(c);
    if (rv != 0) {
        return rv;
    }


    fprintf(stdout, "Successfully created wolfSSL instance\n");

    rv = client_ngtcp2_init(c);
    if (rv != 0) {
        fprintf(stderr, "Failed to initialise ngtcp2 connection\n");
        return rv;
    }

    return 0;
}

static int client_prepare_packet(client *c, uint8_t *buf, size_t buflen, size_t *bytes_written, struct iovec *iov, size_t iov_count) {
    // Write stream prepares the message to be sent into buf and returns size of the message
    ngtcp2_tstamp ts = timestamp();
    ngtcp2_pkt_info pi;
    ngtcp2_path_storage ps;
    ngtcp2_ssize wdatalen;

    int rv;

    ngtcp2_path_storage_zero(&ps);

    // TODO - Apparently need to make a call to ngtcp2_conn_update_pkt_tx_time after writev_stream
    // Need to cast *iov to (ngtcp2_vec*). Apparently safe: https://nghttp2.org/ngtcp2/types.html#c.ngtcp2_vec
    rv = ngtcp2_conn_writev_stream(c->conn, &ps.path, &pi, buf, buflen, &wdatalen, NGTCP2_WRITE_STREAM_FLAG_NONE, c->stream_id, (ngtcp2_vec*) iov, iov_count, ts);
    if (rv < 0) {
        fprintf(stderr, "Trying to write to stream failed: %s\n", ngtcp2_strerror(rv));
        return rv;
    }

    if (rv == 0) {
        // TODO - If rv == 0, buffer is too small or packet is congestion limited. Handle this case
        ;
    }

    *bytes_written = rv;

    return 0;
}

static int client_send_packet(client *c, uint8_t* buf, size_t nwrite) {
    // TODO - Improve the buf and nwrite variable names
    struct iovec msg_iov;
    struct msghdr msg;

    int rv;

    msg_iov.iov_base = buf;
    msg_iov.iov_len = nwrite;

    msg.msg_iov = &msg_iov;
    msg.msg_iovlen = 1;

    // TODO - Maybe poll to wait for the fd to be ready to write

    // TODO - Look into flags
    rv = sendmsg(c->fd, &msg, 0);

    // On success rv > 0 is the number of bytes sent

    if (rv == -1) {
        fprintf(stderr, "sendmsg: %s\n", strerror(errno));
        return rv;
    }

    return 0;
}

static int client_establish_connection(client *c) {
    // TODO - Pull the buf further up so it persists
    size_t bytes_written;
    uint8_t buf[8192]; // Smallest power of 2 that didn't throw "No buffer space available"
    
    struct iovec iov;
    size_t iov_count;

    int rv;

    iov_count = 0;

    rv = client_prepare_packet(c, buf, sizeof(buf), &bytes_written, &iov, iov_count);
    // If success, rv > 0 is the number of bytes saved into buf
    if (rv != 0) {
        // TODO - Add error message?
        fprintf(stderr, "client_establish_connection: TODO - Implement this message\n");
        return rv;
    }

    rv = client_send_packet(c, buf, bytes_written);

    if (rv != 0) {
        return rv;
    }

    return 0;
}

static int client_deinit(client *c) {
    // TODO - Implement

    return 0;
}

int main(int argc, char **argv){
    client c;

    int rv;

    rv = client_init(&c);

    // If client init failed, propagate error
    if (rv != 0) {
        return rv;
    }

    rv = client_establish_connection(&c);

    if (rv != 0) {
        return rv;
    }

    return 0;
}
