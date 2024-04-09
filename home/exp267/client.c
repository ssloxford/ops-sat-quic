#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_wolfssl.h>

#include <wolfssl/ssl.h>
#include <wolfssl/options.h>

#include <poll.h>

#include "client.h"
#include "utils.h"
#include "errors.h"
#include "connection.h"

static int extend_max_local_streams_uni_cb(ngtcp2_conn *conn, uint64_t max_streams, void *user_data) {
    int64_t stream_id;
    int rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);
    if (rv < 0) {
        fprintf(stderr, "Failed to open new uni stream: %s\n", ngtcp2_strerror(rv));
        return ERROR_NEW_STREAM;
    }

    client *c = (client*) user_data;
    c->stream_id = stream_id;

    return 0;
}

static int recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t *data, size_t datalen, void *user_data, void *stream_user_data) {
    fprintf(stdout, "Server sent: %*s\n", (int) datalen, data);

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

    wolfSSL_set_app_data(c->ssl, &c->ref);
    wolfSSL_set_connect_state(c->ssl);
    // QUIC version 1
    wolfSSL_set_quic_transport_version(c->ssl, TLSEXT_TYPE_quic_transport_parameters); 

    // TODO - Determine if there is further SSL setup

    return 0;
}

static int client_resolve_and_connect(client *c, const char *target_host, const char *target_port) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int rv, fd;

    // Documentation says that unused fields in hints (eg. next) must be 0/null
    memset(&hints, 0, sizeof(hints));

    // Look for available IPv4 UDP endpoints
    hints.ai_family = AF_INET;
    hints.ai_protocol = IPPROTO_UDP;

    // Resolves target host and port, opens connection to it,
    // and updates variables fd, and local and remote sockaddr and socklen in client
    rv = resolve_and_process(&c->fd, target_host, target_port, &hints, 0, &c->localsock, &c->locallen, &c->remotesock, &c->remotelen);

    if (rv != 0) {
        return rv;
    }

    return 0;
}

static int client_ngtcp2_init(client *c, char* server_ip) {
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
        NULL, /* handshake_completed */
        NULL, /* recv_version_negotiation */
        ngtcp2_crypto_encrypt_cb,
        ngtcp2_crypto_decrypt_cb,
        ngtcp2_crypto_hp_mask_cb,
        recv_stream_data_cb, /* recv_stream_data */
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
    // Set initial timestamp. Exact value is unimportant
    settings.initial_ts = timestamp();

    // Enable debugging
    // settings.log_printf = debug_log; // ngtcp2 debugging

    ngtcp2_transport_params_default(&params);

    params.initial_max_streams_uni = 3;
    params.initial_max_stream_data_uni = BUF_SIZE;
    params.initial_max_data = BUF_SIZE;

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

    // Resolve provided hostname and port, and create a socket connected to it
    rv = client_resolve_and_connect(c, server_ip, SERVER_PORT);
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
        fprintf(stderr, "Failed to create new client connection: %s\n", ngtcp2_strerror(rv));
        return rv;
    }

    ngtcp2_conn_set_tls_native_handle(c->conn, c->ssl);

    return 0;
}

static ngtcp2_conn* get_conn (ngtcp2_crypto_conn_ref* ref) {
    client *c = (client*) ref->user_data;
    return c->conn;
}

static int client_init(client *c, char* server_ip) {
    int rv;

    c->ref.get_conn = get_conn;
    c->ref.user_data = c;

    // TODO - Consider moving this to one of the other init funcs
    c->stream_id = -1;

    rand_init();

    // Create the wolfSSL context and ssl instance and load it into the client struct
    rv = client_wolfssl_init(c);
    if (rv != 0) {
        return rv;
    }

    rv = client_ngtcp2_init(c, server_ip);
    if (rv != 0) {
        fprintf(stderr, "Failed to initialise ngtcp2 connection: %s\n", ngtcp2_strerror(rv));
        return rv;
    }

    return 0;
}

static int client_write_step(client *c, uint8_t *data, size_t datalen) {
    return write_step(c->conn, c->fd, c->stream_id, data, datalen);
}

static int client_read_step(client *c) {
    struct sockaddr remote_addr;
    ngtcp2_version_cid version;

    uint8_t buf[BUF_SIZE];

    int rv;

    size_t pktlen;

    struct pollfd conn_poll;

    // Create socket polling
    conn_poll.fd = c->fd;
    conn_poll.events = POLLIN;
    
    // Waits for there to be a datagram ready to read
    poll(&conn_poll, 1, -1);

    for (;;) {
        rv = read_message(c->fd, buf, sizeof(buf), &remote_addr, sizeof(remote_addr), &pktlen);

        if (rv == ERROR_NO_NEW_MESSAGE) {
            return 0;
        }

        if (rv != 0) {
            return rv;
        }

        // TODO - pktlen will be 0 when client has closed connection?
        if (pktlen == 0) {
            return ERROR_NO_NEW_MESSAGE;
        }

        rv = ngtcp2_pkt_decode_version_cid(&version, buf, pktlen, NGTCP2_MAX_CIDLEN);
        if (rv != 0) {
            fprintf(stderr, "Failed to decode version cid: %s\n", ngtcp2_strerror(rv));
            return rv;
        }

        // If got to here, the packet recieved is an acceptable QUIC packet

        // remoteaddr populated by await_message
        ngtcp2_path path = {
            .local = {
                .addr = &c->localsock,
                .addrlen = c->locallen,
            },
            .remote = {
                .addr = &remote_addr,
                .addrlen = sizeof(remote_addr),
            }
        };

        // General actions on the packet (including processing incoming handshake on conn if incomplete)
        rv = ngtcp2_conn_read_pkt(c->conn, &path, NULL, buf, pktlen, timestamp());

        if (rv != 0) {
            fprintf(stderr, "Failed to read packet: %s\n", ngtcp2_strerror(rv));
            return rv;
        }
    }

    return 0;
}

static int client_deinit(client *c) {
    uint8_t buf[BUF_SIZE];
    ngtcp2_path_storage ps;
    ngtcp2_ccerr ccerr;

    int rv;

    ngtcp2_ssize pktlen;

    ccerr.type = NGTCP2_CCERR_TYPE_APPLICATION;

    ngtcp2_path_storage_zero(&ps);

    ngtcp2_tstamp ts = timestamp();

    pktlen = ngtcp2_conn_write_connection_close(c->conn, &ps.path, NULL, buf, sizeof(buf), &ccerr, ts);

    if (pktlen < 0) {
        fprintf(stderr, "Error when closing connection: %s\n", ngtcp2_strerror(pktlen));
        return pktlen;
    }

    rv = send_packet(c->fd, buf, pktlen);

    if (rv != 0) {
        return rv;
    }

    ngtcp2_conn_del(c->conn);

    wolfSSL_free(c->ssl);
    wolfSSL_CTX_free(c->ctx);

    close(c->fd);

    return 0;
}

int main(int argc, char **argv){
    client c;

    int rv;

    // TODO - Macro the max message length
    uint8_t message[160];

    char *server_ip = DEFAULT_IP;

    if (argc > 1) {
        // User has provided an IP to connect to
        server_ip = argv[1];
    }

    rv = client_init(&c, server_ip);

    // If client init failed, propagate error
    if (rv != 0) {
        return rv;
    }

    while (1) {
        // Once the stream is opened, we're able to start sending stream data
        if (c.stream_id != -1) {
            fprintf(stdout, "Send: ");
            fflush(stdout);
            rv = read(STDIN_FILENO, message, 160);
            // Replace newline character with null terminate
            message[rv-1] = '\0';
        }

        if (strcmp(message, "quit") == 0) {
            return client_deinit(&c);
        }

        rv = client_write_step(&c, message, rv);

        if (rv != 0) {
            return rv;
        }

        rv = client_read_step(&c);
        
        if (rv != 0) {
            return rv;
        }
    }

    return 0;
}
