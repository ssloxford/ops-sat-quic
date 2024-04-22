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
#include "callbacks.h"

static int client_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t *data, size_t datalen, void *user_data, void *stream_user_data) {
    fprintf(stdout, "Server sent: %*s\n", (int) datalen, data);

    return 0;
}

static int client_acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id, uint64_t offset, uint64_t datalen, void *user_data, void *stream_data) {
    client *c = user_data;
    stream *stream_n = stream_data;

    return acked_stream_data_offset_cb(conn, offset, datalen, stream_n, c->settings->timing);
}

static int client_extend_max_local_streams_uni_cb(ngtcp2_conn *conn, uint64_t max_streams, void *user_data) {
    client *c = user_data;

    return extend_max_local_streams_uni_cb(conn, c->streams);
}

static int client_stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t app_error_code, void *user_data, void *stream_data) {
    client *c = user_data;

    stream *stream_n = stream_data;

    if (c->settings->timing) {
        // Report timing for that stream
        printf("Stream %ld closed in %lld after %ld bytes\n", stream_id, timestamp_ms() - stream_n->stream_opened, stream_n->stream_offset);
    }

    return stream_close_cb(stream_n, c->streams);
}

static int client_handshake_completed_cb(ngtcp2_conn *conn, void *user_data) {
    client *c = user_data;

    if (c->settings->timing) {
        handshake_completed_cb(c->initial_ts);
    }

    return 0;
}

static int client_wolfssl_init(client *c) {
    int rv;

    wolfSSL_Init();

    c->ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (c->ctx == NULL) {
        fprintf(stderr, "Failed to create context\n");
        return ERROR_WOLFSSL_SETUP;
    };

    rv = ngtcp2_crypto_wolfssl_configure_client_context(c->ctx);
    if (rv < 0) {
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
    int rv;

    struct in_addr inaddr;

    rv = inet_aton(target_host, &inaddr);

    // 0 for error is correct. https://linux.die.net/man/3/inet_aton
    if (rv == 0) {
        // Address provided is invalid
        return -1;
    }

    // Resolves target host and port, opens connection to it,
    // and updates variables fd, and local and remote sockaddr and socklen in client
    rv = resolve_and_process(inaddr.s_addr, atoi(target_port), IPPROTO_UDP, 0, (struct sockaddr*) &c->localsock, &c->locallen, (struct sockaddr*) &c->remotesock, &c->remotelen);

    if (rv < 0) {
        return rv;
    }

    c->fd = rv;

    return 0;
}

static int client_ngtcp2_init(client *c, char* server_ip, char *server_port) {
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
        client_handshake_completed_cb, /* handshake_completed */
        NULL, /* recv_version_negotiation */
        ngtcp2_crypto_encrypt_cb,
        ngtcp2_crypto_decrypt_cb,
        ngtcp2_crypto_hp_mask_cb,
        client_recv_stream_data_cb, /* recv_stream_data */
        client_acked_stream_data_offset_cb, /* acked_stream_data_offset */
        NULL, /* stream_open */
        client_stream_close_cb, /* stream_close */
        NULL, /* recv_stateless_reset */
        ngtcp2_crypto_recv_retry_cb,
        NULL, /* extend_max_local_streams_bidi */
        client_extend_max_local_streams_uni_cb, /* extend_max_local_streams_uni */ // Not provided by library
        rand_cb,
        get_new_connection_id_cb,
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
    // Set initial timestamp. Exact value is unimportant. 
    // By setting to timestamp, we can use timestamp() throughout for accurate deltas
    // Timestamp in nanosecond resolution
    settings.initial_ts = timestamp();

    // Enable debugging
    if (c->settings->debug) {
        settings.log_printf = debug_log; // ngtcp2 debugging
    }

    ngtcp2_transport_params_default(&params);

    params.initial_max_streams_uni = 3;
    params.initial_max_stream_data_uni = BUF_SIZE;
    params.initial_max_data = BUF_SIZE;
    params.max_udp_payload_size = MAX_UDP_PAYLOAD;

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
    rv = client_resolve_and_connect(c, server_ip, server_port);
    if (rv < 0) {
        fprintf(stderr, "Failed to resolve and connect to target socket: %d\n", rv);
        return rv;
    }

    struct ngtcp2_path path = {
        .local = {
            .addr = (ngtcp2_sockaddr*) &c->localsock,
            .addrlen = c->locallen,
        },
        .remote = {
            .addr = (ngtcp2_sockaddr*) &c->remotesock,
            .addrlen = c->remotelen,
        },
        .user_data = NULL
    };

    rv = ngtcp2_conn_client_new(&c->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, NULL, c);

    if (rv < 0) {
        fprintf(stderr, "Failed to create new client connection: %s\n", ngtcp2_strerror(rv));
        return rv;
    }

    ngtcp2_conn_set_tls_native_handle(c->conn, c->ssl);

    return 0;
}

static ngtcp2_conn* get_conn (ngtcp2_crypto_conn_ref* ref) {
    client *c = ref->user_data;
    return c->conn;
}

static int client_init(client *c, char* server_ip, char *server_port) {
    int rv;

    c->ref.get_conn = get_conn;
    c->ref.user_data = c;

    c->streams = malloc(sizeof(stream));
    if (c->streams == NULL) {
        return ERROR_OUT_OF_MEMORY;
    }

    c->streams->next = NULL;

    c->locallen = sizeof(c->localsock);
    c->remotelen = sizeof(c->remotesock);

    if (c->settings->timing) {
        c->initial_ts = timestamp_ms();
    }

    rand_init();

    // Create the wolfSSL context and ssl instance and load it into the client struct
    rv = client_wolfssl_init(c);
    if (rv < 0) {
        return rv;
    }

    if (c->settings->debug) {
        printf("Successfully initialised wolfSSL\n");
    }

    rv = client_ngtcp2_init(c, server_ip, server_port);
    if (rv < 0) {
        fprintf(stderr, "Failed to initialise ngtcp2 connection: %s\n", ngtcp2_strerror(rv));
        return rv;
    }

    return 0;
}

static int client_write_step(client *c) {
    int rv;

    if (c->settings->debug) printf("Starting write step\n");

    if (c->streams->next == NULL) {
        rv = write_step(c->conn, c->fd, NULL, (struct sockaddr*) &c->remotesock, c->remotelen);

        if (rv < 0) {
            return rv;
        }
    } else {
        rv = write_step(c->conn, c->fd, c->streams->next->inflight_tail, (struct sockaddr*) &c->remotesock, c->remotelen);

        if (rv < 0) {
            return rv;
        }

        // Stream data has been written. Update the in flight list
        if (rv > 0) {
            // Send queue is non-empty, so the head was sent
            c->streams->next->inflight_tail = c->streams->next->inflight_tail->next;
        }
    }

    return 0;
}

static int client_read_step(client *c) {
    ngtcp2_sockaddr_union remote_addr;
    socklen_t remote_addrlen = sizeof(remote_addr);
    ngtcp2_version_cid version;

    uint8_t buf[BUF_SIZE];

    int rv;

    ssize_t pktlen;

    if (c->settings->debug) printf("Starting read step\n");

    for (;;) {
        pktlen = read_message(c->fd, buf, sizeof(buf), (struct sockaddr*) &remote_addr, &remote_addrlen);

        if (pktlen == ERROR_NO_NEW_MESSAGE) {
            return 0;
        }

        if (pktlen < 0) {
            return pktlen;
        }

        // TODO - pktlen will be 0 when client has closed connection?
        if (pktlen == 0) {
            return ERROR_NO_NEW_MESSAGE;
        }

        rv = ngtcp2_pkt_decode_version_cid(&version, buf, pktlen, NGTCP2_MAX_CIDLEN);
        if (rv < 0) {
            fprintf(stderr, "Failed to decode version cid: %s\n", ngtcp2_strerror(rv));
            return rv;
        }

        // If got to here, the packet recieved is an acceptable QUIC packet

        // remoteaddr populated by await_message
        ngtcp2_path path = {
            .local = {
                .addr = (ngtcp2_sockaddr*) &c->localsock,
                .addrlen = c->locallen,
            },
            .remote = {
                .addr = (ngtcp2_sockaddr*) &remote_addr,
                .addrlen = remote_addrlen,
            }
        };

        // General actions on the packet (including processing incoming handshake on conn if incomplete)
        rv = ngtcp2_conn_read_pkt(c->conn, &path, NULL, buf, pktlen, timestamp());

        if (rv < 0) {
            fprintf(stderr, "Failed to read packet: %s\n", ngtcp2_strerror(rv));
            return rv;
        }
    }

    // Send ACK frames
    rv = send_nonstream_packets(c->conn, c->fd, -1, (struct sockaddr*) &c->remotesock, c->remotelen);

    if (rv < 0) {
        return rv;
    }

    return 0;
}

static int client_close_connection(client *c) {
    uint8_t buf[BUF_SIZE];
    ngtcp2_path_storage ps;
    ngtcp2_ccerr ccerr;

    int rv;

    ngtcp2_ssize pktlen;

    ngtcp2_ccerr_default(&ccerr);

    ccerr.type = NGTCP2_CCERR_TYPE_APPLICATION;

    ngtcp2_path_storage_zero(&ps);

    ngtcp2_tstamp ts = timestamp();

    // TODO - ERR_NOBUF on this call after exchanging data frames. See docs https://nghttp2.org/ngtcp2/ngtcp2_conn_write_connection_close.html
    pktlen = ngtcp2_conn_write_connection_close(c->conn, &ps.path, NULL, buf, BUF_SIZE, &ccerr, ts);

    if (pktlen < 0) {
        fprintf(stderr, "Error when closing connection: %s\n", ngtcp2_strerror(pktlen));
        return pktlen;
    }

    rv = send_packet(c->fd, buf, pktlen, (struct sockaddr*) &c->remotesock, c->remotelen);

    if (rv < 0) {
        return rv;
    }

    return 0;
}

static void client_deinit(client *c) {
    client_close_connection(c);

    if (c->settings->timing) {
        printf("Total client uptime: %lld\n", timestamp_ms() - c->initial_ts);
    }

    ngtcp2_conn_del(c->conn);

    wolfSSL_free(c->ssl);
    wolfSSL_CTX_free(c->ctx);

    close(c->fd);
}

static void default_settings(client_settings *settings) {
    settings->debug = 0;
    settings->timing = 0;
    settings->input_fd = STDIN_FILENO;
}

void print_helpstring() {
    printf("-h: Print help string\n");
    printf("-i [ip]: Specifies IP to connect to. Default localhost\n");
    printf("-p [port]: Specifies port to connect to. Default 11111\n");
    printf("-f [file]: Specifies source of transmission data. Default stdin\n");
    printf("-s [bytes]: Generate and send [bytes] random bytes. Negative number for infinite bytes. Cannot be used with -f\n");
    printf("-t: Enable timing and reporting\n");
    printf("-d: Enable debug printing\n");
}

int main(int argc, char **argv){
    client c;

    int rv;
    signed char opt;

    struct pollfd polls[2];

    size_t remaining_rand_data;

    uint8_t payload[1024];
    int payloadlen;

    char *server_ip = DEFAULT_IP;
    char *server_port = SERVER_PORT;

    int timeout;

    client_settings settings;
    default_settings(&settings);

    c.settings = &settings;

    while ((opt = getopt(argc, argv, "hdti:p:f:s:")) != -1) {
        switch (opt) {
            case 'h':
                print_helpstring();
                return 0;
            case 'i':
                server_ip = optarg;
                break;
            case 'p':
                server_port = optarg;
                break;
            case 'd':
                settings.debug = 1;
                break;
            case 'f':
                settings.input_fd = open(optarg, O_RDONLY);
                if (settings.input_fd == -1) {
                    fprintf(stderr, "Failed to open file %s\n", optarg);
                }
                return 0;
                break;
            case 's':
                settings.input_fd = -1;
                remaining_rand_data = atoi(optarg);
                break;
            case 't':
                settings.timing = 1;
                break;
            case '?':
                printf("Unknown option -%c\n", optopt);
                break;
        }
    }

    if (settings.debug) printf("STARTING CLIENT\n");

    rv = client_init(&c, server_ip, server_port);

    // If client init failed, propagate error
    if (rv < 0) {
        return rv;
    }

    if (settings.debug) printf("Successfully initialised client\n");

    // Polling a negative fd is defined behaviour that will not ever return on that fd.
    // If not using input_fd, we can safely leave that fd as -1 and it will not be accessed
    polls[0].fd = c.fd;
    polls[1].fd = settings.input_fd;

    polls[0].events = polls[1].events = POLLIN;


    while (1) {
        if (c.streams->next == NULL) {
            // Send handshake data
            rv = client_write_step(&c);

            if (rv < 0) {
                return rv;
            }

            timeout = get_timeout(c.conn);

            // Wait for there to be a UDP packet available
            rv = poll(polls, 1, timeout);

            if (rv == 0) {
                if (settings.debug) printf("Handling timeout\n");
                // Timeout occured
                rv = handle_timeout(c.conn, c.fd, (struct sockaddr*) &c.remotesock, c.remotelen);
                if (rv == ERROR_DROP_CONNECTION) {
                    // TODO - Maybe a printf in to say we idle timed out
                    return 0;
                }
                continue;
            }

            rv = client_read_step(&c);

            if (rv < 0) {
                return rv;
            }
        } else {
            // Stream is open. Wait for either line from STDIN or to recieve a packet
            timeout = get_timeout(c.conn);
            
            // Timeout may be extremely short
            rv = poll(polls, 2, timeout);

            if (rv == 0) {
                // Timeout occured
                rv = handle_timeout(c.conn, c.fd, (struct sockaddr*) &c.remotesock, c.remotelen);
                if (rv == ERROR_DROP_CONNECTION) {
                    return 0;
                }
                continue;
            }

            if (polls[0].revents & POLLIN) {
                rv = client_read_step(&c);

                if (rv < 0) {
                    return rv;
                }
            } else if (polls[1].revents & POLLIN) {
                // Recieved input data to be transmitted
                // By shortening the payload buffer by 1, there will be space to null terminate if needed
                payloadlen = read(settings.input_fd, payload, sizeof(payload));

                if (payloadlen == -1) {
                    fprintf(stdout, "Failed to read from input: %s\n", strerror(errno));
                    return -1;
                }

                if (payloadlen == 0) {
                    // End of file reached
                    close(settings.input_fd);
                    client_deinit(&c);
                    return 0;
                }

                rv = enqueue_message(payload, payloadlen, 0, c.streams->next);


                if (rv < 0) {
                    return rv;
                }
            }

            if (settings.input_fd == -1) {
                // We're using generated test data rather than data read from a file descriptor
                if (remaining_rand_data == 0) {
                    client_deinit(&c);
                    return 0;
                }

                // Generate and add some more data to the send queue
                payloadlen = remaining_rand_data;

                if (remaining_rand_data > sizeof(payload)) {
                    payloadlen = sizeof(payload);
                }

                rand_bytes(payload, payloadlen);

                remaining_rand_data -= payloadlen;

                rv = enqueue_message(payload, payloadlen, remaining_rand_data == 0, c.streams->next);

                if (rv < 0) {
                    return rv;
                }
            }

            rv = client_write_step(&c);

            if (rv < 0) {
                return rv;
            }
        }
    }

    return 0;
}
