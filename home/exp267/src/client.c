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

    return acked_stream_data_offset_cb(offset, datalen, stream_n, c->settings->timing);
}

static int client_stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t app_error_code, void *user_data, void *stream_data) {
    // A local stream has been closed
    client *c = user_data;

    if (c->settings->debug >= 1) printf("Closing stream with id %"PRId64"\n", stream_id);

    if (!(stream_id & 0x01)) {
        // Client initiated stream. No need to do anything if it's a server-initiated stream
        stream *stream_n = stream_data;

        if (c->settings->timing >= 1) {
            // Report timing for that stream
            printf("Stream %"PRId64" closed in %"PRIu64"ms after %"PRIu64" bytes\n", stream_id, timestamp_ms() - stream_n->stream_opened, stream_n->stream_offset);
        }

        // Null the pointer in the input list
        for (int i = 0; i < c->inputslen; i++) {
            if (c->inputs[i].stream == stream_n) {
                // This input sends on this stream
                c->inputs[i].stream = NULL;
            }
        }

        return stream_close_cb(stream_n, c->streams, c->multiplex_ctx);
    }

    return 0;
}

static int client_handshake_completed_cb(ngtcp2_conn *conn, void *user_data) {
    // Just used for reporing handshake timing
    client *c = user_data;

    if (c->settings->timing >= 1) {
        handshake_completed_cb(c->initial_ts);
    }

    return 0;
}

static int client_extend_max_local_streams_uni_cb(ngtcp2_conn *conn, uint64_t max_streams, void *user_data) {
    client *c = user_data;

    if (c->settings->debug >= 1) printf("Client opening new streams. Max streams: %"PRIu64"\n", max_streams);

    for (size_t i = 0; i < c->inputslen; i++) {
        if (i < max_streams) {
            // Open a stream for this input
            c->inputs[i].stream = open_stream(c->conn);

            if (c->inputs[i].stream == NULL) {
                fprintf(stderr, "Out of memory\n");
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }

            // Push the new stream onto the front of the client's stream list
            c->inputs[i].stream->next = c->streams->next;
            c->streams->next = c->inputs[i].stream;
        } else {
            // We've run out of streams we can open. Some inputs will need to share
            c->inputs[i].stream = c->inputs[i-max_streams].stream;
        }
    }

    return 0;
}

static int client_get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token, size_t cidlen, void *user_data) {
    int rv;
    
    rv = get_new_connection_id_cb(cid, token, cidlen);

    if (rv < 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

static void client_rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx) {
    rand_cb(dest, destlen);
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
        client_extend_max_local_streams_uni_cb, /* extend_max_local_streams_uni */
        client_rand_cb,
        client_get_new_connection_id_cb,
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

    // Give up on the handshake after 1 minute
    settings.handshake_timeout = 60ull * NGTCP2_SECONDS;

    // Enable debugging
    if (c->settings->debug >= 3) {
        settings.log_printf = debug_log; // ngtcp2 debugging
    }

    settings.cc_algo = c->settings->congestion_control;

    ngtcp2_transport_params_default(&params);

    params.initial_max_streams_uni = 8;
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

static int client_init(client *c, char* server_ip, char *server_port, input_source *inputs, size_t inputslen) {
    int rv;

    c->ref.get_conn = get_conn;
    c->ref.user_data = c;

    c->streams = malloc(sizeof(stream));
    if (c->streams == NULL) {
        return ERROR_OUT_OF_MEMORY;
    }

    c->streams->next = NULL;

    c->multiplex_ctx = malloc(sizeof(stream_multiplex_ctx));
    if (c->multiplex_ctx == NULL) {
        free(c->streams);
        return ERROR_OUT_OF_MEMORY;
    }

    // Initialise the multiplex context
    // Last sent is initialised to the dummy head
    c->multiplex_ctx->streams_list = c->multiplex_ctx->next_send = c->streams;

    c->locallen = sizeof(c->localsock);
    c->remotelen = sizeof(c->remotesock);

    if (c->settings->timing >= 1) {
        c->initial_ts = timestamp_ms();
    }

    for (int i = 0; i < inputslen; i++) {
        inputs[i].stream = NULL;
    }

    c->inputs = inputs;
    c->inputslen = inputslen;

    rand_init();

    // Create the wolfSSL context and ssl instance and load it into the client struct
    rv = client_wolfssl_init(c);
    if (rv < 0) {
        return rv;
    }

    if (c->settings->debug >= 1) {
        printf("Successfully initialised wolfSSL\n");
    }

    rv = client_ngtcp2_init(c, server_ip, server_port);
    if (rv < 0) {
        fprintf(stderr, "Failed to initialise ngtcp2 connection: %s\n", ngtcp2_strerror(rv));
        return rv;
    }

    return 0;
}

static int client_generate_data(client *c) {
    int rv;

    // TODO - Macro the payload size
    uint8_t payload[1024];
    ssize_t payloadlen;

    int to_enqueue;

    // Scan through the inputs and enqueue data to respective streams
    for (size_t i = 0; i < c->inputslen; i++) {
        if (c->inputs[i].stream == NULL) {
            // This input doesn't have an open stream yet. Skip it
            continue;
        }

        data_node *node = c->inputs[i].stream->inflight_tail;

        // Find out how many nodes to add to get to max length
        for (to_enqueue = MAX_SEND_QUEUE; to_enqueue > 0; to_enqueue--) {
            if (node == c->inputs[i].stream->send_tail) {
                // We've reached the end of the queue
                break;
            }

            // Node will never be null, since if it's the inflight_tail, loop would have broken
            node = node->next;
        }

        for (int j = 0; j < to_enqueue; j++) {
            // Add to the queue up to queue capacity
            if (c->inputs[i].remaining_data == 0) {
                // Input is closed
                break;
            }

            // Search the inputs for available data
            if (c->inputs[i].input_fd == -1) {

                // Genereate random data on this input. Remaining data == 0 means generate no more data

                payloadlen = sizeof(payload);

                if (c->inputs[i].remaining_data > 0) {
                    // Generating finite data
                    if (c->inputs[i].remaining_data < payloadlen) {
                        // We can fit all remaining data into this packet
                        payloadlen = c->inputs[i].remaining_data;
                    }

                    c->inputs[i].remaining_data -= payloadlen;
                }

                rand_bytes(payload, payloadlen);

                rv = enqueue_message(payload, payloadlen, c->inputs[i].remaining_data == 0, c->inputs[i].stream);

                if (rv < 0) {
                    return rv;
                }
            } else {
                // Fd is for a file or input stream
                if (c->inputs[i].input_fd == STDIN_FILENO) {
                    // The input is stdin, which would block if we called read
                    // TODO - Implement this
                    break;
                } else {
                    payloadlen = read(c->inputs[i].input_fd, payload, sizeof(payload));
                }

                if (payloadlen == -1) {
                    fprintf(stdout, "Failed to read from fd %d: %s\n", c->inputs[i].input_fd, strerror(errno));
                    return -1;
                }

                if (payloadlen == 0) {
                    // End of file reached. Stream will be closed when sending a packet with the fin bit set
                    close(c->inputs[i].input_fd);
                    // Close this input. This will mean this input will be skipped when calling enqueue
                    c->inputs[i].remaining_data = 0;
                }

                // Get the stream to send on. The poll array and the input array are zipped so can access directly
                stream* stream_to_send = c->inputs[i].stream;

                // Sending a 0 length stream frame is fine
                rv = enqueue_message(payload, payloadlen, payloadlen == 0, stream_to_send);

                if (rv < 0) {
                    return rv;
                }
            }
        }
    }

    return 0;
}

static int client_write_step(client *c) {
    if (c->settings->debug >= 2) printf("Starting write step\n");

    return write_step(c->conn, c->fd, c->multiplex_ctx, (struct sockaddr*) &c->remotesock, c->remotelen, c->settings->debug);
}

static int client_read_step(client *c) {
    ngtcp2_sockaddr_union remote_addr;
    socklen_t remote_addrlen = sizeof(remote_addr);
    ngtcp2_version_cid version;

    uint8_t buf[BUF_SIZE];

    int rv;

    ssize_t pktlen;

    if (c->settings->debug >= 2) printf("Starting read step\n");

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
            if (rv == NGTCP2_ERR_INVALID_ARGUMENT || rv == NGTCP2_ERR_VERSION_NEGOTIATION) {
                // Couldn't decode the cid. Just drop the packet
                continue;
            }
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

    if (c->settings->timing >= 1) {
        printf("Total client uptime: %"PRIu64"ms\n", timestamp_ms() - c->initial_ts);
    }

    // Free the allocated memory
    free(c->multiplex_ctx);

    for (stream *ptr = c->streams->next; ptr != NULL; ptr = c->streams->next) {
        // The callback deallocates the inflight/send queue, deallocates the stream struct, and rejoins the queue
        stream_close_cb(ptr, c->streams, NULL);
    }

    // Free the streams dummy header
    free(c->streams);
    
    free(c->inputs);

    ngtcp2_conn_del(c->conn);

    wolfSSL_free(c->ssl);
    wolfSSL_CTX_free(c->ctx);

    close(c->fd);
}

static void default_settings(client_settings *settings) {
    settings->debug = 0;
    settings->timing = 0;
    settings->congestion_control = NGTCP2_CC_ALGO_CUBIC;
}

void print_helpstring() {
    printf("-h: Print help string\n");
    printf("-i [ip]: Specifies IP to connect to. Default localhost\n");
    printf("-p [port]: Specifies port to connect to. Default 11111\n");
    printf("-f [file]: Specifies source of transmission data. Default stdin\n");
    printf("-s [bytes]: Generate and send [bytes] random bytes. Empty for infinite data. Cannot be used with -f\n");
    printf("-t: Enable timing and reporting. Can be used multiple times\n");
    printf("-c [algo]: Specifies congestion control algorithm. Default Cubic\n\tc: Cubic\n\tb: BBR v2\n\tr: Reno\n");
    printf("-d: Enable debug printing. Can be used multiple times\n");
}

int main(int argc, char **argv){
    client c;

    int rv;
    signed char opt;

    // An array of inputs to read from. They correspond 1-1 with outgoing streams.
    int open_inputs = 0, inputslen = 1;
    input_source *inputs = malloc(inputslen * sizeof(input_source));
    if (inputs == NULL) {
        fprintf(stderr, "Out of memory\n");
        return -1;
    }

    char *server_ip = DEFAULT_IP;
    char *server_port = DEFAULT_PORT;

    int timeout;

    client_settings settings;
    default_settings(&settings);

    c.settings = &settings;

    while ((opt = getopt(argc, argv, "hdti:p:f:s::c:")) != -1) {
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
                settings.debug += 1;
                break;
            case 'f':
                if (open_inputs >= inputslen) {
                    // Need to expand the input array. Double the length
                    inputslen *= 2;
                    inputs = realloc(inputs, sizeof(input_source) * inputslen);
                    if (inputs == NULL) {
                        fprintf(stderr, "Out of memory\n");
                        return -1;
                    }
                }
                if (optarg == 0) {
                    inputs[open_inputs].input_fd = STDIN_FILENO;
                } else {
                    inputs[open_inputs].input_fd = open(optarg, O_RDONLY);
                }
                if (inputs[open_inputs].input_fd == -1) {
                    fprintf(stderr, "Failed to open file %s\n", optarg);
                    return -1;
                }
                inputs[open_inputs].remaining_data = -1;
                open_inputs++;
                break;
            case 's':
                if (open_inputs >= inputslen) {
                    // Need to expand the input array. Double the length
                    inputslen *= 2;
                    inputs = realloc(inputs, sizeof(input_source) * inputslen);
                    if (inputs == NULL) {
                        fprintf(stderr, "Out of memory\n");
                        return -1;
                    }
                }
                // fd of -1 indicates randomly generated data rather than read from a fd
                inputs[open_inputs].input_fd = -1;
                if (optarg == NULL) {
                    inputs[open_inputs].remaining_data = -1;
                } else {
                    inputs[open_inputs].remaining_data = atoi(optarg);
                }
                open_inputs++;
                break;
            case 't':
                settings.timing += 1;
                break;
            case 'c':
                switch (optarg[0]) {   
                    case 'c':
                        settings.congestion_control = NGTCP2_CC_ALGO_CUBIC;
                        break;
                    case 'r':
                        settings.congestion_control = NGTCP2_CC_ALGO_RENO;
                        break;
                    case 'b':
                        settings.congestion_control = NGTCP2_CC_ALGO_BBR;
                        break;
                    default:
                        printf("Unknown congestion control algorithm %c. Check helpstring\n", optarg[0]);
                        break;
                }
                break;
            case '?':
                printf("Unknown option -%c\n", optopt);
                break;
        }
    }

    if (settings.debug >= 1) printf("STARTING CLIENT\n");

    rv = client_init(&c, server_ip, server_port, inputs, open_inputs);

    // If client init failed, propagate error
    if (rv < 0) {
        return rv;
    }

    if (settings.debug >= 1) printf("Successfully initialised client\n");

    // Set up UDP socket polling
    struct pollfd poll_fd;

    poll_fd.fd = c.fd;
    poll_fd.events = POLLIN;

    for (;;) {
        if (!ngtcp2_conn_get_handshake_completed(c.conn)) {
            // Send handshake data
            rv = client_write_step(&c);

            if (rv < 0) {
                return rv;
            }

            timeout = get_timeout(c.conn);

            if (c.settings->debug >= 2) printf("Timeout: %d\n", timeout);

            // Wait for there to be a UDP packet available
            rv = poll(&poll_fd, 1, timeout);

            if (rv == 0) {
                if (settings.debug >= 1) printf("Handling timeout\n");
                // Timeout occured
                rv = handle_timeout(c.conn, c.fd, (struct sockaddr*) &c.remotesock, c.remotelen, c.settings->debug);
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
            if (c.streams->next == NULL) {
                // All streams are closed. We can close the connection
                client_deinit(&c);
                return 0;
            }

            client_generate_data(&c);

            timeout = get_timeout(c.conn);
            
            if (c.settings->debug >= 2) printf("Timeout: %d\n", timeout);

            // Wait for an input, a UDP message, or a timeout
            rv = poll(&poll_fd, 1, timeout);

            if (rv == 0) {
                // Timeout occured
                rv = handle_timeout(c.conn, c.fd, (struct sockaddr*) &c.remotesock, c.remotelen, c.settings->debug);
                if (rv == ERROR_DROP_CONNECTION) {
                    return 0;
                }
            }

            if (poll_fd.revents & POLLIN) {
                // There's a UDP message. Process it
                rv = client_read_step(&c);

                if (rv < 0) {
                    return rv;
                }
            }

            rv = client_write_step(&c);

            if (rv < 0) {
                if (rv == ERROR_NO_NEW_MESSAGE) {
                    if (c.settings->debug >= 2) printf("Could not send any message due to congestion control\n");
                    continue;
                }
                return rv;
            }
        }
    }

    return 0;
}
