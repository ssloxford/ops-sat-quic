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

static int acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id, uint64_t offset, uint64_t datalen, void *user_data, void *stream_data) {
    // The server has acknowledged all data in the range [offset, offset+datalen)    
    client *c = user_data;

    // Used for calculating inflight time of acknowledged packets, to be reported if timing is on
    uint64_t delta;

    // Start on the dummy header
    data_node *prev_ptr = c->inflight_head;
    
    // Must update using prev_ptr->next as ptr may have been deallocated
    for (data_node *ptr = prev_ptr->next; prev_ptr != c->inflight_tail; ptr = prev_ptr->next) {
        if (ptr->stream_id == stream_id && ptr->offset >= offset && ptr->offset < (offset + datalen)) {
            // This frame has been acked in this call. We can deallocate it
            // Update the pointers
            prev_ptr->next = ptr->next;

            if (c->settings->timing) {
                // Report total time in flight of this packet
                delta = timestamp_ms() - ptr->time_sent;

                printf("Packet at offset %lu acknowledged. Total time inflight: %lu ms\n", offset, delta);
            }

            free(ptr->payload);
            free(ptr);

            // If deleting the last element of the list, make the tail pointer accurate
            if (ptr == c->inflight_tail) {
                // Deleting the last element of the queue. Must update the pointers to track
                c->inflight_tail = prev_ptr;
                if (c->send_tail == ptr) {
                    // We're also deleting the send_tail, meaning the send list must have been empty. Therefore, we must update the tail pointer to track the send head
                    c->send_tail = c->inflight_tail;
                }
            }
        } else {
            // Keep tracking the previous pointer
            prev_ptr = ptr;
        }
    }

    return 0;
}

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

static int handshake_completed_cb(ngtcp2_conn *conn, void *user_data) {
    client *c = user_data;

    if (c->settings->timing) {
        uint64_t delta = timestamp_ms() - c->initial_ts;

        printf("Handshake completed: %lu ms\n", delta);
    }

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
    rv = resolve_and_process(&c->fd, target_host, target_port, &hints, 0, (ngtcp2_sockaddr*) &c->localsock, &c->locallen, (ngtcp2_sockaddr*) &c->remotesock, &c->remotelen);

    if (rv < 0) {
        return rv;
    }

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
        handshake_completed_cb, /* handshake_completed */
        NULL, /* recv_version_negotiation */
        ngtcp2_crypto_encrypt_cb,
        ngtcp2_crypto_decrypt_cb,
        ngtcp2_crypto_hp_mask_cb,
        recv_stream_data_cb, /* recv_stream_data */
        acked_stream_data_offset_cb, /* acked_stream_data_offset */
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
    client *c = (client*) ref->user_data;
    return c->conn;
}

static int client_init(client *c, char* server_ip, char *server_port) {
    int rv;

    c->ref.get_conn = get_conn;
    c->ref.user_data = c;

    c->stream_id = -1;

    // inflight_head is a dummy node
    c->send_tail = c->inflight_tail = c->inflight_head = malloc(sizeof(data_node));
    c->send_tail->next = NULL;
    c->sent_offset = 0;

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

    rv = client_ngtcp2_init(c, server_ip, server_port);
    if (rv < 0) {
        fprintf(stderr, "Failed to initialise ngtcp2 connection: %s\n", ngtcp2_strerror(rv));
        return rv;
    }

    return 0;
}

static int client_write_step(client *c) {
    int rv;

    // TODO - Implement deciding when fin
    rv = write_step(c->conn, c->fd, 0, c->inflight_tail, &c->sent_offset);

    if (rv < 0) {
        return rv;
    }

    // Stream data has been written. Update the in flight list
    if (c->inflight_tail != c->send_tail) {
        // Send queue is non-empty, so the head was sent
        c->inflight_tail = c->inflight_tail->next;
    }

    return 0;
}

static int client_read_step(client *c) {
    ngtcp2_sockaddr_union remote_addr;
    ngtcp2_version_cid version;

    uint8_t buf[BUF_SIZE];

    int rv;

    size_t pktlen;

    for (;;) {
        pktlen = read_message(c->fd, buf, sizeof(buf), (ngtcp2_sockaddr*) &remote_addr, sizeof(remote_addr));

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
                .addrlen = sizeof(remote_addr),
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
    rv = send_nonstream_packets(c->conn, c->fd, buf, sizeof(buf), -1);

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

    ccerr.type = NGTCP2_CCERR_TYPE_APPLICATION;

    ngtcp2_path_storage_zero(&ps);

    ngtcp2_tstamp ts = timestamp();

    // TODO - ERR_NOBUF on this call after exchanging data frames. See docs https://nghttp2.org/ngtcp2/ngtcp2_conn_write_connection_close.html
    pktlen = ngtcp2_conn_write_connection_close(c->conn, &ps.path, NULL, buf, BUF_SIZE, &ccerr, ts);

    if (pktlen < 0) {
        fprintf(stderr, "Error when closing connection: %s\n", ngtcp2_strerror(pktlen));
        return pktlen;
    }

    rv = send_packet(c->fd, buf, pktlen);

    if (rv < 0) {
        return rv;
    }
}

static void client_deinit(client *c) {
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
    char opt;

    struct pollfd polls[2];

    size_t remaining_rand_data;

    uint8_t payload[1024];
    int payloadlen;

    char *server_ip = DEFAULT_IP;
    char *server_port = SERVER_PORT;

    ngtcp2_tstamp expiry, delta_time;
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

    rv = client_init(&c, server_ip, server_port);

    // If client init failed, propagate error
    if (rv < 0) {
        return rv;
    }

    // Polling a negative fd is defined behaviour that will not ever return on that fd.
    // If not using input_fd, we can safely leave that fd as -1 and it will not be accessed
    polls[0].fd = c.fd;
    polls[1].fd = settings.input_fd;

    polls[0].events = polls[1].events = POLLIN;


    while (1) {
        if (c.stream_id == -1) {
            // Send handshake data
            rv = client_write_step(&c);

            if (rv < 0) {
                return rv;
            }

            timeout = get_timeout(c.conn);

            // Wait for there to be a UDP packet available
            rv = poll(polls, 1, timeout);

            if (rv == 0) {
                // Timeout occured
                rv = handle_timeout(c.conn, c.fd);
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
                rv = handle_timeout(c.conn, c.fd);
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
                payloadlen = read(settings.input_fd, payload, sizeof(payload)-1);

                if (payloadlen == -1) {
                    fprintf(stdout, "Failed to read from input: %s\n", strerror(errno));
                    return -1;
                }

                if (payloadlen == 0) {
                    // End of file reached
                    close(settings.input_fd);
                    client_close_connection(&c);
                    client_deinit(&c);
                    return 0;
                }

                if (settings.input_fd == STDIN_FILENO) {
                    // Null terminate the string
                    payload[payloadlen] = '\0';
                    payloadlen++;
                }

                rv = enqueue_message(payload, payloadlen, c.stream_id, c.sent_offset, c.send_tail);

                if (rv < 0) {
                    return rv;
                }

                // Update the tail pointer to the newly enqueued message
                c.send_tail = c.send_tail->next;
            }

            if (settings.input_fd == -1) {
                // We're using generated test data rather than data read from a file descriptor
                // Generate and add some more data to the send queue
                payloadlen = remaining_rand_data;

                if (remaining_rand_data > sizeof(payload)) {
                    payloadlen = sizeof(payload);
                }

                rand_bytes(payload, payloadlen);

                rv = enqueue_message(payload, payloadlen, c.stream_id, c.sent_offset, c.send_tail);

                if (rv < 0) {
                    return rv;
                }

                remaining_rand_data -= payloadlen;

                c.send_tail = c.send_tail->next;
            }

            rv = client_write_step(&c);

            if (rv < 0) {
                return rv;
            }
        }
    }

    return 0;
}
