#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_wolfssl.h>

#include <wolfssl/ssl.h>
#include <wolfssl/options.h>

#include <poll.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>

#include "server.h"
#include "utils.h"
#include "errors.h"
#include "connection.h"
#include "callbacks.h"

static int server_acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id, uint64_t offset, uint64_t datalen, void *user_data, void *stream_data) {
    // The remote has acknowledged all data in the range [offset, offset+datalen)    
    server *s = user_data;
    stream *stream_n = stream_data;

    return acked_stream_data_offset_cb(conn, offset, datalen, stream_n, s->settings->timing);
}

static int server_stream_open_cb(ngtcp2_conn *conn, int64_t incoming_stream_id, void *user_data) {
    // Remote has opened a stream
    server *s = user_data;

    stream *stream_n;

    if (s->settings->reply) {
        // Open a stream to reply this data on
        // Create the node for the reply stream lookup list
        reply_on *reply = malloc(sizeof(reply_on));

        if (reply == NULL) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        if (ngtcp2_conn_get_streams_uni_left(conn)) {
            // Open a stream to reply on and register it in the reply list
            stream_n = open_stream(conn);

            if (stream_n == NULL) {
                free(reply);
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }

            // Insert the newly created stream at the head of the provided stream list
            // Streams has a dummy header
            stream_n->next = s->streams->next;
            s->streams->next = stream_n;
        } else {
            // We're not able to open any more reply streams. Some will need to share. Simple solution is to put them all on the same stream
            stream_n = s->streams->next;
        }

        reply->incoming_stream_id = incoming_stream_id;
        reply->reply_stream = stream_n;

        // Add to the front of the reply_streams lookup list. Dummy header node
        reply->next = s->reply_stream->next;
        s->reply_stream->next = reply;
    }

    return 0;
}

static int server_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t *data, size_t datalen, void *user_data, void *stream_user_data) {
    int rv;

    server *s = user_data;

    if (s->settings->output_fd != -1) {
        rv = write(s->settings->output_fd, data, datalen);

        if (rv < 0) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }
    
    if (s->settings->reply) {
        reply_on *reply;

        for (reply = s->reply_stream->next; reply != NULL; reply = reply->next) {
            if (reply->incoming_stream_id == stream_id) {
                // We've found the stream we need to reply on
                break;
            }
        }

        if (reply == NULL) {
            // Something's gone wrong. We don't have the stream we've recieved on in the reply lookup list
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        stream *stream_n;

        // Search for the stream to reply on in the list
        for (stream_n = s->streams->next; stream_n != NULL; stream_n = stream_n->next) {
            if (stream_n == reply->reply_stream) {
                break;
            }
        }

        if (stream_n == NULL) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        rv = enqueue_message(data, datalen, 0, stream_n);
        
        if (rv < 0) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }

    return 0;
}

static int server_handshake_completed_cb(ngtcp2_conn *conn, void *user_data) {
    server *s = user_data;

    if (s->settings->timing) {
        handshake_completed_cb(s->initial_ts);
    }

    return 0;
}

static int server_stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t app_error_code, void *user_data, void *stream_data) {
    server *s = user_data;

    if (s->settings->debug) printf("Closing stream %ld\n", stream_id);
    if (stream_id & 0x01) {
        // Server initiated stream
        stream *stream_n = stream_data;

        if (s->settings->timing) {
            // Report timing for that stream
            printf("Stream %ld closed in %ld after %ld bytes\n", stream_id, timestamp_ms() - stream_n->stream_opened, stream_n->stream_offset);
        }

        return stream_close_cb(stream_n, s->streams);
    } else {
        // Client initiated stream
        if (s->settings->reply) {
            // There's a reply stream we may need to close
            int can_close_reply = 1;
            stream *reply_stream = NULL;

            reply_on *prev_ptr = s->reply_stream;

            for (reply_on *ptr = prev_ptr->next; ptr != NULL; ptr = prev_ptr->next) {
                if (ptr->incoming_stream_id == stream_id) {
                    // This is the node in the list that needs to be deleted
                    reply_stream = ptr->reply_stream;

                    prev_ptr->next = ptr->next;
                    free(ptr);
                    break;
                }
                prev_ptr = ptr;
            }

            if (reply_stream == NULL) {
                // We did not find the incoming stream in the list. Non-fatal error
                fprintf(stderr, "Warning: Tried to close reply stream for %ld. Could not find stream with id %ld\n", stream_id, stream_id);
                return 0;
            }

            for (reply_on *ptr = s->reply_stream->next; ptr != NULL; ptr = ptr->next) {
                if (ptr->reply_stream == reply_stream) {
                    // The reply stream was shared. We cannot close the stream.
                    can_close_reply = 0;
                    break;
                }
            }
            
            if (can_close_reply) {
                // Enqueue a 0 length stream frame with fin bit set. When sent, this will close the reply stream.
                enqueue_message(NULL, 0, 1, reply_stream);
            }
        }
    }

    return 0;
}

static int server_wolfssl_new(server *s) {
    int rv;

    s->ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (s->ctx == NULL) {
        fprintf(stderr, "Failed to create context\n");
        return ERROR_WOLFSSL_SETUP;
    };

    if (wolfSSL_CTX_load_verify_locations(s->ctx, "certs/ca-cert.pem", 0) != SSL_SUCCESS) {
        fprintf(stderr, "Failed verifying certs\n");
        return ERROR_WOLFSSL_SETUP;
    }

    if (wolfSSL_CTX_use_certificate_file(s->ctx, "certs/server-cert.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        fprintf(stderr, "Failed loading server certificate\n");
        return ERROR_WOLFSSL_SETUP;
    }

    if (wolfSSL_CTX_use_PrivateKey_file(s->ctx, "certs/server-key.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        fprintf(stderr, "Failed loading server key\n");
        return ERROR_WOLFSSL_SETUP;
    }

    rv = ngtcp2_crypto_wolfssl_configure_server_context(s->ctx);
    if (rv < 0) {
        fprintf(stderr, "Failed to configure wolf context: %s\n", ngtcp2_strerror(rv));
        return ERROR_WOLFSSL_SETUP;
    }

    s->ssl = wolfSSL_new(s->ctx);
    if (s->ssl == NULL) {
        fprintf(stderr, "Failed to create ssl instance\n");
        return ERROR_WOLFSSL_SETUP;
    }

    wolfSSL_set_app_data(s->ssl, &s->ref);
    wolfSSL_set_accept_state(s->ssl);

    return 0;
}

static int server_settings_init(ngtcp2_callbacks *callbacks, ngtcp2_settings *settings, int debug) {
    // Similar to client.c. Removed unnecessary recv_retry callback
    ngtcp2_callbacks local_callbacks = {
        NULL,
        ngtcp2_crypto_recv_client_initial_cb, /* recv_client_initial */
        ngtcp2_crypto_recv_crypto_data_cb,
        server_handshake_completed_cb, /* handshake_completed */
        NULL, /* recv_version_negotiation */
        ngtcp2_crypto_encrypt_cb,
        ngtcp2_crypto_decrypt_cb,
        ngtcp2_crypto_hp_mask_cb,
        server_recv_stream_data_cb, /* recv_stream_data */
        server_acked_stream_data_offset_cb, /* acked_stream_data_offset */
        server_stream_open_cb, /* stream_open */
        server_stream_close_cb, /* stream_close */
        NULL, /* recv_stateless_reset */
        NULL, /* recv_retry */
        NULL, /* extend_max_local_streams_bidi */
        NULL, /* extend_max_local_streams_uni */
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

    memcpy(callbacks, &local_callbacks, sizeof(local_callbacks));

    ngtcp2_settings_default(settings);
    settings->initial_ts = timestamp_ms();
    if (debug) {
        settings->log_printf = debug_log; // Allows ngtcp2 debug
    }
    return 0;
}

static int server_resolve_and_bind(server *s, const char *server_port) {
    int rv;

    // Resolves the local port, opens an fd and binds it to the address,
    // and updates the local sockaddr and socklen in server
    rv = resolve_and_process(htonl(INADDR_ANY), atoi(server_port), IPPROTO_UDP, 1, (ngtcp2_sockaddr*) &s->localsock, &s->locallen, NULL, NULL);

    if (rv < 0) {
        return rv;
    }

    s->fd = rv;

    return 0;
}

static ngtcp2_conn* get_conn (ngtcp2_crypto_conn_ref* ref) {
    server *data = ref->user_data;

    return data->conn;
}

static int server_init(server *s, char *server_port) {
    int rv;

    s->ref.user_data = s;
    s->ref.get_conn = get_conn;

    // Server is not connected. No open stream
    s->connected = 0;
    
    s->streams = malloc(sizeof(stream));
    if (s->streams == NULL) {
        return ERROR_OUT_OF_MEMORY;
    }
    s->streams->next = NULL;


    s->multiplex_ctx = malloc(sizeof(stream_multiplex_ctx));
    if (s->multiplex_ctx == NULL) {
        free(s->streams);
        return ERROR_OUT_OF_MEMORY;
    }

    // Initialise the multiplex context
    // Last sent is initialised to the dummy head
    s->multiplex_ctx->streams_list = s->multiplex_ctx->last_sent = s->streams;

    // Dummy header
    s->reply_stream = malloc(sizeof(reply_on));
    if (s->reply_stream == NULL) {
        free(s->streams);
        free(s->multiplex_ctx);
        return ERROR_OUT_OF_MEMORY;
    }

    s->reply_stream->next = NULL;

    s->locallen = sizeof(s->localsock);
    s->remotelen = sizeof(s->remotesock);

    rand_init();

    wolfSSL_Init();

    rv = server_resolve_and_bind(s, server_port);
    if (rv < 0) {
        return rv;
    }

    return 0;
}

static int server_close_connection(server *s) {
    s->connected = 0;

    free(s->streams->next);
    s->streams->next = NULL;

    ngtcp2_conn_del(s->conn);

    wolfSSL_CTX_free(s->ctx);
    wolfSSL_free(s->ssl);

    return 0;
}

static int server_accept_connection(server *s, uint8_t *buf, size_t buflen, ngtcp2_path *path) {
    ngtcp2_pkt_hd header;
    ngtcp2_transport_params params;
    ngtcp2_settings settings;
    ngtcp2_callbacks callbacks;

    int rv;

    if (s->connected) {
        //TODO - Error message, error code
        return -1;
    }

    // Determine if the received first message is acceptable
    // If it is, write the data into the header structure
    rv = ngtcp2_accept(&header, buf, buflen);
    if (rv < 0) {
        fprintf(stderr, "First packet could not be parsed or was unacceptable: %s\n", ngtcp2_strerror(rv));
        return rv;
    }

    // First packet is acceptable, so create the ngtcp2_conn
    ngtcp2_transport_params_default(&params);

    server_settings_init(&callbacks, &settings, s->settings->debug);

    // Docs state the the original_dcid field must be set
    params.original_dcid = header.dcid;
    params.original_dcid_present = 1;

    // Allow up to 3 incoming unidirectional streams
    params.initial_max_streams_uni = 3;
    // Can accept up to BUF_SIZE bytes at a time on uni streams
    params.initial_max_stream_data_uni = BUF_SIZE;
    // Will send up to BUF_SIZE bytes at a time
    params.initial_max_data = BUF_SIZE;

    params.max_udp_payload_size = MAX_UDP_PAYLOAD;

    // Server DCID is client SCID. 
    ngtcp2_cid scid;
    scid.datalen = 8;
    if (rand_bytes(scid.data, scid.datalen) != 0) {
        fprintf(stderr, "Failed to populate server SCID\n");
        return -1; // TODO - New error code
    }

    rv = ngtcp2_conn_server_new(&s->conn, &header.scid, &scid, path, header.version, &callbacks, &settings, &params, NULL, s);

    if (rv < 0) {
        fprintf(stderr, "Failed to create connection instance from incomming request\n");
        return rv;
    }

    // Creates new WOLFSSL and WOLFSSL_CTX pointers in the server
    server_wolfssl_new(s);

    ngtcp2_conn_set_tls_native_handle(s->conn, s->ssl);

    if (rv < 0) {
        fprintf(stderr, "Failed to add connection to fd\n");
        return rv; // TODO - Make a new error code
    }

    s->connected = 1;

    if (s->settings->timing) {
        s->initial_ts = timestamp_ms();
    }

    return 0;
}

static int server_read_step(server *s) {
    ngtcp2_version_cid version;

    int rv;

    uint8_t buf[BUF_SIZE];

    ssize_t pktlen;

    for (;;) {
        pktlen = read_message(s->fd, buf, sizeof(buf), (struct sockaddr*) &s->remotesock, &s->remotelen);

        if (pktlen == ERROR_NO_NEW_MESSAGE) {
            return 0;
        }

        if (pktlen < 0) {
            return pktlen;
        }

        if (pktlen == 0) {
            return ERROR_NO_NEW_MESSAGE;
        }

        rv = ngtcp2_pkt_decode_version_cid(&version, buf, pktlen, NGTCP2_MAX_CIDLEN);
        if (rv < 0) {
            fprintf(stderr, "Could not decode packet version: %s\n", ngtcp2_strerror(rv));
            return rv;
        }

        // If got to here, the packet recieved is an acceptable QUIC packet

        // remoteaddr populated by read_message. Localsock already known
        ngtcp2_path path = {
            .local = {
                .addr = (ngtcp2_sockaddr*) &s->localsock,
                .addrlen = s->locallen,
            },
            .remote = {
                .addr = (ngtcp2_sockaddr*) &s->remotesock,
                .addrlen = s->remotelen,
            }
        };

        // If we're not currently connected, try accepting the connection. If it works, action the packet
        if (!s->connected) {
            rv = server_accept_connection(s, buf, sizeof(buf), &path);
            if (rv < 0) {
                return rv;
            }
        }

        // General actions on the packet (including processing incoming handshake on conn if incomplete)
        rv = ngtcp2_conn_read_pkt(s->conn, &path, NULL, buf, pktlen, timestamp());

        if (rv < 0) {
            if (rv == NGTCP2_ERR_DRAINING) {
                // Client has closed it's connection
                server_close_connection(s);
                return ERROR_DRAINING_STATE;
            }
            fprintf(stderr, "Failed to read packet: %s\n", ngtcp2_strerror(rv));

            if (rv == NGTCP2_ERR_CRYPTO) {
                fprintf(stderr, "TLS alert: %d\n", ngtcp2_conn_get_tls_alert(s->conn));
            }
            return rv; 
        }
    }

    // Send ACK packets
    rv = send_nonstream_packets(s->conn, s->fd, -1, (struct sockaddr*) &s->remotesock, s->remotelen);

    if (rv < 0) {
        return rv;
    }

    return 0;
}

static int server_write_step(server *s) {
    int rv;

    stream *stream_to_send;

    // If there are no streams open, multiplex_streams will return NULL
    stream_to_send = multiplex_streams(s->multiplex_ctx);

    rv = write_step(s->conn, s->fd, stream_to_send, (struct sockaddr*) &s->remotesock, s->remotelen);

    if (rv < 0) {
        return rv;
    }

    return 0;
}

static void settings_default(server_settings *settings) {
    settings->debug = 0;
    settings->reply = 0;
    settings->output_fd = -1;
    settings->timing = 0;
}

void print_helpstring() {
    printf("-h: Print help string\n");
    printf("-p [port]: Specify port to use. Default 11111\n");
    printf("-d: Enable debugging output\n");
    printf("-f [file]: File to write recieved data into. Default stdout\n");
    printf("-t: Enable timing and reporting\n");
    printf("-r: Enable echoing all data back to client\n");
}

int main(int argc, char **argv) {
    server s;

    int rv;
    int8_t opt;

    char *server_port = SERVER_PORT;

    struct pollfd conn_poll;

    int timeout;

    server_settings settings;
    settings_default(&settings);

    s.settings = &settings;

    while ((opt = getopt(argc, argv, "htdp:f::r")) != -1) {
        switch (opt) {
            case 'h':
                print_helpstring();
                return 0;
            case 'p':
                server_port = optarg;
                break;
            case 'd':
                settings.debug = 1;
                break;
            case 'r':
                settings.reply = 1;
                break;
            case 'f':
                if (optarg == 0) {
                    // No file path given
                    settings.output_fd = STDOUT_FILENO;
                } else {
                    settings.output_fd = open(optarg, O_WRONLY);
                    if (settings.output_fd == -1) {
                        fprintf(stderr, "Failed to open file %s\n", optarg);
                    }
                }
                break;
            case 't':
                settings.timing = 1;
                break;
            case '?':
                printf("Unknown option: -%c\n", optopt);
                break;
        }
    }

    // Allocates the fd to listen for connections, and sets up the wolfSSL backend
    rv = server_init(&s, server_port);
    if (rv < 0) {
        return rv;
    }

    // Create socket polling
    conn_poll.fd = s.fd;
    conn_poll.events = POLLIN;

    while (1) {
        if (s.connected) {
            // s.conn only valid when s.connected
            timeout = get_timeout(s.conn);
        } else {
            // Wait indefinitely for a connection
            timeout = -1;
        }

        // Waits for the fd saved to the server to be ready to read. No timeout
        rv = poll(&conn_poll, 1, timeout);

        if (rv == -1) {
            fprintf(stderr, "Poll error: %s\n", strerror(errno));
            return rv;
        }

        if (rv == 0) {
            handle_timeout(s.conn, s.fd, (struct sockaddr*) &s.remotesock, s.remotelen);
            continue;
        }

        rv = server_read_step(&s);
        if (rv < 0 && rv != ERROR_NO_NEW_MESSAGE) {
            if (rv == ERROR_DRAINING_STATE) {
                // The connection is being closed. Server must process remaining packets (eg. ACK)
                continue;
            }
            return rv;
        }

        // TODO - Deal with this call for when not sending data
        rv = server_write_step(&s);
        if (rv < 0) {
            return rv;
        }
    }

    return 0;
}