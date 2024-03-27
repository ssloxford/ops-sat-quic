#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_wolfssl.h>

#include <wolfssl/ssl.h>

#include <poll.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "utils.h"
#include "errors.h"
#include "server.h"

// TODO - Look unto spaceQUIC https://github.com/ssloxford/spaceQUIC/blob/main/code/libs/space_quic/fsw/src/quic/serv.c

static int server_wolfssl_init(server *s) {
    WOLFSSL_METHOD* method;

    int rv;

    wolfSSL_Init();

    method = wolfTLSv1_3_server_method();
    if (method == NULL) {
        fprintf(stderr, "Failed to create TLS method\n");
        return ERROR_WOLFSSL_SETUP;
    };

    s->ctx = wolfSSL_CTX_new(method);
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
    if (rv != 0) {
        fprintf(stderr, "Failed to configure wolf context: %s\n", ngtcp2_strerror(rv));
        return ERROR_WOLFSSL_SETUP;
    }

    s->ssl = wolfSSL_new(s->ctx);
    if (s->ssl == NULL) {
        fprintf(stderr, "Failed to create ssl instance\n");
        return ERROR_WOLFSSL_SETUP;
    }

    // TODO - Look into further ssl setup
    wolfSSL_set_app_data(s->ssl, &s->ref);
    wolfSSL_set_accept_state(s->ssl);

    // Set cipher suites?

    return 0;
}

static int server_settings_init(server *s) {
    // Similar to client.c. Removed unnecessary recv_retry callback
    ngtcp2_callbacks callbacks = {
        ngtcp2_crypto_client_initial_cb,
        ngtcp2_crypto_recv_client_initial_cb, /* recv_client_initial */
        ngtcp2_crypto_recv_crypto_data_cb,
        NULL, /* handshake_completed */
        NULL, /* recv_version_negotiation */
        ngtcp2_crypto_encrypt_cb,
        ngtcp2_crypto_decrypt_cb,
        ngtcp2_crypto_hp_mask_cb,
        NULL, /* recv_stream_data */
        NULL, /* acked_stream_data_offset */
        NULL, /* stream_open */
        NULL, /* stream_close */
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

    s->callbacks = malloc(sizeof(callbacks));

    if (s->callbacks == NULL) {
        return ERROR_OUT_OF_MEMORY;
    }

    // Copy the callbacks structure into the allocated memory
    memcpy(s->callbacks, &callbacks, sizeof(callbacks));

    ngtcp2_settings settings;

    ngtcp2_settings_default(&settings);
    settings.initial_ts = timestamp();
    settings.log_printf = debug_log;

    s->settings = malloc(sizeof(settings));

    if (s->settings == NULL) {
        return ERROR_OUT_OF_MEMORY;
    }

    memcpy(s->settings, &settings, sizeof(settings));

    return 0;
}

// TODO - Comment function and provide acknowledgement
static int server_resolve_and_bind(server *s, const char *server_host, const char *server_port) {
    // Server host is expected to be "127.0.0.1" aka "localhost"

    // printf("Attempting to bind to %s:%s\n", server_host, server_port);

    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int ret, fd;

    memset(&hints, 0, sizeof(hints));
    // TODO - Understand these fields
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    ret = getaddrinfo(server_host, server_port, &hints, &result);
    if (ret != 0)
        return ERROR_HOST_LOOKUP;

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1)
            continue;

        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            fprintf(stdout, "Opened and bound fd to socket data: %s\n", rp->ai_addr->sa_data);
            s->locallen = rp->ai_addrlen;
            memcpy(&s->localsock, rp->ai_addr, rp->ai_addrlen);
            break;
        }

        close(fd);
    }

    freeaddrinfo(result);

    if (rp == NULL)
        return -1;

    s->fd = fd;
    return 0;
}

static ngtcp2_conn* get_conn (ngtcp2_crypto_conn_ref* ref) {
    server *data = (server*) ref->user_data;

    return data->conn;
}

static int server_init(server *s) {
    int rv;

    s->ref.user_data = s;
    s->ref.get_conn = get_conn;

    rv = server_wolfssl_init(s);
    if (rv != 0) {
        return rv;
    }

    rv = server_resolve_and_bind(s, LOCAL_HOST, SERVER_PORT);
    if (rv != 0) {
        return rv;
    }

    rv = server_settings_init(s);

    if (rv != 0) {
        return rv;
    }

    return 0;
}

// TODO - NGTCP2 the struct sockaddr type
static int server_await_message(server *s, struct iovec *iov, struct sockaddr *remote_addr, size_t remote_addrlen) {
    /*
    Waits for a message to be recieved on the fd saved in server, and saved the recieved data into iov
    Also saves the sockaddr of the sender into remote_addr
    */
    struct pollfd conn_poll;
    
    struct msghdr msg;

    int rv;

    // Create socket polling
    conn_poll.fd = s->fd;
    conn_poll.events = POLLIN;

    // Clear message structure
    memset(&msg, 0, sizeof(msg));

    // Sents the fields where the senders address will be saved to by recvmsg
    msg.msg_name = remote_addr;
    msg.msg_namelen = remote_addrlen;

    // msg_iov is an array of iovecs to write the recieved message into. msg_iovlen is the size of that array.
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    // Waits for the fd saved to the server to be ready to read. No timeout
    poll(&conn_poll, 1, -1);
    
    // TODO - Think about flags here. https://pubs.opengroup.org/onlinepubs/009695399/functions/recvmsg.html
    rv = recvmsg(s->fd, &msg, 0);

    // Warning when buffer is not big enough to store the recieved message
    if (msg.msg_flags & MSG_TRUNC) {
        fprintf(stderr, "Warning: Message data was truncated as it did not fit into the buffer\n");
    }

    /*  If rv < 0, then error
    *   If rv == 0, client has closed the connection
    *   If rv > 0, read was success and rv bytes were read*/
    return rv;
}

static int server_accept_connection(server *s, struct iovec *iov, ngtcp2_path *path) {
    ngtcp2_version_cid version;
    ngtcp2_pkt_hd header;

    ngtcp2_transport_params params;

    int rv;

    rv = ngtcp2_pkt_decode_version_cid(&version, iov->iov_base, iov->iov_len, NGTCP2_MAX_CIDLEN);
    
    // TODO - Fix this assumtion?
    // Assume that the connection DCID is not found
    
    if (rv != 0) {
        fprintf(stderr, "Could not decode the version\n");
        return rv;
    }

    /*
    // DEBUG - https://nghttp2.org/ngtcp2/ngtcp2_pkt_decode_version_cid.html#c.ngtcp2_pkt_decode_version_cid
    if (version.scid == NULL) {
        fprintf(stdout, "Recieved a short packet header\n");
    } else {
        fprintf(stdout, "Recieved a long packet header\n");
    }
    */

    // Determine if the received first message is acceptable
    // If it is, write the data into the header structure
    rv = ngtcp2_accept(&header, iov->iov_base, iov->iov_len);
    if (rv != 0) {
        fprintf(stderr, "First packet could not be parsed or was unacceptable\n");
        return rv;
    }

    // First packet is acceptable, so create the ngtcp2_conn
    ngtcp2_transport_params_default(&params);

    // Docs state the the original_dcid field must be set
    params.original_dcid = header.dcid;
    params.original_dcid_present = 1;

    // Server DCID is client SCID. 
    ngtcp2_cid scid;
    scid.datalen = 8;
    if (rand_bytes(scid.data, scid.datalen) != 0) {
        fprintf(stderr, "Failed to populate server SCID\n");
        return -1;
    }

    rv = ngtcp2_conn_server_new(&s->conn, &header.scid, &scid, path, header.version, s->callbacks, s->settings, &params, NULL, s);

    ngtcp2_conn_set_tls_native_handle(s->conn, s->ssl);

    if (rv != 0) {
        fprintf(stderr, "Failed to create connection instance from incomming request\n");
        return rv;
    }

    return 0;
}

static int server_await_connection(server *s) {
    // TODO - Break function down further

    struct sockaddr remote_addr;

    int rv;

    struct iovec iov;
    // Must allocate space to save the incoming data into and set the pointer
    // TODO - Use a macro for the buf size and pull it out the defn
    uint8_t buf[8092];
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    // Call is blocking
    // Server waits for message on fd saved in s, saves data into iov and address into remote_addr
    rv = server_await_message(s, &iov, &remote_addr, sizeof(remote_addr));

    if (rv == 0) {
        fprintf(stdout, "Client closed connection\n");
        return -1; // TODO - Change this return value. New error origin point
    } else if (rv < 0) {
        // TODO - fprintf error
        return rv;
    }
    
    // remoteaddr populated by server_await_message
    ngtcp2_path path = {
        .local = {
            .addr = &s->localsock,
            .addrlen = s->locallen,
        },
        .remote = {
            .addr = &remote_addr,
            .addrlen = sizeof(remote_addr),
        }
    };

    // TODO - Comment with docs
    rv = server_accept_connection(s, &iov, &path);

    if (rv != 0) {
        // TODO - fprintf
        return rv;
    }

    fprintf(stdout, "Successfully created conn object\n");

    // TODO - Add comment docs. Check ngtcp2 manual
    rv = ngtcp2_conn_read_pkt(s->conn, &path, NULL, iov.iov_base, iov.iov_len, timestamp());

    if (rv != 0) {
        fprintf(stderr, "Failed to read packet\n");
        return rv;
    }

    return 0;
}

static int server_deinit(server *s) {
    // TODO - Cleanup conn and wolfSSL

    return 0;
}

int main(int argc, char **argv) {
    server s;

    int rv;

    // Server settings and parameters
    ngtcp2_transport_params params;
    ngtcp2_settings settings;

    rv = server_init(&s);
    if (rv != 0) {
        return rv;
    }

    // Server struct has fd, localaddr, ssl, callbacks and settings assigned

    rv = server_await_connection(&s);

    if (rv != 0) {
        return rv;
    }

    // TODO - Implement read-write server loop

    return 0;
}