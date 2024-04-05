#include <ngtcp2/ngtcp2.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "connection.h"
#include "utils.h"
#include "errors.h"

int prepare_packet(ngtcp2_conn *conn, uint64_t stream_id, uint8_t* buf, size_t buflen, size_t *pktlen, struct iovec *iov) {
    // Write stream prepares the message to be sent into buf and returns size of the message
    ngtcp2_tstamp ts = timestamp();
    ngtcp2_pkt_info pi;
    ngtcp2_path_storage ps;
    ngtcp2_ssize wdatalen; // wdatalen is the length of data within STREAM (data) frames only

    int rv;

    ngtcp2_path_storage_zero(&ps);

    // Need to cast *iov to (ngtcp2_vec*). Apparently safe: https://nghttp2.org/ngtcp2/types.html#c.ngtcp2_vec
    rv = ngtcp2_conn_writev_stream(conn, &ps.path, &pi, buf, buflen, &wdatalen, NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id, (ngtcp2_vec*) iov, 1, ts);
    if (rv < 0) {
        fprintf(stderr, "Trying to write to stream failed: %s\n", ngtcp2_strerror(rv));
        return rv;
    }

    if (rv == 0) {
        // fprintf(stderr, "Warning: Buffer to prepare packet into too small or packet is congestion limited\n");
        return ERROR_NO_NEW_MESSAGE;
    }

    if (pktlen != NULL) {
        // Update pktlen with the length of the produced packet
        *pktlen = rv;
    }
    
    return 0;
}

int prepare_nonstream_packet(ngtcp2_conn *conn, uint8_t *buf, size_t buflen, size_t *pktlen) {
    return prepare_packet(conn, -1, buf, buflen, pktlen, NULL);
}

int send_packet(int fd, uint8_t* pkt, size_t pktlen) {
    struct iovec msg_iov;
    struct msghdr msg;

    memset(&msg, 0, sizeof(msg));

    int rv;

    // Assume that there is a packet to be sent in the global buf array
    msg_iov.iov_base = pkt;
    msg_iov.iov_len = pktlen;

    msg.msg_iov = &msg_iov;
    msg.msg_iovlen = 1;

    // Don't need to poll ready to write since UDP sockets are connectinless, so can always write
    rv = sendmsg(fd, &msg, 0);

    // On success rv > 0 is the number of bytes sent

    if (rv == -1) {
        fprintf(stderr, "sendmsg: %s\n", strerror(errno));
        return rv;
    }

    return 0;
}

int read_message(int fd, uint8_t *buf, size_t buflen, struct sockaddr *remote_addr, size_t remote_addrlen, size_t *bytes_read) {    
    struct msghdr msg;

    int rv;

    struct iovec iov;

    iov.iov_base = buf;
    iov.iov_len = buflen;
    
    // Clear message structure
    memset(&msg, 0, sizeof(msg));

    // Sents the fields where the senders address will be saved to by recvmsg
    msg.msg_name = remote_addr;
    msg.msg_namelen = remote_addrlen;

    // msg_iov is an array of iovecs to write the recieved message into. msg_iovlen is the size of that array.
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    
    rv = recvmsg(fd, &msg, MSG_DONTWAIT);

    if (rv == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return ERROR_NO_NEW_MESSAGE;
        }
        fprintf(stderr, "recvmsg: %s\n", strerror(errno));
        return rv;
    }

    *bytes_read = rv;

    return 0;
}


// Function code taken mostly from spaceQUIC
int resolve_and_process(int *save_fd, const char *target_host, const char* target_port, struct addrinfo *hints, int is_server, ngtcp2_sockaddr *localsock, ngtcp2_socklen *localsocklen, ngtcp2_sockaddr *remotesock, ngtcp2_socklen *remotesocklen) {
    struct addrinfo *result, *rp;
    int rv, fd;

    rv = getaddrinfo(target_host, target_port, hints, &result);
    if (rv != 0) {
        fprintf(stderr, "Failed to get address info for requested endpoint: %s\n", gai_strerror(rv));
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
        if (!is_server && connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            // Assign the path's remote addrlen. Must copy the value into the remote.addr pointer since rp will be deallocated
            *remotesocklen = rp->ai_addrlen;
            memcpy(remotesock, rp->ai_addr, rp->ai_addrlen);

            // Set the local path of the client
            if (getsockname(fd, localsock, localsocklen) == -1)
                return ERROR_GET_SOCKNAME;

            // Exit the loop when the first successful connection is made
            break;
        } else if (is_server && bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            *localsocklen = rp->ai_addrlen;
            memcpy(localsock, rp->ai_addr, rp->ai_addrlen);
            break;
        }

        // If the connection was not made, close the fd and keep looking
        close(fd);
    }

    // Must manually deallocate the results from the lookup
    freeaddrinfo(result);

    // If the loop finished by getting to the end, rather than with a successful connection, return -1
    if (rp == NULL) {
        fprintf(stderr, "Could not proccess any resolved addresses\n");
        return ERROR_COULD_NOT_OPEN_CONNECTION_FD;
    }

    // Save the fd of the open socket connected to the endpoint
    *save_fd = fd;
    return 0;
}

int write_step(ngtcp2_conn *conn, int fd, uint64_t stream_id, uint8_t *data, size_t datalen) {
    // Data and datalen is the data to be written
    // Buf and bufsize is a general use memory allocation (eg. to pass packets to subroutines)
    size_t pktlen;
    struct iovec iov;

    uint8_t buf[BUF_SIZE];

    int rv;

    iov.iov_base = data;
    iov.iov_len = datalen;

    // Send any non-stream packets (eg. handshake, ack, etc.)
    for (;;) {
        rv = prepare_nonstream_packet(conn, buf, sizeof(buf), &pktlen);
        if (rv == ERROR_NO_NEW_MESSAGE) {
            // No more "housekeeping" packets to send. Continue to data packet
            break;
        }

        if (rv != 0) {
            return rv;
        }

        rv = send_packet(fd, buf, pktlen);

        if (rv != 0) {
            return rv;
        }

    }

    if (stream_id != -1) {
        // A stream is open, so we will write to the stream
        rv = prepare_packet(conn, stream_id, buf, sizeof(buf), &pktlen, &iov);

        if (rv != 0) {
            return rv;
        }

        rv = send_packet(fd, buf, pktlen);
        
        if (rv != 0) {
            return rv;
        }
    }

    return 0;
}