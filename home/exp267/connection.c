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

int prepare_packet(ngtcp2_conn *conn, uint64_t stream_id, uint8_t* buf, size_t buflen, size_t *pktlen, ngtcp2_ssize *wdatalen, struct iovec *iov, int fin) {
    // Write stream prepares the message to be sent into buf and returns size of the message
    ngtcp2_tstamp ts = timestamp();
    ngtcp2_pkt_info pi;
    ngtcp2_path_storage ps;

    int rv;

    ngtcp2_path_storage_zero(&ps);

    int flag = NGTCP2_WRITE_STREAM_FLAG_NONE;
    if (fin) {
        // This is the final stream frame for this stream
        flag |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    }

    // Need to cast *iov to (ngtcp2_vec*). Apparently safe: https://nghttp2.org/ngtcp2/types.html#c.ngtcp2_vec
    rv = ngtcp2_conn_writev_stream(conn, &ps.path, &pi, buf, buflen, wdatalen, flag, stream_id, (ngtcp2_vec*) iov, 1, ts);
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
    return prepare_packet(conn, -1, buf, buflen, pktlen, NULL, NULL, 0);
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

int write_step(ngtcp2_conn *conn, int fd, uint64_t stream_id, int fin, const uint8_t *data, size_t datalen, inflight_data **inflight, uint64_t *sent_offset) {
    // Data and datalen is the data to be written
    // Buf and bufsize is a general use memory allocation (eg. to pass packets to subroutines)
    size_t pktlen;
    struct iovec iov;

    uint8_t buf[BUF_SIZE];

    int rv;

    if (stream_id != -1) {
        // There's an open stream
        uint8_t *pkt_data = malloc(datalen);
        ngtcp2_ssize stream_framelen;


        if (pkt_data == NULL) {
            fprintf(stderr, "Warning: Failed to allocate buffer memory of length %ld to write packet\n", datalen);
            return ERROR_OUT_OF_MEMORY;
        }

        // Copy the provided data into malloced buffer to allow storage in the ack tracking
        memcpy(pkt_data, data, datalen);

        iov.iov_base = pkt_data;
        iov.iov_len = datalen;

        // A stream is open, so we will write to the stream
        // Will also add "housekeeping" frames to the packet
        rv = prepare_packet(conn, stream_id, buf, sizeof(buf), &pktlen, &stream_framelen, &iov, fin);

        if (rv != 0) {
            free(pkt_data);
            return rv;
        }

        rv = send_packet(fd, buf, pktlen);

        if (rv != 0) {
            free(pkt_data);
            return rv;
        }

        // Allocate a new inflight data node
        *inflight = malloc(sizeof(inflight_data));

        if (*inflight == NULL) {
            // If out of memory, make sure all allocated memory is freed
            // Will mean that if this packet is not ACKed the data is lost
            fprintf(stderr, "Warning: Failed to allocate new node to track inflight data\n");
            free(pkt_data);
            return ERROR_OUT_OF_MEMORY;
        }

        (*inflight)->payload = pkt_data;
        (*inflight)->payloadlen = stream_framelen;
        (*inflight)->stream_id = stream_id;
        (*inflight)->offset = *sent_offset;

        *sent_offset = *sent_offset + stream_framelen;
    }

    // If there are any "housekeeping" frames that didn't fit into the above packet, send them now
    // Will likely only send packets if the above code wasn't run. Housekeeping frames are typically small
    rv = send_nonstream_packets(conn, fd, buf, sizeof(buf), -1);

    if (rv != 0) {
        return rv;
    }

    return 0;
}

// Processes preparing and sending all available acknowledge packets, handshake, etc.
int send_nonstream_packets(ngtcp2_conn *conn, int fd, uint8_t *buf, size_t buflen, int limit) {
    size_t pktlen;
    int rv;

    // Limit less than 0 is treated as no limit
    for (int i = 0; limit < 0 || i < limit; i++) {
        rv = prepare_nonstream_packet(conn, buf, buflen, &pktlen);
        if (rv == ERROR_NO_NEW_MESSAGE) {
            // No more "housekeeping" packets to send. Return 
            return 0;
        }

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

int handle_timeout(ngtcp2_conn *conn, int fd) {
    int rv;

    // Docs are incredibly sparse on this
    // Basically just adjusts internal state to inform writev_stream of what to do next
    rv = ngtcp2_conn_handle_expiry(conn, timestamp());

    if (rv == NGTCP2_ERR_IDLE_CLOSE) {
        return ERROR_DROP_CONNECTION;
    }

    uint8_t buf[BUF_SIZE];

    // Send a single non-stream packet
    rv = send_nonstream_packets(conn, fd, buf, sizeof(buf), 1);

    if (rv != 0) {
        return rv;
    }

    return 0;
}