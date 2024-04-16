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
#include <limits.h>

#include "connection.h"
#include "utils.h"
#include "errors.h"

ssize_t prepare_packet(ngtcp2_conn *conn, uint64_t stream_id, uint8_t* buf, size_t buflen, ngtcp2_ssize *wdatalen, struct iovec *iov, int fin) {
    // Write stream prepares the message to be sent into buf and returns size of the message
    ngtcp2_tstamp ts = timestamp();
    ngtcp2_pkt_info pi;
    ngtcp2_path_storage ps;

    ssize_t bytes_written;

    ngtcp2_path_storage_zero(&ps);

    int flag = NGTCP2_WRITE_STREAM_FLAG_NONE;
    if (fin) {
        // This is the final stream frame for this stream
        flag |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    }

    // Need to cast *iov to (ngtcp2_vec*). Apparently safe: https://nghttp2.org/ngtcp2/types.html#c.ngtcp2_vec
    bytes_written = ngtcp2_conn_writev_stream(conn, &ps.path, &pi, buf, buflen, wdatalen, flag, stream_id, (ngtcp2_vec*) iov, 1, ts);
    if (bytes_written < 0) {
        fprintf(stderr, "Trying to write to stream failed: %s\n", ngtcp2_strerror(bytes_written));
        return bytes_written;
    }

    if (bytes_written == 0) {
        // fprintf(stderr, "Warning: Buffer to prepare packet into too small or packet is congestion limited\n");
        return ERROR_NO_NEW_MESSAGE;
    }
    
    return bytes_written;
}

ssize_t prepare_nonstream_packet(ngtcp2_conn *conn, uint8_t *buf, size_t buflen) {
    return prepare_packet(conn, -1, buf, buflen, NULL, NULL, 0);
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

    return rv;
}

ssize_t read_message(int fd, uint8_t *buf, size_t buflen, struct sockaddr *remote_addr, size_t remote_addrlen) {    
    struct msghdr msg;

    ssize_t bytes_read;

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
    
    bytes_read = recvmsg(fd, &msg, MSG_DONTWAIT);

    if (bytes_read == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return ERROR_NO_NEW_MESSAGE;
        }
        fprintf(stderr, "recvmsg: %s\n", strerror(errno));
        return bytes_read;
    }

    return bytes_read;
}

int write_step(ngtcp2_conn *conn, int fd, int fin, const data_node *send_queue, size_t *stream_offset) {
    // Data and datalen is the data to be written
    // Buf and bufsize is a general use memory allocation (eg. to pass packets to subroutines)
    size_t pktlen;
    struct iovec iov;

    uint8_t buf[BUF_SIZE];

    memset(buf, 0, sizeof(buf));

    ssize_t rv;

    data_node *pkt_to_send = send_queue->next;

    if (pkt_to_send != NULL) {
        // There's something in the send queue
        ngtcp2_ssize stream_framelen;

        iov.iov_base = pkt_to_send->payload;
        iov.iov_len = pkt_to_send->payloadlen;

        // A stream is open, so we will write to the stream
        // Will also add "housekeeping" frames to the packet
        pktlen = prepare_packet(conn, pkt_to_send->stream_id, buf, sizeof(buf), &stream_framelen, &iov, fin);

        if (pktlen < 0) {
            return pktlen;
        }

        rv = send_packet(fd, buf, pktlen);

        if (rv < 0) {
            return rv;
        }

        pkt_to_send->time_sent = timestamp_ms();

        *stream_offset = *stream_offset + stream_framelen;
    }

    // If there are any "housekeeping" frames that didn't fit into the above packet, send them now
    // Will likely only send packets if the above code wasn't run. Housekeeping frames are typically small
    rv = send_nonstream_packets(conn, fd, buf, sizeof(buf), -1);

    if (rv < 0) {
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
        pktlen = prepare_nonstream_packet(conn, buf, buflen);
        if (pktlen == ERROR_NO_NEW_MESSAGE) {
            // No more "housekeeping" packets to send. Return 
            return 0;
        }

        if (pktlen < 0) {
            return pktlen;
        }

        rv = send_packet(fd, buf, pktlen);

        if (rv < 0) {
            return rv;
        }
    }

    return 0;
}

int get_timeout(ngtcp2_conn *conn) {
    ngtcp2_tstamp expiry, delta_time, now = timestamp();

    uint64_t timeout;

    // The timestamp (according to timestamp()) of the next time-sensitive intervention
    // Conn expiry is updated as calls to writev_stream etc. are made
    expiry = ngtcp2_conn_get_expiry(conn);

    if (expiry == UINT64_MAX) {
        // Not waiting on any expiry
        return -1;
    } else {
        // Expiry should be ahead of timestamp()
        delta_time = expiry - now;
        if (delta_time < 0) {
            // Expiry to wait on has passed. Continue immediately
            return 0;
        } else {
            // Return millisecond resolution. Timestamp uses nanosecond resolution
            // Will truncate to a millisecond. Round up to not underestimate
            timeout = delta_time / (1000 * 1000);
            if (timeout >= INT_MAX) {
                // Clamp the value down to max int value. We can just set another wait if needed (INT_MAX ms will be a while)
                return INT_MAX;
            }
            return timeout+1;
        }
    }
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

    if (rv < 0) {
        return rv;
    }

    return 0;
}

int enqueue_message(const uint8_t *payload, size_t payloadlen, uint64_t stream_id, uint64_t offset, data_node *queue_tail) {
    uint8_t *pkt_data = malloc(payloadlen);

    if (pkt_data == NULL) {
        return ERROR_OUT_OF_MEMORY;
    }

    // Create a new data node and 
    data_node *queue_node = malloc(sizeof(data_node));

    if (queue_node == NULL) {
        free(pkt_data);
        return ERROR_OUT_OF_MEMORY;
    }

    // Load the provided data into the allocated node buffer
    memcpy(pkt_data, payload, payloadlen);

    queue_node->payload = pkt_data;
    queue_node->payloadlen = payloadlen;

    queue_node->stream_id = stream_id;

    queue_node->offset = offset;

    // Join the values after queue_tail onto the created node
    // For a true tail node, this will be NULL
    queue_node->next = queue_tail->next;

    // Add the new node after *queue_tail
    queue_tail->next = queue_node;

    return 0;
}
