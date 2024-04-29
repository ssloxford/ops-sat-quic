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

ssize_t prepare_packet(ngtcp2_conn *conn, int64_t stream_id, uint8_t* buf, size_t buflen, ngtcp2_ssize *wdatalen, struct iovec *iov, int fin) {
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

    // Manages the timer for when the packet can be sent. If it's too early, no packet will have been written and a timeout will send it
    ngtcp2_conn_update_pkt_tx_time(conn, ts);

    if (bytes_written == 0) {
        // fprintf(stderr, "Warning: Packet is congestion limited\n");
        return ERROR_NO_NEW_MESSAGE;
    }

    return bytes_written;
}

ssize_t prepare_nonstream_packet(ngtcp2_conn *conn, uint8_t *buf, size_t buflen) {
    return prepare_packet(conn, -1, buf, buflen, NULL, NULL, 0);
}

int send_packet(int fd, uint8_t* pkt, size_t pktlen, const struct sockaddr* dest_addr, socklen_t destlen) {
    int rv;

    // Don't need to poll ready to write since UDP sockets are connectinless, so can always write
    rv = sendto(fd, pkt, pktlen, 0, dest_addr, destlen);

    // On success rv > 0 is the number of bytes sent

    if (rv == -1) {
        fprintf(stderr, "sendto: %s\n", strerror(errno));
        return rv;
    }

    return rv;
}

ssize_t read_message(int fd, uint8_t *buf, size_t buflen, struct sockaddr *remote_addr, socklen_t *remote_addrlen) {    
    ssize_t bytes_read;
    
    bytes_read = recvfrom(fd, buf, buflen, MSG_DONTWAIT, remote_addr, remote_addrlen);

    if (bytes_read == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return ERROR_NO_NEW_MESSAGE;
        }
        fprintf(stderr, "recvfrom: %s\n", strerror(errno));
        return bytes_read;
    }

    return bytes_read;
}

ssize_t write_step(ngtcp2_conn *conn, int fd, stream_multiplex_ctx *multi_ctx, struct sockaddr* sockaddr, socklen_t sockaddrlen) {
    // Data and datalen is the data to be written
    // Buf and bufsize is a general use memory allocation (eg. to pass packets to subroutines)
    ssize_t pktlen;
    struct iovec iov;

    ngtcp2_ssize stream_framelen;

    uint8_t buf[BUF_SIZE];

    memset(buf, 0, sizeof(buf));

    ssize_t rv;

    data_node *pkt_to_send;
    stream *send_stream;
    
    for (;;) {
        // Decide on the next stream to send on
        send_stream = multiplex_streams(multi_ctx);

        if (send_stream == NULL) {
            // All the streams have empty send queues. Exit the send loop
            break;
        } else {
            // Multiplex_streams will not return a stream with empty send queue, so pkt_to_send is not null
            pkt_to_send = send_stream->inflight_tail->next;
        }
        
        iov.iov_base = pkt_to_send->payload;
        iov.iov_len = pkt_to_send->payloadlen;

        // Prepare a packet containing a stream frame with the selected data taken from the queue
        pktlen = prepare_packet(conn, send_stream->stream_id, buf, sizeof(buf), &stream_framelen, &iov, pkt_to_send->fin_bit);

        if (pktlen < 0) {
            if (pktlen == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
                // This stream has reached maximum capacity (according to remote max stream data parameter)
                // We should sent a fin bit on this stream, open a new one, and copy the send queue (with updated offsets)
                // TODO - Implement this
                return pktlen;
            } else if (pktlen == ERROR_NO_NEW_MESSAGE) {
                // We've filled the congestion window. The NGTCP2 expiry will fire when we are next allowed to send
                return 0;
            }
            return pktlen;
        }

        rv = send_packet(fd, buf, pktlen, sockaddr, sockaddrlen);

        if (rv < 0) {
            return rv;
        }

        pkt_to_send->time_sent = timestamp_ms();

        // Update the inflight and send queues for the selected stream
        send_stream->inflight_tail = pkt_to_send;
    }

    // If there are any "housekeeping" frames that didn't fit into the above packet, send them now
    // Will likely only send packets if the above code wasn't run. Housekeeping frames are typically small
    rv = send_nonstream_packets(conn, fd, -1, sockaddr, sockaddrlen);

    if (rv < 0) {
        return rv;
    }

    return 0;
}

// Processes preparing and sending all available acknowledge packets, handshake, etc.
ssize_t send_nonstream_packets(ngtcp2_conn *conn, int fd, int limit, struct sockaddr* sockaddr, socklen_t sockaddrlen) {
    ssize_t pktlen;
    int rv;

    uint8_t buf[BUF_SIZE];

    // Limit less than 0 is treated as no limit
    for (int i = 0; limit < 0 || i < limit; i++) {
        pktlen = prepare_nonstream_packet(conn, buf, sizeof(buf));
        if (pktlen == ERROR_NO_NEW_MESSAGE) {
            // No more "housekeeping" packets to send. Return 
            return 0;
        }

        if (pktlen < 0) {
            return pktlen;
        }

        rv = send_packet(fd, buf, pktlen, sockaddr, sockaddrlen);

        if (rv < 0) {
            return rv;
        }
    }

    return 0;
}

int get_timeout(ngtcp2_conn *conn) {
    ngtcp2_tstamp expiry, now = timestamp();

    int64_t delta_time;

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

int handle_timeout(ngtcp2_conn *conn, int fd, struct sockaddr *remote_addr, socklen_t remote_addrlen, int debug) {
    int rv;

    // Docs are incredibly sparse on this
    // Basically just adjusts internal state to inform writev_stream of what to do next
    rv = ngtcp2_conn_handle_expiry(conn, timestamp());

    if (debug >= 2 && rv != 0) {
        printf("Handle expiry: %s\n", ngtcp2_strerror(rv));
    }

    if (rv == NGTCP2_ERR_IDLE_CLOSE || rv == NGTCP2_ERR_HANDSHAKE_TIMEOUT) {
        return ERROR_DROP_CONNECTION;
    }

    // Send a single non-stream packet
    rv = send_nonstream_packets(conn, fd, 1, remote_addr, remote_addrlen);

    if (rv < 0) {
        return rv;
    }

    return 0;
}

int enqueue_message(const uint8_t *payload, size_t payloadlen, int fin, stream *stream) {
    uint8_t *pkt_data = malloc(payloadlen);

    if (pkt_data == NULL && payloadlen > 0) {
        return ERROR_OUT_OF_MEMORY;
    }

    // Create a new data node and 
    data_node *queue_node = malloc(sizeof(data_node));

    if (queue_node == NULL) {
        free(pkt_data);
        return ERROR_OUT_OF_MEMORY;
    }

    // Load the provided data into the allocated node buffer. Memcpy of payloadlen = 0 is defined as a no-op
    memcpy(pkt_data, payload, payloadlen);

    queue_node->payload = pkt_data;
    queue_node->payloadlen = payloadlen;

    queue_node->stream_id = stream->stream_id;

    queue_node->offset = stream->stream_offset;

    stream->stream_offset += payloadlen;

    queue_node->fin_bit = fin;

    // Enqueue the created node and update relevant pointers
    // Insert the queue_node after the send_tail
    queue_node->next = stream->send_tail->next;
    stream->send_tail->next = queue_node;
    // Update the send tail to track the new node
    stream->send_tail = queue_node;

    return 0;
}

stream* open_stream(ngtcp2_conn *conn) {
    stream *stream_n = malloc(sizeof(stream));
    int64_t stream_id;

    if (stream_n == NULL) {
        return NULL;
    }

    stream_n->stream_offset = 0;
    stream_n->stream_opened = timestamp_ms();

    // Set up the dummy header on the stream
    stream_n->inflight_head = malloc(sizeof(data_node));

    if (stream_n->inflight_head == NULL) {
        free(stream_n);
        return NULL;
    }

    // Initialse all the pointers
    stream_n->inflight_tail = stream_n->send_tail = stream_n->inflight_head;
    stream_n->send_tail->next = NULL;

    // Opens a new stream and sets the stream id in the stream struct
    int rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, stream_n);

    stream_n->stream_id = stream_id;

    if (rv < 0) {
        free(stream_n->inflight_head);
        free(stream_n);
        return NULL;
    }

    return stream_n;
}

stream* multiplex_streams(stream_multiplex_ctx *ctx) {
    stream *ptr;
    
    // Verify that the last_sent stream has not been closed
    for (ptr = ctx->streams_list; ptr != NULL; ptr = ptr->next) {
        if (ptr == ctx->last_sent) {
            // Found the stream in the list
            break;
        }
    }

    if (ptr == NULL) {
        // The last_sent had been closed. Reset the last_sent
        ctx->last_sent = ctx->streams_list;
    }

    for (ptr = ctx->last_sent->next; ptr != ctx->last_sent;) {
        if (ptr == NULL) {
            // We've reached the end of the list. Loop around to the front.
            ptr = ctx->streams_list;
            // Must continue so the terminatation condition is rechecked and the pointer is advanced to a real stream
            // If there was no last_sent, dummy header is last sent
            continue;
        }

        if (ptr->inflight_tail != ptr->send_tail) {
            // The send queue for this stream is non-empty
            break;
        }

        ptr = ptr->next;
    }

    // We could have pointer end at last_sent if all are empty or if that's the valid next stream to send
    if (ptr == ctx->last_sent && ptr->inflight_tail == ptr->send_tail) {
        // All stream send queues are empty
        return NULL;
    }

    // Update the context ready for next time
    ctx->last_sent = ptr;

    return ptr;
}
