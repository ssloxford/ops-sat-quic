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

ssize_t prepare_packet(ngtcp2_conn *conn, int64_t stream_id, uint8_t* buf, size_t buflen, ngtcp2_ssize *wdatalen, const uint8_t *data, size_t datalen, int fin) {
    // Write stream prepares the message to be sent into buf and returns size of the message
    ngtcp2_tstamp ts = timestamp();
    ngtcp2_pkt_info pi;
    ngtcp2_path_storage ps;

    ssize_t bytes_written;

    // Initialises path storage. It's a path struct packaged with the sockaddr structs also allocated
    ngtcp2_path_storage_zero(&ps);

    int flag = NGTCP2_WRITE_STREAM_FLAG_NONE;
    if (fin) {
        // This is the final stream frame for this stream
        flag |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    }

    bytes_written = ngtcp2_conn_write_stream(conn, &ps.path, &pi, buf, buflen, wdatalen, flag, stream_id, data, datalen, ts);
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
    return prepare_packet(conn, -1, buf, buflen, NULL, NULL, 0, 0);
}

int send_packet(int fd, uint8_t* pkt, size_t pktlen, const struct sockaddr* dest_addr, socklen_t destlen) {
    int rv;

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

ssize_t write_step(ngtcp2_conn *conn, int fd, stream_multiplex_ctx *multi_ctx, struct sockaddr* sockaddr, socklen_t sockaddrlen, int debug_level) {
    // Data and datalen is the data to be written
    // Buf and bufsize is a general use memory allocation (eg. to pass packets to subroutines)
    ssize_t pktlen;

    ngtcp2_ssize stream_framelen;

    uint8_t buf[BUF_SIZE];

    memset(buf, 0, sizeof(buf));

    ssize_t rv;

    data_node *pkt_to_send;
    stream *send_stream;
    
    // Send a packet with any required "housekeeping" frames, eg. acknowledgements
    rv = send_nonstream_packets(conn, fd, 1, sockaddr, sockaddrlen);

    if (rv < 0) {
        return rv;
    }

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

        // Prepare a packet containing a stream frame with the selected data taken from the queue
        pktlen = prepare_packet(conn, send_stream->stream_id, buf, sizeof(buf), &stream_framelen, pkt_to_send->payload, pkt_to_send->payloadlen, pkt_to_send->fin_bit);

        if (pktlen < 0) {
            if (pktlen == ERROR_NO_NEW_MESSAGE) {
                // We've filled the congestion window. The NGTCP2 expiry will fire when we are next allowed to send
                if (debug_level >= 2) printf("Congestion window full. Data at %"PRIu64" on stream %"PRId64" not sent\n", pkt_to_send->offset, send_stream->stream_id);
                return 0;
            }
            return pktlen;
        }

        rv = send_packet(fd, buf, pktlen, sockaddr, sockaddrlen);

        // Indicate we just sent on the stream provided, so advance the round robin pointer
        multiplex_ctx_advance_next_stream(multi_ctx);

        if (rv < 0) {
            return rv;
        }

        if (debug_level >= 2) printf("Sent a stream frame to stream %"PRId64"\n", send_stream->stream_id);

        if (stream_framelen != pkt_to_send->payloadlen) {
            // The ammount of data sent was not equal to the ammount of data provided
            if (stream_framelen == -1) {
                // None of the stream frame was added, do not advance the inflight tail
                continue;
            }

            if (debug_level >= 2) printf("Detected partially sent packet, splitting in send queue\n");

            // Split the part sent packet and add the unsent section to the queue after the sent section. We can then advance the tail pointer as normal
            insert_message(pkt_to_send->payload + stream_framelen, pkt_to_send->payloadlen - stream_framelen, pkt_to_send->fin_bit, pkt_to_send->stream_id, pkt_to_send->offset + stream_framelen, pkt_to_send);
            // Updating this isn't strictly necessary, but the fin bit in the sent packet was clear so it's nice to reflect that in the send queue
            pkt_to_send->fin_bit = 0;
        }


        pkt_to_send->time_sent = timestamp_ms();

        // Update the inflight and send queues for the selected stream
        send_stream->inflight_tail = pkt_to_send;
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
            // No more "housekeeping" packets to send or congestion window full.
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

int handle_timeout(ngtcp2_conn *conn, int fd, struct sockaddr *remote_addr, socklen_t remote_addrlen, int debug_level) {
    int rv;

    // Docs are incredibly sparse on this
    // Basically just adjusts internal state to inform writev_stream of what to do next
    rv = ngtcp2_conn_handle_expiry(conn, timestamp());

    if (debug_level >= 2 && rv != 0) {
        printf("Handle expiry: %s\n", ngtcp2_strerror(rv));
    }

    if (rv == NGTCP2_ERR_IDLE_CLOSE || rv == NGTCP2_ERR_HANDSHAKE_TIMEOUT) {
        return ERROR_DROP_CONNECTION;
    }

    // Send any non-stream packets needed
    rv = send_nonstream_packets(conn, fd, -1, remote_addr, remote_addrlen);

    if (rv < 0) {
        return rv;
    }

    return 0;
}

int enqueue_message(const uint8_t *payload, size_t payloadlen, int fin, stream *stream) {
    int rv;

    // Inserts the new message at the end of the stream's send queue
    rv = insert_message(payload, payloadlen, fin, stream->stream_id, stream->stream_offset, stream->send_tail);

    if (rv < 0) {
        return rv;
    }

    // Keep track of the stream offset
    stream->stream_offset += payloadlen;

    // Update the send tail to be the newly created node
    stream->send_tail = stream->send_tail->next;

    return 0;
}

int insert_message(const uint8_t *payload, size_t payloadlen, int fin, uint64_t stream_id, uint64_t offset, data_node *insert_after) {
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

    queue_node->stream_id = stream_id;

    queue_node->offset = offset;

    queue_node->fin_bit = fin;

    queue_node->next = insert_after->next;
    insert_after->next = queue_node;

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

void update_multiplex_ctx_stream_closing(stream_multiplex_ctx *ctx, stream *closed_stream) {
    if (ctx->next_send == closed_stream) {
        // Update the next send pointer to the stream after the one closed in the order
        ctx->next_send = closed_stream->next;
        if (ctx->next_send == NULL) {
            ctx->next_send = ctx->streams_list;
        }
    }
}

void multiplex_ctx_advance_next_stream(stream_multiplex_ctx *ctx) {
    if (ctx->next_send == ctx->streams_list) {
        // Linear search through the streams list
        for (stream *ptr = ctx->streams_list->next; ptr != NULL; ptr = ptr->next) {
            if (ptr->inflight_tail != ptr->send_tail) {
                // The send queue for this stream is non-empty
                ctx->next_send = ptr;
                break;
            }
        }
    } else {
        // We need to search the list while also looping round to the front once we get to the end
        // We also know that the streams list is non-empty
        for (stream *ptr = ctx->next_send->next;; ptr = ptr->next) {
            if (ptr == NULL) {
                // We hit the end of the list, so move the the front
                ptr = ctx->streams_list->next;
            }

            if (ptr->inflight_tail != ptr->send_tail) {
                // The send queue for this stream is non-empty, so we use this one
                ctx->next_send = ptr;
                break;
            }

            if (ptr == ctx->next_send) {
                // We've gone the whole way around without finding a suitable next stream
                break;
            }
        }
    }
}

stream* multiplex_streams(stream_multiplex_ctx *ctx) {
    if (ctx->next_send->inflight_tail == ctx->next_send->send_tail) {
        // The next send has an empty send queue, so look for the next stream with a populated send queue. If all are empty, this is a NOP
        multiplex_ctx_advance_next_stream(ctx);
    }
    if (ctx->next_send->inflight_tail == ctx->next_send->send_tail) {
        // No stream has a populated send queue, so return NULL
        return NULL;
    }
    return ctx->next_send;
}
