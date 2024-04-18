#include "callbacks.h"
#include "utils.h"

#include <stdio.h>
#include <inttypes.h>

int acked_stream_data_offset_cb(ngtcp2_conn *conn, uint64_t offset, uint64_t datalen, stream *stream, int timing) {
    // The remote has acknowledged all data in the range [offset, offset+datalen)
    // Used for calculating inflight time of acknowledged packets, to be reported if timing is on
    uint64_t delta;

    // Start on the dummy header
    data_node *prev_ptr = stream->inflight_head;
    
    // Must update using prev_ptr->next as ptr may have been deallocated
    for (data_node *ptr = prev_ptr->next; prev_ptr != stream->inflight_tail; ptr = prev_ptr->next) {
        if (ptr->offset >= offset && ptr->offset < (offset + datalen)) {
            // This frame has been acked in this call. We can deallocate it
            // Update the pointers
            prev_ptr->next = ptr->next;

            if (timing) {
                // Report total time in flight of this packet
                delta = timestamp_ms() - ptr->time_sent;

                printf("Packet at offset %"PRIu64" acknowledged. Total time inflight: %"PRIu64" ms\n", offset, delta);
            }

            free(ptr->payload);
            free(ptr);

            // If deleting the last element of the list, make the tail pointer accurate
            if (ptr == stream->inflight_tail) {
                // Deleting the last element of the queue. Must update the pointers to track
                stream->inflight_tail = prev_ptr;
                if (stream->send_tail == ptr) {
                    // We're also deleting the send_tail, meaning the send list must have been empty. Therefore, we must update the tail pointer to track the send head
                    stream->send_tail = stream->inflight_tail;
                }
            }
        } else {
            // Keep tracking the previous pointer
            prev_ptr = ptr;
        }
    }

    return 0;
}

int extend_max_local_streams_uni_cb(ngtcp2_conn *conn, stream *stream_list) {
    stream* stream_n = malloc(sizeof(stream));

    if (stream_n == NULL) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    stream_n->stream_offset = 0;

    // Set up the dummy header on the stream
    stream_n->inflight_head = malloc(sizeof(data_node));

    if (stream_n->inflight_head == NULL) {
        free(stream_n);
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    // Initialse all the pointers
    stream_n->inflight_tail = stream_n->send_tail = stream_n->inflight_head;
    stream_n->send_tail->next = NULL;

    // Opens a new stream and sets the stream id in the stream struct
    int rv = ngtcp2_conn_open_uni_stream(conn, &stream_n->stream_id, stream_n);

    if (rv < 0) {
        free(stream_n->inflight_head);
        free(stream_n);
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    // Insert the newly created stream at the head of the provided stream list
    stream_n->next = stream_list->next;
    stream_list->next = stream_n;

    return 0;
}

int stream_close_cb(stream *stream_n, stream *stream_list) {
    // Deallocate ack/send queue
    for (data_node *node = stream_n->inflight_head->next; node != NULL; node = stream_n->inflight_head->next) {        
        // Free the node
        free(node->payload);
        free(node);
    }

    // Free the dummy header on the ack/send queue
    free(stream_n->inflight_head);

    stream *prev_stream = stream_list;

    // Linear search for the stream in the queue so that the queue can be rejoined around it
    for (stream *this_stream = prev_stream->next; this_stream == stream_n; this_stream = prev_stream->next) {
        prev_stream = this_stream;
    }

    prev_stream->next = stream_n->next;
    free(stream_n);

    return 0;
}

int handshake_completed_cb(uint64_t initial_ts) {
    uint64_t delta = timestamp_ms() - initial_ts;

    printf("Handshake completed: %"PRIu64" ms\n", delta);

    return 0;
}

// Callback not used for crypto RNG so safe to delegate to stdlib rand() (not crypto secure)
void rand_cb(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx* rand_ctx) {
    rand_bytes(dest, destlen);
}

int get_new_connection_id_cb(ngtcp2_conn* conn, ngtcp2_cid* cid, uint8_t* token, size_t cidlen, void* user_data){
    rand_bytes(cid->data, cidlen);

    cid->datalen = cidlen;

    rand_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);

    return 0;
}
