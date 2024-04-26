// Word count: 5997
#ifndef CALLBACKS_H
#define CALLBACKS_H

#include <ngtcp2/ngtcp2.h>

#include <stdint.h>
#include <stddef.h>

#include "connection.h"

int acked_stream_data_offset_cb(ngtcp2_conn *conn, uint64_t offset, uint64_t datalen, stream *stream, int timing);

int extend_max_local_streams_uni_cb(ngtcp2_conn *conn, stream *stream_list);

int stream_close_cb(stream *stream_n, stream *stream_list);

int handshake_completed_cb(uint64_t initial_ts);

void rand_cb(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx* rand_ctx);

int get_new_connection_id_cb(ngtcp2_cid* cid, uint8_t* token, size_t cidlen);

#endif