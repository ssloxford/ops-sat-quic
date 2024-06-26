#ifndef CONNECTION_H
#define CONNECTION_H

#define DEFAULT_PORT "11120"
#define DEFAULT_IP "127.0.0.1"

#include <ngtcp2/ngtcp2.h>

#include <netdb.h>

typedef struct _data_node {
    uint8_t* payload;
    size_t payloadlen;

    uint64_t stream_id;

    // Total length of data sent before this one
    uint64_t offset;

    int fin_bit;

    // Time sent according to timestamp_ms()
    uint64_t time_sent;

    struct _data_node *next;
} data_node;

typedef struct _stream {
    int64_t stream_id;

    uint64_t stream_offset;

    // Timestamp of when the stream was opened for timing reporting
    int64_t stream_opened;

    data_node *inflight_head, *inflight_tail, *send_tail;

    struct _stream *next;
} stream;

typedef struct _stream_multiplex_ctx {
    stream *next_send;

    stream *streams_list;
} stream_multiplex_ctx;

ssize_t prepare_packet(ngtcp2_conn *conn, int64_t stream_id, uint8_t* buf, size_t buflen, ngtcp2_ssize *wdatalen, const uint8_t *data, size_t datalen, int fin);

ssize_t prepare_nonstream_packet(ngtcp2_conn *conn, uint8_t *buf, size_t buflen);

int send_packet(int fd, uint8_t* pkt, size_t pktlen, const struct sockaddr* dest_addr, socklen_t destlen);

ssize_t read_message(int fd, uint8_t *buf, size_t buflen, struct sockaddr *remote_addr, socklen_t *remote_addrlen);

ssize_t write_step(ngtcp2_conn *conn, int fd, stream_multiplex_ctx *multi_ctx, struct sockaddr *remote_addr, socklen_t remote_addrlen, int debug_level);

ssize_t send_nonstream_packets(ngtcp2_conn *conn, int fd, int limit, struct sockaddr *remote_addr, socklen_t remote_addrlen);

int get_timeout(ngtcp2_conn *conn);

int handle_timeout(ngtcp2_conn *conn, int fd, struct sockaddr *remote_addr, socklen_t remote_addrlen, int debug);

int insert_message(const uint8_t *payload, size_t payloadlen, int fin, uint64_t stream_id, uint64_t offset, data_node *insert_after);

int enqueue_message(const uint8_t *payload, size_t payloadlen, int fin, stream *stream);

stream* open_stream(ngtcp2_conn *conn);

stream* multiplex_streams(stream_multiplex_ctx *ctx);

void update_multiplex_ctx_stream_closing(stream_multiplex_ctx *ctx, stream *closed_stream);

void multiplex_ctx_advance_next_stream(stream_multiplex_ctx *ctx);

#endif