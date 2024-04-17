#ifndef CONNECTION_H
#define CONNECTION_H

#define SERVER_PORT "11111"
#define DEFAULT_IP "localhost"

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

    data_node *inflight_head, *inflight_tail, *send_tail;

    struct _stream *next;
} stream;

ssize_t prepare_packet(ngtcp2_conn *conn, int64_t stream_id, uint8_t* buf, size_t buflen, ngtcp2_ssize *wdatalen, struct iovec *iov, int fin);

ssize_t prepare_nonstream_packet(ngtcp2_conn *conn, uint8_t *buf, size_t buflen);

int send_packet(int fd, uint8_t* pkt, size_t pktlen, const struct sockaddr* dest_addr, socklen_t destlen);

ssize_t read_message(int fd, uint8_t *buf, size_t buflen, struct sockaddr *remote_addr, socklen_t *remote_addrlen);

ssize_t write_step(ngtcp2_conn *conn, int fd, const data_node *send_queue);

ssize_t send_nonstream_packets(ngtcp2_conn *conn, int fd, uint8_t *buf, size_t buflen, int limit);

int get_timeout(ngtcp2_conn *conn);

int handle_timeout(ngtcp2_conn *conn, int fd);

int enqueue_message(const uint8_t *payload, size_t payloadlen, int fin, stream *stream);

#endif