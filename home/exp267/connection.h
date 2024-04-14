#ifndef CONNECTION_H
#define CONNECTION_H

#define SERVER_PORT "11111"
#define DEFAULT_IP "localhost"

#include <ngtcp2/ngtcp2.h>

#include <netdb.h>

typedef struct _data_node {
    uint8_t* payload;
    ssize_t payloadlen;

    uint64_t stream_id;

    // Total length of data sent before this one
    uint64_t offset;

    struct _data_node *next;
} data_node;

ssize_t prepare_packet(ngtcp2_conn *conn, uint64_t stream_id, uint8_t* buf, size_t buflen, ngtcp2_ssize *wdatalen, struct iovec *iov, int fin);

ssize_t prepare_nonstream_packet(ngtcp2_conn *conn, uint8_t *buf, size_t buflen);

int send_packet(int fd, uint8_t* pkt, size_t pktlen);

ssize_t read_message(int fd, uint8_t *buf, size_t buflen, struct sockaddr *remote_addr, size_t remote_addrlen);

int write_step(ngtcp2_conn *conn, int fd, int fin, const data_node *send_queue, size_t *stream_offset);

int send_nonstream_packets(ngtcp2_conn *conn, int fd, uint8_t *buf, size_t buflen, int limit);

int handle_timeout(ngtcp2_conn *conn, int fd);

int enqueue_message(const uint8_t *payload, size_t payloadlen, uint64_t stream_id, uint64_t offset, data_node *queue_tail);

#endif