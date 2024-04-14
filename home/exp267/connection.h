#ifndef CONNECTION_H
#define CONNECTION_H

#define SERVER_PORT "11111"
#define DEFAULT_IP "localhost"

#include <ngtcp2/ngtcp2.h>

#include <netdb.h>

typedef struct _inflight_data {
    uint8_t* payload;
    ssize_t payloadlen;

    uint64_t stream_id;

    // Total length of data sent before this one
    uint64_t offset;

    struct _inflight_data *next;
} inflight_data;

int prepare_packet(ngtcp2_conn *conn, uint64_t stream_id, uint8_t* buf, size_t buflen, size_t *pktlen, ngtcp2_ssize *wdatalen, struct iovec *iov, int fin);

int prepare_nonstream_packet(ngtcp2_conn *conn, uint8_t *buf, size_t buflen, size_t *pktlen);

int send_packet(int fd, uint8_t* pkt, size_t pktlen);

int read_message(int fd, uint8_t *buf, size_t buflen, struct sockaddr *remote_addr, size_t remote_addrlen, size_t *bytes_read);

int write_step(ngtcp2_conn *conn, int fd, uint64_t stream_id, int fin, const uint8_t *data, size_t datalen, inflight_data **inflight, uint64_t *sent_offset);

int send_nonstream_packets(ngtcp2_conn *conn, int fd, uint8_t *buf, size_t buflen, int limit);

int handle_timeout(ngtcp2_conn *conn, int fd);
#endif