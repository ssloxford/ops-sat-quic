#define SERVER_PORT "11111"
#define DEFAULT_IP "localhost"

#include <ngtcp2/ngtcp2.h>

#include <netdb.h>

int prepare_packet(ngtcp2_conn *conn, uint64_t stream_id, uint8_t* buf, size_t buflen, size_t *pktlen, struct iovec *iov);

int prepare_nonstream_packet(ngtcp2_conn *conn, uint8_t *buf, size_t buflen, size_t *pktlen);

int send_packet(int fd, uint8_t* pkt, size_t pktlen);

int read_message(int fd, uint8_t *buf, size_t buflen, struct sockaddr *remote_addr, size_t remote_addrlen, size_t *bytes_read);

int write_step(ngtcp2_conn *conn, int fd, uint64_t stream_id, uint8_t *data, size_t datalen);