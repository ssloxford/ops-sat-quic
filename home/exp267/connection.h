#define SERVER_PORT "11111"
#define LOCAL_HOST "127.0.0.1"
#define DEFAULT_IP LOCAL_HOST
#define BUF_SIZE 32*1024 // 32kb buffer

int prepare_packet(ngtcp2_conn *conn, uint64_t stream_id, uint8_t* buf, size_t buflen, size_t *pktlen, struct iovec *iov);

int send_packet(int fd, uint8_t* pkt, size_t pktlen);

int await_message(int fd, struct iovec *iov, struct sockaddr *remote_addr, size_t remote_addrlen);