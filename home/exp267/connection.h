#define SERVER_PORT "11111"
#define DEFAULT_IP "localhost"
#define BUF_SIZE 32*1024 // 32kb buffer

int prepare_packet(ngtcp2_conn *conn, uint64_t stream_id, uint8_t* buf, size_t buflen, size_t *pktlen, struct iovec *iov);

int prepare_nonstream_packet(ngtcp2_conn *conn, uint8_t *buf, size_t buflen, size_t *pktlen);

int send_packet(int fd, uint8_t* pkt, size_t pktlen);

int read_message(int fd, uint8_t *buf, size_t buflen, struct sockaddr *remote_addr, size_t remote_addrlen, size_t *bytes_read);

int resolve_and_process(int *save_fd, const char *target_host, const char *target_port, struct addrinfo *hints, int is_server, ngtcp2_sockaddr *localsock, ngtcp2_socklen *localsocklen, ngtcp2_sockaddr *remotesock, ngtcp2_socklen *remotesocklen);

int write_step(ngtcp2_conn *conn, int fd, uint64_t stream_id, uint8_t *data, size_t datalen);