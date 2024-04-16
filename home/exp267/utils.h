#ifndef INCLUDE_H
#define INCLUDE_H

#include <ngtcp2/ngtcp2.h>

#include <netdb.h>

#define BUF_SIZE 32*1024 // 32kb buffer
#define MAX_UDP_PAYLOAD NGTCP2_MAX_UDP_PAYLOAD_SIZE

void rand_init();

int rand_bytes(uint8_t* dest, size_t destlen);

void rand_cb(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx* rand_ctx);

int get_new_connection_id_cb(ngtcp2_conn* conn, ngtcp2_cid* cid, uint8_t* token, size_t cidlen, void* user_data);

uint64_t timestamp(void);

uint64_t timestamp_ms(void);

void debug_log(void *user_data, const char *format, ...);

int resolve_and_process(int *save_fd, const char *target_host, const char *target_port, struct addrinfo *hints, int is_server, struct sockaddr *localsock, socklen_t *localsocklen, struct sockaddr *remotesock, socklen_t *remotesocklen);

int bind_udp_socket(int *fd, char *server_port);

int connect_udp_socket(int *fd, char *server_ip, char *server_port, struct sockaddr *remoteaddr, socklen_t *remoteaddrlen);

#endif