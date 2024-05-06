#ifndef UTILS_H
#define UTILS_H

#include <ngtcp2/ngtcp2.h>

#include <netdb.h>

#define BUF_SIZE 2*1024 // 2kb buffer
#define MAX_UDP_PAYLOAD NGTCP2_MAX_UDP_PAYLOAD_SIZE

void rand_init();

int rand_bytes(uint8_t* dest, size_t destlen);

uint64_t timestamp(void);

uint64_t timestamp_ms(void);

void debug_log(void *user_data, const char *format, ...);

int resolve_and_process(in_addr_t target_host, int target_port, int protocol, int is_server, struct sockaddr *localsock, socklen_t *localsocklen, struct sockaddr *remotesock, socklen_t *remotesocklen);

int bind_udp_socket(int *fd, const char *server_port);

int connect_udp_socket(int *fd, const char *server_ip, const char *server_port, struct sockaddr *remoteaddr, socklen_t *remoteaddrlen);

int connect_tcp_socket(int *fd, char *target_ip, char *target_port, struct sockaddr *remoteaddr, socklen_t *remoteaddrlen);

int bind_tcp_socket(int *fd, char *server_port);

int accept_tcp_connection(int *fd, int listen_fd, struct sockaddr *remoteaddr, socklen_t *remoteaddrlen);

void print_cid(const ngtcp2_cid *cid);

#endif