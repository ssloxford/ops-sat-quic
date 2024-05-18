#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "utils.h"
#include "errors.h"

// Code taken from ngtcp2/examples/simpleclient.c
uint64_t timestamp(void) {
  struct timespec tp;

  if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
    fprintf(stderr, "clock_gettime: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

uint64_t timestamp_ms() {
    return (timestamp() / NGTCP2_MILLISECONDS);
}

// Seeds the RNG
void rand_init() {
    srand(timestamp());
}

int rand_bytes(uint8_t* dest, size_t destlen) {
    unsigned int bytes_this_loop;
    int rand_num;

    for (size_t i = 0; i < destlen; i += bytes_this_loop) {
        // Bytes left to randomise in the array
        bytes_this_loop = destlen - i;

        rand_num = rand();

        if (bytes_this_loop > sizeof(rand_num)) {
            bytes_this_loop = sizeof(rand_num);
        }

        // Write the full int from the next byte to randomise
        memcpy(&dest[i], &rand_num, bytes_this_loop); 
    }

    return 0;
}

uint8_t get_rand_byte() {
    uint8_t val;

    rand_bytes(&val, sizeof(val));

    return val;
}

uint64_t get_rand_u64() {
    uint64_t val;

    rand_bytes((uint8_t*) &val, sizeof(val));

    return val;
}

void debug_log(void *user_data, const char *format, ...) {
    va_list args;
    va_start(args, format);

    vfprintf(stdout, format, args);
    va_end(args);
    fprintf(stdout, "\n");
}

int resolve_and_process(in_addr_t target_host, int target_port, int protocol, int is_server, struct sockaddr *localsock, socklen_t *localsocklen, struct sockaddr *remotesock, socklen_t *remotesocklen) {
    int rv, fd;

    int sock_type;

    struct sockaddr_in sockaddrin;
    socklen_t sockaddrinlen = sizeof(sockaddrin);
    memset(&sockaddrin, 0, sockaddrinlen);

    switch (protocol) {
        case IPPROTO_TCP:
            sock_type = SOCK_STREAM;
            break;
        case IPPROTO_UDP:
            sock_type = SOCK_DGRAM;
            break;
        default:
            // Protocol provided was meant to be one of TCP or UDP
            return -1;
            // TODO - Macro this error code
    }

    // Build the sockaddrin struct to be passed to bind/connect
    sockaddrin.sin_family = AF_INET;
    // Argument to integer. Then host to network
    sockaddrin.sin_port = htons(target_port);
    // target_host must be in network order, not host order. Call htonl if needed
    sockaddrin.sin_addr.s_addr = target_host;

    fd = socket(AF_INET, sock_type, protocol);

    if (fd == -1) {
        // TODO - Macro this error code
        return -1;
    }

    if (is_server) {
        // Attempt to bind the socket to provided IP and port
        rv = bind(fd, (struct sockaddr*) &sockaddrin, sockaddrinlen);

        if (rv == -1) {
            fprintf(stderr, "Failed to bind socket to address: %s\n", strerror(errno));
            return -1;
        }

        // Update the provided socket pointer with the bound socket 
        if (localsock != NULL) {
            *localsocklen = sockaddrinlen;
            memcpy(localsock, &sockaddrin, sockaddrinlen);
        }
    } else {
        rv = connect(fd, (struct sockaddr*) &sockaddrin, sockaddrinlen);

        if (rv == -1) {
            fprintf(stderr, "Failed to connect socket to address: %s\n", strerror(errno));
            return -1;
        }

        if (remotesock != NULL) {
            *remotesocklen = sockaddrinlen;
            memcpy(remotesock, &sockaddrin, sockaddrinlen);
        }

        if (localsock != NULL) {
            // Requires *localsocklen to be accurate to the length of localsock before the call
            rv = getsockname(fd, localsock, localsocklen);

            if (rv == -1) {
                fprintf(stderr, "Failed to get local address of connected fd: %s\n", strerror(errno));
            }
        }
    }

    return fd;
}

int bind_udp_socket(int *fd, const char *server_port) {
    int rv;

    rv = resolve_and_process(htonl(INADDR_ANY), atoi(server_port), IPPROTO_UDP, 1, NULL, NULL, NULL, NULL);

    if (rv  < 0) {
        return rv;
    }

    *fd = rv;
    return 0;
}

int connect_udp_socket(int *fd, const char *server_ip, const char *server_port, struct sockaddr *remoteaddr, socklen_t *remoteaddrlen) {
    int rv;

    struct in_addr inaddr;

    rv = inet_aton(server_ip, &inaddr);

    // 0 for error is correct. https://linux.die.net/man/3/inet_aton
    if (rv == 0) {
        // Address provided is invalid
        return -1;
    }

    // Resolves target host and port, opens connection to it,
    // and updates variables fd, and local and remote sockaddr and socklen in client
    rv = resolve_and_process(inaddr.s_addr, atoi(server_port), IPPROTO_UDP, 0, NULL, NULL, remoteaddr, remoteaddrlen);

    if (rv < 0) {
        return rv;
    }

    *fd = rv;

    return 0;
}


int connect_tcp_socket(int *fd, char *target_ip, char *target_port, struct sockaddr *remoteaddr, socklen_t *remoteaddrlen) {
    int rv;

    struct in_addr inaddr;

    rv = inet_aton(target_ip, &inaddr);

    // 0 for error is correct. https://linux.die.net/man/3/inet_aton
    if (rv == 0) {
        // Address provided is invalid
        return -1;
    }

    // Opens TCP socket and connects to localhost:target_port, saving the sockaddr to remoteaddr
    rv = resolve_and_process(inaddr.s_addr, atoi(target_port), IPPROTO_TCP, 0, NULL, NULL, remoteaddr, remoteaddrlen);

    if (rv < 0) {
        return rv;
    }

    *fd = rv;
    return 0;
}

int bind_tcp_socket(int *fd, char *server_port) {
    int rv;

    rv = resolve_and_process(htonl(INADDR_ANY), atoi(server_port), IPPROTO_TCP, 1, NULL, NULL, NULL, NULL);

    if (rv < 0) {
        return rv;
    }

    *fd = rv;

    // Marks the TCP socket as accepting connections. Connection queue of length 1
    rv = listen(*fd, 1);

    if (rv < 0) {
        fprintf(stderr, "SPP bridge: listen: %s\n", strerror(errno));
        return rv;
    }

    return 0;
}

int accept_tcp_connection(int *fd, int listen_fd, struct sockaddr *remoteaddr, socklen_t *remoteaddrlen) {
    int rv;

    // Blocking call if none pending in the connection queue. Returns a new fd on success
    rv = accept(listen_fd, remoteaddr, remoteaddrlen);

    if (rv == -1) {
        fprintf(stderr, "SPP bridge: accept: %s\n", strerror(errno));
        return rv;
    }

    // rv is the fd of the port connected to remote
    *fd = rv;
    return 0;
}


void print_cid(const ngtcp2_cid *cid) {
    printf("0x");
    for (size_t i = 0; i < cid->datalen; i++) {
        printf("%02x", cid->data[i]);
    }
}