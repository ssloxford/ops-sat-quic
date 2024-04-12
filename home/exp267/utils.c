#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

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

// Seeds the RNG
void rand_init() {
    srand(time(NULL));
}

int rand_bytes(uint8_t* dest, size_t destlen) {
    for (size_t i = 0; i < destlen; i++) {
        dest[i] = rand(); // Will truncate down to a single byte
    }

    return 0;
}

// Callback not used for cryptoRNG so safe to delegate to stdlib rand()
void rand_cb(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx* rand_ctx) {
    rand_bytes(dest, destlen);
}

int get_new_connection_id_cb(ngtcp2_conn* conn, ngtcp2_cid* cid, uint8_t* token, size_t cidlen, void* user_data){
    // TODO - Consider implementing lookup and rehash. https://nghttp2.org/ngtcp2/ngtcp2_conn_get_scid.html
    int rv;

    // fprintf(stdout, "Starting call to get_new_connection_id_cb\n");

    rand_bytes(cid->data, cidlen);

    cid->datalen = cidlen;

    rand_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);

    return 0;
}

void debug_log(void *user_data, const char *format, ...) {
    va_list args;
    va_start(args, format);

    vfprintf(stdout, format, args);
    va_end(args);
    fprintf(stdout, "\n");
}

// Function code taken mostly from spaceQUIC
int resolve_and_process(int *save_fd, const char *target_host, const char* target_port, struct addrinfo *hints, int is_server, struct sockaddr *localsock, socklen_t *localsocklen, struct sockaddr *remotesock, socklen_t *remotesocklen) {
    struct addrinfo *result, *rp;
    int rv, fd;

    rv = getaddrinfo(target_host, target_port, hints, &result);
    if (rv != 0) {
        fprintf(stderr, "Failed to get address info for requested endpoint: %s\n", gai_strerror(rv));
        return ERROR_HOST_LOOKUP;
    }

    // Result is the head of a linked list, with nodes of type addrinfo
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        // Attempt to open a file descriptor for current address info in results
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1)
            // If can't open a socket for it, move on
            continue;

        // Attempt to connect the created file descriptor to the address we've looked up
        // && short circuits and connect is not evaluated if is_server
        if (!is_server && connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            // Assign the path's remote addrlen. Must copy the value into the remote.addr pointer since rp will be deallocated
            *remotesocklen = rp->ai_addrlen;
            memcpy(remotesock, rp->ai_addr, rp->ai_addrlen);

            if (localsock != NULL) {
                // Set the local path of the client
                if (getsockname(fd, localsock, localsocklen) == -1)
                    return ERROR_GET_SOCKNAME;
            }

            // Exit the loop when the first successful connection is made
            break;
        } else if (is_server && bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            if (localsock != NULL) {
                *localsocklen = rp->ai_addrlen;
                memcpy(localsock, rp->ai_addr, rp->ai_addrlen);
            }

            break;
        }

        // If the connection was not made, close the fd and keep looking
        close(fd);
    }

    // Must manually deallocate the results from the lookup
    freeaddrinfo(result);

    // If the loop finished by getting to the end, rather than with a successful connection, return -1
    if (rp == NULL) {
        fprintf(stderr, "Could not proccess any resolved addresses\n");
        return ERROR_COULD_NOT_OPEN_CONNECTION_FD;
    }

    // Save the fd of the open socket connected to the endpoint
    *save_fd = fd;
    return 0;
}

int bind_udp_socket(int *fd, char *server_port) {
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET; // IPv4 addresses
    hints.ai_protocol = IPPROTO_UDP; // UDP sockets only
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV; // Port is provided as a number rather than string eg. "ssh"

    return resolve_and_process(fd, INADDR_ANY, server_port, &hints, 1, NULL, NULL, NULL, NULL);
}

int connect_udp_socket(int *fd, char *server_ip, char *server_port, struct sockaddr *remoteaddr, socklen_t *remoteaddrlen) {
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_NUMERICSERV;

    // Opens UDP socket and saves the remote address into remoteaddr
    return resolve_and_process(fd, server_ip, server_port, &hints, 0, NULL, NULL, remoteaddr, remoteaddrlen);
}
