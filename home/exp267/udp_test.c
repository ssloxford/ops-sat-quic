#include <sys/socket.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>

#include "utils.h"

static int bind_udp_socket(int *fd, char *target_port, struct sockaddr *remoteaddr, socklen_t *remoteaddrlen) {
    struct addrinfo hints;

    struct sockaddr_storage addrstorage;
    socklen_t socklen;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    // Opens UDP socket and connects to localhost:target_port, saving the sockaddr to remoteaddr
    return resolve_and_process(fd, "localhost", target_port, &hints, 1, (struct sockaddr*) &addrstorage, &socklen, remoteaddr, remoteaddrlen);
}


int main(int argc, char** argv) {
    int fd, rv;

    char buf[300];

    struct sockaddr remoteaddr;
    socklen_t remoteaddrlen;

    bind_udp_socket(&fd, argv[1], &remoteaddr, &remoteaddrlen);

    while (1) {
        rv = read(STDIN_FILENO, buf, 300);
        buf[rv] = 0; // Null terminate
        rv++;

        if (rv > 1) {
            send(fd, buf, rv, 0);
        }

        recv(fd, buf, 300, 0);
        printf("%s\n", buf);
    }
}