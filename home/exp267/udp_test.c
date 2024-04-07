#include <sys/socket.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "utils.h"

static int connect_udp_socket(int *fd, char *target_port, struct sockaddr *remoteaddr, socklen_t *remoteaddrlen) {
    struct addrinfo hints;

    struct sockaddr_storage addrstorage;
    socklen_t socklen;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    // Opens UDP socket and connects to localhost:target_port, saving the sockaddr to remoteaddr
    return resolve_and_process(fd, "localhost", target_port, &hints, 0, (struct sockaddr*) &addrstorage, &socklen, remoteaddr, remoteaddrlen);
}

int main(int argc, char** argv) {
    int fd, rv;

    char buf[300];

    struct sockaddr remoteaddr;
    socklen_t remoteaddrlen;

    // Accept target port in cmd and connect to it
    rv = connect_udp_socket(&fd, argv[1], &remoteaddr, &remoteaddrlen);

    if (rv != 0) {
        return rv;
    }

    while (1) {
        rv = read(STDIN_FILENO, buf, 300);

        if (rv > 2) {
            printf("Sending data\n");
            
            buf[rv] = 0; // Null terminate
            rv++;
            send(fd, buf, rv, 0);
        }

        rv = recv(fd, buf, 300, MSG_DONTWAIT);

        if (rv == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
            continue;
        }

        printf("%s\n", buf);
    }
}