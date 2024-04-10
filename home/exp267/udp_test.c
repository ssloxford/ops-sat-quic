#include <sys/socket.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>

#include "utils.h"

#define MSG_LEN 1024

static int connect_udp_socket(int *fd, char *target_port, struct sockaddr *remoteaddr, socklen_t *remoteaddrlen) {
    struct addrinfo hints;

    struct sockaddr_storage addrstorage;
    socklen_t socklen;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET;
    hints.ai_protocol = IPPROTO_UDP;

    // Opens UDP socket and connects to localhost:target_port, saving the sockaddr to remoteaddr
    return resolve_and_process(fd, "localhost", target_port, &hints, 0, (struct sockaddr*) &addrstorage, &socklen, remoteaddr, remoteaddrlen);
}

int main(int argc, char** argv) {
    int fd, rv;
    struct pollfd polls[2];

    char buf[MSG_LEN];

    struct sockaddr remoteaddr;
    socklen_t remoteaddrlen;

    // Accept target port in cmd and connect to it
    rv = connect_udp_socket(&fd, argv[1], &remoteaddr, &remoteaddrlen);

    if (rv != 0) {
        return rv;
    }

    polls[0].fd = fd;
    polls[1].fd = STDIN_FILENO;

    polls[0].events = polls[1].events = POLLIN;

    while (1) {
        poll(polls, 2, -1);

        if (polls[0].revents & POLLIN) {
            rv = recv(fd, buf, sizeof(buf), 0);

            if (rv == -1) {
                fprintf(stderr, "Failed to read from UDP socket: %s\n", strerror(errno));
            }

            printf("%s\n", buf);
        } else if (polls[1].revents & POLLIN) {
            rv = read(STDIN_FILENO, buf, sizeof(buf));

            buf[rv-1] = 0; // Replace new line with null terminate

            if (rv == -1) {
                fprintf(stderr, "Failed to read from STDIN: %s\n", strerror(errno));
            }

            sendto(fd, buf, rv, 0, &remoteaddr, remoteaddrlen);
        }
    }
}