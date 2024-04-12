#include <poll.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "utils.h"

typedef struct _waiting_pkt {
    uint8_t *data;
    size_t datalen;
    
    uint64_t send_time;

    struct _waiting_pkt *next;
} waiting_pkt;

void print_helpstring() {
    printf("-h: Prints help string\n");
    printf("-s [port]: Opens a server end listening on the specified port\n");
    printf("-c [port]: Opens a client end connected to the specified port\n");
    printf("-d [ms]: Sets the delay applied to packets in ms. Default 0\n");
}

waiting_pkt* make_node(uint8_t *data, size_t datalen, int delay, time_t start_time) {
    // Delay measured in ms
    waiting_pkt *node = malloc(sizeof(waiting_pkt));

    if (node == NULL) {
        fprintf(stderr, "Out of memory\n");
        return NULL;
    }

    node->data = data;
    node->datalen = datalen;
    node->next = NULL;

    // Time recieved
    node->send_time = difftime(time(NULL), start_time) * 1000 + delay;

    return node;
}

int main(int argc, char **argv) {
    char opt;
    int rv, tmp;

    time_t start_time = time(NULL);

    int time_since_start;

    // Ends are left side and right side. 
    char *left_port, *right_port;
    int left_port_set = 0, right_port_set = 0;
    int left_is_server, right_is_server;

    struct sockaddr_storage left_remote, right_remote;
    socklen_t left_remotelen = sizeof(left_remote), right_remotelen = sizeof(right_remote);
    int left_addr_set = 0, right_addr_set = 0;

    int left_fd, right_fd;

    uint8_t *buf;
    waiting_pkt *pkt_ptr;

    struct pollfd polls[2];
    int timeout;

    int delay_ms = 0;

    // Lists have dummy headers
    waiting_pkt left_waiting_pkts, right_waiting_pkts;
    waiting_pkt *left_waiting_pkts_tail = &left_waiting_pkts;
    waiting_pkt *right_waiting_pkts_tail = &right_waiting_pkts;

    left_waiting_pkts.next = right_waiting_pkts.next = NULL;

    while ((opt = getopt(argc, argv, "hs:c:d:")) != -1) {
        switch (opt) {
            case 'h':
                print_helpstring();
                return 0;
            case 's':
                if (left_port_set) {
                    right_port = optarg;
                    right_is_server = 1;
                    right_port_set = 1;
                } else {
                    left_port = optarg;
                    left_is_server = 1;
                    left_port_set = 1;
                }
                break;
            case 'c':
                if (left_port_set) {
                    right_port = optarg;
                    right_is_server = 0;
                    right_port_set = 1;
                } else {
                    left_port = optarg;
                    left_is_server = 0;
                    left_port_set = 1;
                }
                break;
            case 'd':
                delay_ms = atoi(optarg);
                break;
            case '?':
                printf("Unknown option -%c\n", optopt);
                break;
        }
    }

    // Configuration checks
    if (!(left_port_set && right_port_set)) {
        printf("Must set ports for both ends. eg. `-s 5 -c 6`\n");
        return -1;
    }

    if (!left_is_server && !right_is_server) {
        printf("Must specify at least one server end\n");
        return -1;
    }

    // Resolving sockets
    if (left_is_server) {
        rv = bind_udp_socket(&left_fd, left_port);
    } else {
        rv = connect_udp_socket(&left_fd, "localhost", left_port, (struct sockaddr*) &left_remote, &left_remotelen);
        left_addr_set = 1;
    }

    if (rv != 0) {
        fprintf(stderr, "Failed to process port %s\n", left_port);
        return rv;
    }


    if (right_is_server) {
        rv = bind_udp_socket(&right_fd, right_port);
    } else {
        rv = connect_udp_socket(&right_fd, "localhost", right_port, (struct sockaddr*) &right_remote, &right_remotelen);
        right_addr_set = 1;
    }

    if (rv != 0) {
        fprintf(stderr, "Failed to process port %s\n", right_port);
        return rv;
    }


    polls[0].fd = left_fd;
    polls[1].fd = right_fd;

    polls[0].events = polls[1].events = POLLIN;

    for (;;) {
        if (left_waiting_pkts.next == NULL && right_waiting_pkts.next == NULL) {
            // Both lists are empty
            timeout = -1;
        } else {
            // One list is non-empty
            time_since_start = difftime(time(NULL), start_time) * 1000;

            if (left_waiting_pkts.next == NULL) {
                // Left list is empty. Therefore right list is non-empty
                timeout = right_waiting_pkts.next->send_time - time_since_start;
            } else if (right_waiting_pkts.next == NULL) {
                // Right list is empty. Therefore left list is non-empty
                timeout = left_waiting_pkts.next->send_time - time_since_start;
            } else {
                // Both are non-empty
                timeout = left_waiting_pkts.next->send_time - time_since_start;
                tmp = right_waiting_pkts.next->send_time - time_since_start;
                if (tmp < timeout) {
                    // right timeout is before left timeout
                    timeout = tmp;
                }
            }
            if (timeout < 0) {
                // Safety check in case one of the timeouts elapsed while processing previous loop iteration
                // One of the timeouts has elapsed. Important not to provide negative timeout to poll in this case
                timeout = 0;
            }
        }

        // Wait on a message on either end
        rv = poll(polls, 2, timeout);

        if (rv == 0) {
            // Timeout reached before any sockets ready to read
            time_since_start = difftime(time(NULL), start_time) * 1000;

            // Process right packets
            for (pkt_ptr = right_waiting_pkts.next; pkt_ptr != NULL; pkt_ptr = right_waiting_pkts.next) {
                // Packets are arranged in ascending order. If this one is still waiting, we can break.
                if (pkt_ptr->send_time > time_since_start) break;

                // Send the packet data to it's intended dest. If remote address not yet set, drop the packet
                if (right_addr_set) {
                    sendto(right_fd, pkt_ptr->data, pkt_ptr->datalen, 0, (struct sockaddr*) &right_remote, right_remotelen);
                }

                // Pop the packet node off the head of the queue
                right_waiting_pkts.next = pkt_ptr->next;

                // Free memory allocated to the pointer
                free(pkt_ptr->data);
                free(pkt_ptr);
            }

            if (pkt_ptr == NULL) {
                // Emptied the list. Must update the tail pointer
                right_waiting_pkts_tail = &right_waiting_pkts;
            }

            // Exactly as above, but with the left queue
            for (pkt_ptr = left_waiting_pkts.next; pkt_ptr != NULL; pkt_ptr = left_waiting_pkts.next) {
                if (pkt_ptr->send_time > time_since_start) break;

                if (left_addr_set) {
                    sendto(left_fd, pkt_ptr->data, pkt_ptr->datalen, 0, (struct sockaddr*) &left_remote, left_remotelen);
                }

                left_waiting_pkts.next = pkt_ptr->next;

                free(pkt_ptr->data);
                free(pkt_ptr); 
            }

            if (pkt_ptr == NULL) {
                left_waiting_pkts_tail = &left_waiting_pkts;
            }

            // All pending packets have been processed. Return to the poll call
        } else {
            // Poll continued due to recieved message
            buf = malloc(MAX_UDP_PAYLOAD);

            if (buf == NULL) {
                fprintf(stderr, "Out of memory\n");
                return -1;
            }

            if (polls[0].revents & POLLIN) {
                // Recieved message to the left side

                if (!left_addr_set) {
                    rv = recvfrom(left_fd, buf, MAX_UDP_PAYLOAD, 0, (struct sockaddr*) &left_remote, &left_remotelen);
                    left_addr_set = 1;
                } else {
                    rv = recv(left_fd, buf, MAX_UDP_PAYLOAD, 0);
                }

                if (rv == -1) {
                    fprintf(stderr, "Error when left receiving message: %s\n", strerror(errno));
                    return -1;
                }

                pkt_ptr = make_node(buf, rv, delay_ms, start_time);

                if (pkt_ptr == NULL) {
                    // Out of memory
                    return -1;
                }

                // Add the message to the queue waiting to be sent from the right side
                right_waiting_pkts_tail->next = pkt_ptr;
                right_waiting_pkts_tail = pkt_ptr;
            } else if (polls[1].revents & POLLIN) {
                // Recieved a message to the right side
                if (!right_addr_set) {
                    rv = recvfrom(right_fd, buf, MAX_UDP_PAYLOAD, 0, (struct sockaddr*) &right_remote, &right_remotelen);
                    right_addr_set = 1;
                } else {
                    rv = recv(right_fd, buf, MAX_UDP_PAYLOAD, 0);
                }

                if (rv == -1) {
                    fprintf(stderr, "Error when right receiving message: %s\n", strerror(errno));
                    return -1;
                }

                pkt_ptr = make_node(buf, rv, delay_ms, start_time);

                if (pkt_ptr == NULL) {
                    return -1;
                }

                // Add to the queue waiting to be sent from the left side
                left_waiting_pkts_tail->next = pkt_ptr;
                left_waiting_pkts_tail = pkt_ptr;
            }
        }
    }
}