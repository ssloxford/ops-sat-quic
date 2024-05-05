#include <poll.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

#include "utils.h"

typedef struct _waiting_data {
    uint8_t *data;
    size_t datalen;
    
    uint64_t send_time;

    struct _waiting_data *next;
} waiting_data;

void print_helpstring() {
    printf("-h: Prints help string\n");
    printf("-s [port]: Opens a server end listening on the specified port\n");
    printf("-c [port]: Opens a client end connected to the specified port\n");
    printf("-d [ms]: Sets the delay applied to data in ms. Default 0\n");
    printf("-r [range]: Sets the range of delay times. Per section delay is in the range d+-r. Default 0\n");
    printf("-l [chance]: Sets the data section loss chance. Default 0\n");
    printf("-k [bytes]: Proportion of chunks corrupted (eg. 100 means 1 percent of chunks are corrupted). Default 0 (ie. no corruption)\n");
}

waiting_data* make_node(const uint8_t *data, size_t datalen, int delay) {
    // Delay measured in ms
    waiting_data *node = malloc(sizeof(waiting_data));

    if (node == NULL) {
        fprintf(stderr, "Out of memory\n");
        return NULL;
    }

    uint8_t *node_data = malloc(datalen);

    if (node_data == NULL) {
        free(node);
        fprintf(stderr, "Out of memory\n");
        return NULL;
    }

    memcpy(node_data, data, datalen);

    node->data = node_data;
    node->datalen = datalen;
    node->next = NULL;

    // Time recieved
    node->send_time = timestamp() + (1000000ull * delay);

    return node;
}

void enqueue_node(waiting_data *queue, waiting_data *node) {
    waiting_data *prev_ptr = queue;

    for (waiting_data *ptr = prev_ptr->next;; ptr = prev_ptr->next) {
        if (ptr == NULL) {
            // We're at the tail. Put the node here
            node->next = ptr;
            prev_ptr->next = node;
            break;
        }

        if (ptr->send_time < node->send_time) {
            // The enqueue node goes later than this one. Keep going
            prev_ptr = ptr;
        } else {
            // We want to insert this node here
            node->next = ptr;
            prev_ptr->next = node;
            break;
        }
    }
}

int main(int argc, char **argv) {
    signed char opt;
    int rv;

    unsigned int rand_uint;
    uint8_t rand_byte;

    int left_is_server, right_is_server;
    int left_fd, right_fd;

    char *left_port, *right_port;
    int left_port_set = 0, right_port_set = 0;

    uint8_t *buf;
    waiting_data *pkt_ptr;

    struct pollfd polls[2];
    int left_timeout, right_timeout, timeout;

    int delay_mean = 0, delay_range = 0;
    double loss_chance = 0;
    double corruption_chance = 0;

    unsigned int corruption_cutoff, loss_cutoff;
    
    int discard_packet, delay;

    rand_init();

    // Lists have dummy headers
    waiting_data left_waiting_datas, right_waiting_datas;

    left_waiting_datas.next = right_waiting_datas.next = NULL;

    while ((opt = getopt(argc, argv, "hs:c:d:l:k:r:")) != -1) {
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
                delay_mean = atoi(optarg);
                break;
            case 'l':
                loss_chance = atof(optarg);
                break;
            case 'k':
                corruption_chance = 1.0/atoi(optarg);
                break;
            case 'r':
                delay_range = atoi(optarg);
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

    if (delay_mean < 0) {
        printf("Delay cannot be negative. Setting to 0\n");
        delay_mean = 0;
    }

    if (delay_range < 0) {
        delay_range = -delay_range;
    }

    if (loss_chance < 0) {
        printf("Loss chance cannot be negative. Setting to 0\n");
        loss_chance = 0;
    } else if (loss_chance > 1) {
        printf("Loss chance cannot be greater than 1. Setting to 1\n");
        loss_chance = 1;
    }

    if (corruption_chance < 0) {
        printf("Corruption chance cannot be negative. Setting to 0\n");
        corruption_chance = 0;
    }

    loss_cutoff = UINT_MAX * loss_chance;
    corruption_cutoff = UINT_MAX * corruption_chance;

    // Resolving sockets
    if (left_is_server) {
        rv = bind_and_accept_tcp_socket(&left_fd, left_port, NULL, NULL);
    } else {
        rv = connect_tcp_socket(&left_fd, "127.0.0.1", left_port, NULL, NULL);
    }

    if (rv < 0) {
        fprintf(stderr, "Failed to process port %s\n", left_port);
        return rv;
    }


    if (right_is_server) {
        rv = bind_and_accept_tcp_socket(&right_fd, right_port, NULL, NULL);
    } else {
        rv = connect_tcp_socket(&right_fd, "127.0.0.1", right_port, NULL, NULL);
    }

    if (rv < 0) {
        fprintf(stderr, "Failed to process port %s\n", right_port);
        return rv;
    }


    polls[0].fd = left_fd;
    polls[1].fd = right_fd;

    polls[0].events = polls[1].events = POLLIN;

    for (;;) {
        // Calculate the timeout for the packets waiting to be sent left
        if (left_waiting_datas.next == NULL) {
            left_timeout = -1;
        } else {
            left_timeout = (left_waiting_datas.next->send_time - timestamp()) / 1000000ull;
            if (left_timeout < 0) left_timeout = 0;
        }

        // Calculate the timeouts for the packets waiting to be sent right
        if (right_waiting_datas.next == NULL) {
            right_timeout = -1;
        } else {
            right_timeout = (right_waiting_datas.next->send_time - timestamp()) / 1000000ull;
            if (right_timeout < 0) right_timeout = 0;
        }

        // Let timeout be the minimum of those above (where they're set)
        if (left_timeout == -1) {
            // No timeout on left. Use the right timeout
            timeout = right_timeout;
        } else {
            // There's a timeout on the left
            timeout = left_timeout;

            // If there's a right timeout and it's before the left timeout, take the min
            if (right_timeout != -1 && right_timeout < left_timeout) {
                timeout = right_timeout;
            }
        }

        // Wait on a message on either end
        rv = poll(polls, 2, timeout);

        if (rv == 0) {
            // Poll continued due to timeout
            // Process right packets
            for (pkt_ptr = right_waiting_datas.next; pkt_ptr != NULL; pkt_ptr = right_waiting_datas.next) {
                // Packets are arranged in ascending order. If this one is still waiting, we can break.
                if (pkt_ptr->send_time > timestamp()) break;

                rv = send(right_fd, pkt_ptr->data, pkt_ptr->datalen, 0);

                if (rv < 0) {
                    return rv;
                }

                // Pop the packet node off the head of the queue
                right_waiting_datas.next = pkt_ptr->next;

                // Free memory allocated to the pointer
                free(pkt_ptr->data);
                free(pkt_ptr);
            }

            // Exactly as above, but with the left queue
            for (pkt_ptr = left_waiting_datas.next; pkt_ptr != NULL; pkt_ptr = left_waiting_datas.next) {
                if (pkt_ptr->send_time > timestamp()) break;
                
                rv = send(left_fd, pkt_ptr->data, pkt_ptr->datalen, 0);
                
                if (rv < 0) {
                    return rv;
                }

                left_waiting_datas.next = pkt_ptr->next;

                free(pkt_ptr->data);
                free(pkt_ptr); 
            }

            // All pending packets have been processed. Return to the poll call
        } else {
            // We must have recieved a chunk
            // RNG to determine if we need to drop this chunk
            rand_uint = rand();

            if (rand_uint < loss_cutoff) {
                printf("Dropping chunk\n");
                discard_packet = 1;
            } else {
                discard_packet = 0;
            }

            // Even if dropping the packet, we need the buffer to read into to take it out of the socket buffer
            buf = malloc(MAX_UDP_PAYLOAD);

            if (buf == NULL) {
                fprintf(stderr, "Out of memory\n");
                return -1;
            }

            if (polls[0].revents & POLLIN) {
                // Recieved message to the left side

                rv = recv(left_fd, buf, MAX_UDP_PAYLOAD, 0);

                if (rv == -1) {
                    fprintf(stderr, "Error when left receiving message: %s\n", strerror(errno));
                    return -1;
                }

                if (rv == 0) {
                    printf("Remote closed connection\n");
                    return 0;
                }

                // If dropping this packet, free the buffer it's been read into and return to the top of the loop
                if (discard_packet) {
                    free(buf);
                    continue;
                }

                rand_uint = rand();

                if (rand_uint < corruption_cutoff) {
                    printf("Corrupting right bound chunk of length %d\n", rv);
                    for (int offset = 0; offset < rv; offset += 0x0f & rand_byte) {
                        rand_bytes(&rand_byte, 1);
                        // Corrupt this byte
                        buf[offset] ^= rand_byte;
                    }
                }

                delay = delay_mean + (rand() % 2*delay_range) - delay_range;

                pkt_ptr = make_node(buf, rv, delay);

                if (pkt_ptr == NULL) {
                    // Out of memory
                    return -1;
                }

                enqueue_node(&right_waiting_datas, pkt_ptr);
            } else if (polls[1].revents & POLLIN) {
                // Recieved a message to the right side
                
                rv = recv(right_fd, buf, MAX_UDP_PAYLOAD, 0);

                if (rv == -1) {
                    fprintf(stderr, "Error when right receiving message: %s\n", strerror(errno));
                    return -1;
                }

                if (rv == 0) {
                    printf("Remote closed connection\n");
                    return 0;
                }

                if (discard_packet) {
                    free(buf);
                    continue;
                }

                rand_uint = rand();

                if (rand_uint < corruption_cutoff) {
                    printf("Corrupting left bound chunk of length %d\n", rv);
                    for (int offset = 0; offset < rv; offset += 0x0f & rand_byte) {
                        rand_bytes(&rand_byte, 1);
                        // Corrupt this byte
                        buf[offset] ^= rand_byte;
                    }
                }

                delay = delay_mean + (rand() % 2*delay_range) - delay_range;

                pkt_ptr = make_node(buf, rv, delay);

                if (pkt_ptr == NULL) {
                    return -1;
                }

                enqueue_node(&left_waiting_datas, pkt_ptr);
            }
        }
    }
}