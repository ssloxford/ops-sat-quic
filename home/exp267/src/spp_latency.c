#include <poll.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <getopt.h>
#include <math.h>

#include "utils.h"
#include "spp.h"

typedef struct _waiting_data {
    uint8_t *data;
    size_t datalen;
    
    uint64_t send_time;

    struct _waiting_data *next;
} waiting_data;

static double get_rand_gaussian(double mean, double sd) {
    // Calculate a gaussian using the Box-Muller transform
    // Two uniform variables in the range [0, 1]
    double x = (double)get_rand_u64()/(double)(UINT64_MAX);
    double y = (double)get_rand_u64()/(double)(UINT64_MAX);

    // Calculate a standardised Gaussian, and transform
    return sd * sqrt(-2.0*log(x)) * cos(2.0*M_PI*y) + mean;
}

void print_helpstring() {
    printf("--help, -h: Prints help string\n");
    printf("--server, -s [port]: Opens a server end listening on the specified port\n");
    printf("--client, -c [port]: Opens a client end connected to the specified port\n");
    printf("--delay, -d [ms]: Sets the delay applied to data in ms. Default 0\n");
    printf("--delay-sd [std. dev.]: Sets the standard deviation for the delay. Default 0\n");
    printf("--dc [ms]: Sets the mean time between disconnections. Default 0 (no disconnections)\n");
    printf("--dc-sd [ms]: Sets the standard deviation for the disconnection time. Default 0\n");
    printf("--rc [ms]: Sets the mean time before reconnecting. Default 0 (immediate reconnection)\n");
    printf("--rc-sd [ms]: Sets the standard deviation for the reconnection time. Default 0\n");
    printf("--loss, -l [chance]: Sets the SPP loss chance. Default 0\n");
    printf("--ber, -e [chance]: Sets the bit error rate. Default 0. Allows exponential notation eg. 1e-9\n");
    printf("-v: Enables debugging. Can be used multiple times to be more verbose\n");
}

waiting_data* make_node(const uint8_t *data, size_t datalen, int delay) {
    // Delay measured in ms
    waiting_data *node = malloc(sizeof(waiting_data));

    if (node == NULL) {
        fprintf(stderr, "Out of memory\n");
        return NULL;
    }

    uint8_t *node_data = malloc(SPP_MTU);

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
    node->send_time = timestamp_ms() + delay;

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

    uint64_t rand_uint;
    uint8_t rand_byte;

    int left_is_server, right_is_server;
    int left_fd, right_fd, left_listen_fd, right_listen_fd;

    char *left_port, *right_port;
    int left_port_set = 0, right_port_set = 0;

    int debug = 0;

    uint8_t buf[BUF_SIZE];
    uint8_t bit_error_mask[SPP_MTU];
    waiting_data *pkt_ptr;

    struct pollfd polls[2];
    int left_timeout, right_timeout, timeout;
    uint64_t ts;

    int delay_mean = 0, delay_sd = 0;
    int discon_mean = 0, discon_sd = 0;
    int recon_mean = 0, recon_sd = 0;
    double loss_chance = 0.0, bit_error_rate = 0.0;

    // UINT64_MAX indicates the ts for the disconnection is not set
    uint64_t disconnection_timeout = UINT64_MAX;

    uint64_t loss_cutoff, bit_error_cutoff;
    
    int discard_packet, delay, disconnected = 0;

    rand_init();

    // Lists have dummy headers
    waiting_data left_waiting_datas, right_waiting_datas;

    left_waiting_datas.next = right_waiting_datas.next = NULL;

    // getopt_long needs to be able which longopt we've got
    int longindex;

    struct option long_opts[] = {
        {"help", no_argument, NULL, 'h'},
        {"client", required_argument, NULL, 'c'},
        {"server", required_argument, NULL, 's'},
        {"delay", required_argument, NULL, 'd'},
        {"delay-sd", required_argument, NULL, 0},
        {"dc", required_argument, NULL, 0},
        {"dc-sd", required_argument, NULL, 0},
        {"rc", required_argument, NULL, 0},
        {"rc-sd", required_argument, NULL, 0},
        {"loss", required_argument, NULL, 'l'},
        {"ber", required_argument, NULL, 'e'},
        {"debug", no_argument, NULL, 'v'},
        {NULL, 0, NULL, 0} // Docs says that the last index must be all zeros
    };

    // TOOD - Implement intermittent disconnections distributed Gaussian
    while ((opt = getopt_long(argc, argv, "hs:c:d:l:e:v", long_opts, &longindex)) != -1) {
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
            case 'e':
                bit_error_rate = atof(optarg);
                break;
            case 'v':
                debug += 1;
                break;
            case 0:
                // We've got a long-opt. All other long-opts are redirected to equivalent short options
                switch (longindex) {
                    case 4:
                        // --delay-sd
                        delay_sd = atoi(optarg);
                        break;
                    case 5:
                        // --dc
                        discon_mean = atoi(optarg);
                        break;
                    case 6:
                        // --dc-sd
                        discon_sd = atoi(optarg);
                        break;
                    case 7:
                        // --rc
                        recon_mean = atoi(optarg);
                        break;
                    case 8:
                        // --rc-sd
                        recon_sd = atoi(optarg);
                        break;
                }
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
        printf("Delay mean cannot be negative. Setting to 0\n");
        delay_mean = 0;
    }

    if (delay_sd < 0) {
        delay_sd = -delay_sd;
    }

    if (discon_mean < 0) {
        printf("Disconnection interval mean cannot be negative. Disabling disconnections\n");
        discon_mean = 0;
    }

    if (discon_sd < 0) {
        discon_sd = -discon_sd;
    }

    if (recon_mean < 0) {
        printf("Reconnection interval mean cannot be negative. Setting immediate reconnection\n");
        recon_mean = 0;
    }

    if (recon_sd < 0) {
        recon_sd = -recon_sd;
    }

    if (loss_chance < 0) {
        printf("Loss chance cannot be negative. Setting to 0\n");
        loss_chance = 0;
    } else if (loss_chance > 1) {
        printf("Loss chance cannot be greater than 1. Setting to 1\n");
        loss_chance = 1;
    }

    if (bit_error_rate < 0) {
        printf("Bit error rate cannot be negative. Setting to 0\n");
        bit_error_rate = 0;
    } else if (bit_error_rate > 1) {
        printf("Bit error rate cannot be greater than 1. Setting to 1\n");
        bit_error_rate = 1;
    }

    loss_cutoff = UINT64_MAX * loss_chance;
    bit_error_cutoff = UINT64_MAX * bit_error_rate;

    // Resolving sockets
    if (left_is_server) {
        rv = bind_tcp_socket(&left_listen_fd, left_port);
    } else {
        rv = connect_tcp_socket(&left_fd, "127.0.0.1", left_port, NULL, NULL);
    }

    if (rv < 0) {
        fprintf(stderr, "Failed to process port %s\n", left_port);
        return rv;
    }


    if (right_is_server) {
        rv = bind_tcp_socket(&right_listen_fd, right_port);
    } else {
        rv = connect_tcp_socket(&right_fd, "127.0.0.1", right_port, NULL, NULL);
    }

    if (rv < 0) {
        fprintf(stderr, "Failed to process port %s\n", right_port);
        return rv;
    }

    // Bind both first, then accept. Makes sure that the ports are open as soon as possible so no connection refused
    if (left_is_server) {
        // The left_fd is currently set to the listen 
        rv = accept_tcp_connection(&left_fd, left_listen_fd, NULL, NULL);
    }

    if (rv < 0) {
        fprintf(stderr, "Failed to accept connection on port %s\n", left_port);
        return rv;
    }

    if (right_is_server) {
        rv = accept_tcp_connection(&right_fd, right_listen_fd, NULL, NULL);
    }

    if (rv < 0) {
        fprintf(stderr, "Failed to accept connection on port %s\n", right_port);
        return rv;
    }


    polls[0].fd = left_fd;
    polls[1].fd = right_fd;

    polls[0].events = polls[1].events = POLLIN;

    for (;;) {
        ts = timestamp_ms();

        // Calculate the timeout for the packets waiting to be sent left
        if (left_waiting_datas.next == NULL) {
            left_timeout = -1;
        } else {
            left_timeout = left_waiting_datas.next->send_time - ts;
            if (left_timeout < 0) left_timeout = 0;
        }

        // Calculate the timeouts for the packets waiting to be sent right
        if (right_waiting_datas.next == NULL) {
            right_timeout = -1;
        } else {
            right_timeout = right_waiting_datas.next->send_time - ts;
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

        if (discon_mean > 0) {
            // We're running disconnections
            if (disconnection_timeout == UINT64_MAX) {
                // The timeout is not set
                if (disconnected) {
                    // Sample from the reconnection distribution
                    disconnection_timeout = ts+get_rand_gaussian(recon_mean, recon_sd);
                } else {
                    // Sample from the disconnection distribution
                    disconnection_timeout = ts+get_rand_gaussian(discon_mean, discon_sd);
                }
                // Clip the timeout if it's in the past (distribution came back negative)
                if (disconnection_timeout < ts) disconnection_timeout = ts;
            }

            if (disconnection_timeout < timeout) {
                // We're processing the disconnection/reconnection before sending the next SPP
                timeout = disconnection_timeout;
            }
        }

        // Wait on a message on either end
        rv = poll(polls, 2, timeout);

        if (rv == 0) {
            // Poll continued due to timeout
            ts = timestamp_ms();

            if (ts <= disconnection_timeout) {
                // Run the disconnection op.
                // TODO - Define these ops.
                if (disconnected) {
                    // Reconnect
                    if (left_is_server) {
                        rv = accept_tcp_connection(&left_fd, left_listen_fd, NULL, NULL);
                    } else {
                        rv = connect_tcp_socket(&left_fd, "127.0.0.1", left_port, NULL, NULL);
                    }

                    if (rv < 0) {
                        return rv;
                    }

                    if (right_is_server) {
                        rv = accept_tcp_connection(&right_fd, right_listen_fd, NULL, NULL);
                    } else {
                        rv = connect_tcp_socket(&right_fd, "127.0.0.1", right_port, NULL, NULL);
                    }

                    if (rv < 0) {
                        return rv;
                    }
                } else {
                    // Disconnect
                    close(left_fd);
                    close(right_fd);
                }
                disconnection_timeout = UINT64_MAX;
                disconnected = !disconnected;
            }

            // Process right packets
            for (pkt_ptr = right_waiting_datas.next; pkt_ptr != NULL; pkt_ptr = right_waiting_datas.next) {
                // Packets are arranged in ascending order. If this one is still waiting, we can break.
                if (pkt_ptr->send_time > ts) break;

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
                if (pkt_ptr->send_time > ts) break;
                
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
            // We must have recieved TCP data
            // RNG to determine if we need to drop this SPP
            rand_uint = get_rand_u64();

            if (rand_uint < loss_cutoff) {
                discard_packet = 1;
            } else {
                discard_packet = 0;
            }

            delay = get_rand_gaussian(delay_mean, delay_sd);

            if (delay < 0) delay = 0;

            // Build the bit error mask
            for (int i = 0; i<SPP_MTU; i++) {
                rand_byte = 0;
                for (int b = 0; b < 8; b++) {
                    rand_uint = get_rand_u64();
                    if (rand_uint < bit_error_cutoff) {
                        // Corrupt this bit
                        rand_byte |= 0x01u << b;
                    }
                }
                // We're done building the corruption byte. Add it to the mask
                bit_error_mask[i] = rand_byte;
            }

            if (polls[0].revents & POLLIN) {
                // Recieved message to the left side

                rv = recv(left_fd, buf, SPP_HEADER_LEN, MSG_WAITALL);

                if (rv == -1) {
                    fprintf(stderr, "Error when left receiving message: %s\n", strerror(errno));
                    return -1;
                }

                if (rv == 0) {
                    printf("Remote closed connection\n");
                    return 0;
                }

                rv = recv(left_fd, buf+SPP_HEADER_LEN, get_spp_data_length(buf) + 1 - SPP_SEC_HEADER_LEN, MSG_WAITALL);

                // If dropping this packet, free the buffer it's been read into and return to the top of the loop
                if (discard_packet) {
                    if (debug >= 1) printf("Dropping right bound SPP\n");
                    continue;
                }

                // Apply the corruption mask for this packet
                for (int i = 0; i < rv+SPP_HEADER_LEN; i++) {
                    buf[i] ^= bit_error_mask[i];
                }

                pkt_ptr = make_node(buf, rv+SPP_HEADER_LEN, delay);

                if (pkt_ptr == NULL) {
                    // Out of memory
                    return -1;
                }

                enqueue_node(&right_waiting_datas, pkt_ptr);
            } else if (polls[1].revents & POLLIN) {
                // Recieved a message to the right side

                rv = recv(right_fd, buf, SPP_HEADER_LEN, MSG_WAITALL);

                if (rv == -1) {
                    fprintf(stderr, "Error when right receiving message: %s\n", strerror(errno));
                    return -1;
                }

                if (rv == 0) {
                    printf("Remote closed connection\n");
                    return 0;
                }

                rv = recv(right_fd, buf+SPP_HEADER_LEN, get_spp_data_length(buf) + 1 - SPP_SEC_HEADER_LEN, MSG_WAITALL);

                // If dropping this packet, free the buffer it's been read into and return to the top of the loop
                if (discard_packet) {
                    if (debug >= 1) printf("Dropping left bound SPP\n");
                    continue;
                }

                // Apply the corruption mask for this packet
                for (int i = 0; i < rv+SPP_HEADER_LEN; i++) {
                    buf[i] ^= bit_error_mask[i];
                }                

                pkt_ptr = make_node(buf, rv + SPP_HEADER_LEN, delay);

                if (pkt_ptr == NULL) {
                    // Out of memory
                    return -1;
                }

                enqueue_node(&left_waiting_datas, pkt_ptr);
            }
        }
    }
}