#include "utils.h"
#include "spp.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <poll.h>
#include <netdb.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define TCP_PORT "11112"
#define MAX_UDP_PACKET_SIZE 1200

// TODO - Timeout on these?
typedef struct _incomplete_packet {
    uint8_t packet_number;

    size_t packet_length;

    // How many fragments have we recieved 
    uint8_t frag_count;
    uint8_t frags_recieved;

    // Copy the payloads into here as the packets are recieved
    uint8_t *partial_payload;

    // Doubly linked list to allow fast insert and removal
    struct _incomplete_packet *next, *last;
} incomplete_packet;

// Function for debug only
static int connect_tcp_socket(int *fd, char *server_port, struct sockaddr *remoteaddr, socklen_t *remoteaddrlen) {
    struct addrinfo hints;

    struct sockaddr_storage addrstorage;
    socklen_t socklen;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET;
    hints.ai_protocol = IPPROTO_TCP;

    // Opens TCP socket and connects to localhost:target_port, saving the sockaddr to remoteaddr
    return resolve_and_process(fd, "localhost", server_port, &hints, 0, (struct sockaddr*) &addrstorage, &socklen, remoteaddr, remoteaddrlen);
}

static int bind_and_accept_tcp_socket(int *fd, char *server_port, struct sockaddr *remoteaddr, socklen_t *remoteaddrlen) {
    struct addrinfo hints;

    int rv;

    // Dummy variables so that we can use the resolve and process function without segfault
    struct sockaddr_storage addrstorage;
    socklen_t socklen;

    int listen_fd;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET; // IPv4 addresses
    hints.ai_protocol = IPPROTO_TCP; // TCP socket
    hints.ai_flags = AI_PASSIVE;

    rv = resolve_and_process(&listen_fd, INADDR_ANY, server_port, &hints, 1, (struct sockaddr*) &addrstorage, &socklen, NULL, NULL);

    if (rv != 0) {
        return rv;
    }

    // Marks the TCP socket as accepting connections. Connection queue of length 1
    rv = listen(listen_fd, 1);

    if (rv != 0) {
        fprintf(stderr, "listen: %s\n", strerror(errno));
        return rv;
    }

    // Blocking call if none pending in the connection queue. Returns a new fd on success
    rv = accept(listen_fd, remoteaddr, remoteaddrlen);

    if (rv == -1) {
        fprintf(stderr, "accept: %s\n", strerror(errno));
        return rv;
    }

    close(listen_fd);

    // rv is the fd of the port connected to remote
    *fd = rv;
    return 0;
}

static int bind_udp_socket(int *fd, char *server_port) {
    struct addrinfo hints;

    // Dummy variables so that we can use the resolve and process function without segfault
    struct sockaddr_storage addrstorage;
    socklen_t socklen;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET; // IPv4 addresses
    hints.ai_protocol = IPPROTO_UDP; // UDP sockets only
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV; // Port is provided as a number rather than string eg. "ssh"

    return resolve_and_process(fd, INADDR_ANY, server_port, &hints, 1, (struct sockaddr*) &addrstorage, &socklen, NULL, NULL);
}

static int connect_udp_socket(int *fd, char *server_port, struct sockaddr *remoteaddr, socklen_t *remoteaddrlen) {
    struct addrinfo hints;

    struct sockaddr_storage addrstorage;
    socklen_t socklen;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET;
    hints.ai_protocol = IPPROTO_UDP;

    // Opens TCP socket and connects to localhost:target_port, saving the sockaddr to remoteaddr
    return resolve_and_process(fd, "localhost", server_port, &hints, 0, (struct sockaddr*) &addrstorage, &socklen, remoteaddr, remoteaddrlen);
}

static void add_to_node(SPP *spp, incomplete_packet *node) {
    int payload_length = SPP_PAYLOAD_LENGTH(spp->primary_header.packet_data_length);

    node->frags_recieved += 1;
    node->packet_length += payload_length;

    // TODO - Update timeout

    // TODO - Check these mem addresses
    // We assume that all previous packets have carried the max data len
    memcpy(node->partial_payload + (SPP_MAX_DATA_LEN * spp->secondary_header.udp_frag_num), spp->user_data, payload_length);
}

static incomplete_packet* insert_new_node(SPP *spp, incomplete_packet *last, incomplete_packet *next) {
    incomplete_packet *node = malloc(sizeof(incomplete_packet));

    if (node == NULL) {
        // TODO - Out of memory error
        return NULL;
    }

    uint8_t *payload = malloc(MAX_UDP_PACKET_SIZE);

    if (payload == NULL) {
        // TODO - Out of memory error
        return NULL;
    }

    node->packet_number = spp->secondary_header.udp_packet_num;
    node->frag_count = spp->secondary_header.udp_frag_count;

    node->frags_recieved = 0;
    node->packet_length = 0;
    node->partial_payload = payload;

    node->next = next;
    node->last = last;

    if (next != NULL) {
        next->last = node;
    }

    last->next = node;

    add_to_node(spp, node);

    return node;
}

static int handle_tcp_packet(int udp_fd, uint8_t *buf, size_t buflen, size_t pktlen, incomplete_packet *incomp_pkts, const struct sockaddr *udp_addr, socklen_t addrlen) {
    int rv;

    size_t bytes_remaining, bytes_deserialised;

    SPP spp;
    uint8_t spp_payload[SPP_MAX_DATA_LEN];

    int node_udp_pkt_num, searching_udp_pkt_num;

    incomplete_packet *pkt_ptr, *found_pkt;

    spp.user_data = spp_payload;
    
    // rv is the number of bytes read into buf
    bytes_remaining = pktlen;
    bytes_deserialised = 0;

    // Loop allows multiple contiguous SPP packets in the TCP payload
    while (bytes_remaining > bytes_deserialised) {
        rv = deserialise_spp(buf+bytes_deserialised, &spp);

        if (rv < 0) {
            return rv;
        }

        // Allows us to keep track of where to start the next SPP packet
        bytes_deserialised += rv;

        // UDP packet number we're searching for in the linked list of incomplete packets
        searching_udp_pkt_num = spp.secondary_header.udp_packet_num;

        // Search the incomplete packets list for this UDP packet number
        for (pkt_ptr = incomp_pkts;; pkt_ptr = pkt_ptr->next) {
            if (pkt_ptr->next == NULL) {
                // Insert the new node 
                found_pkt = insert_new_node(&spp, pkt_ptr, pkt_ptr->next);
                break;
            }
            
            // UDP packet number of the current node
            node_udp_pkt_num = pkt_ptr->next->packet_number;

            if (node_udp_pkt_num == searching_udp_pkt_num) {
                found_pkt = pkt_ptr->next;
                add_to_node(&spp, found_pkt);
                break;
            } else if (node_udp_pkt_num < searching_udp_pkt_num) {
                // Search list will be ordered by udp packet number in increaing order

                // TODO - Process timeout to abandon partial UDP packet
                continue;
            } else {
                // next packet number is greater than the search number, so insert here
                found_pkt = insert_new_node(&spp, pkt_ptr, pkt_ptr->next);
                break;
            }
        }

        // found_pkt is a pointer to the node containing the relevant packet. Handle if the packet is now complete
        if (found_pkt->frag_count == found_pkt->frags_recieved) {
            // Packet is complete. Ready to be transmitted over UDP

            rv = sendto(udp_fd, found_pkt->partial_payload, found_pkt->packet_length, 0, udp_addr, addrlen);

            if (rv == -1) {
                fprintf(stderr, "Sendto: %s\n", strerror(errno));
                return -1;
            }

            // Reconnect the linked list
            found_pkt->last->next = found_pkt->next;
            if (found_pkt->next != NULL) {
                found_pkt->next->last = found_pkt->last;
            }

            // Deallocate the list node and associated buffer
            free(found_pkt->partial_payload);
            free(found_pkt);
        }
    }
}

static int handle_udp_packet(int tcp_fd, uint8_t *buf, size_t buflen, size_t pktlen, uint16_t spp_count, uint8_t udp_count, int *packets_sent) {
    int rv, packets_made;
    size_t bytes_to_send;

    SPP *packets;

    // Updates packets to the head of the array containing the fragmented data
    rv = fragment_data(&packets, buf, pktlen, &packets_made, spp_count, udp_count);

    if (rv != 0) {
        return rv;
    }

    for (int i = 0; i < packets_made; i++) {
        rv = serialise_spp(buf, buflen, &packets[i]);

        if (rv != 0) {
            return rv;
        }

        bytes_to_send = SPP_TOTAL_LENGTH(packets[i].primary_header.packet_data_length);

        // Potentially blocking call if remote not able to recieve data
        rv = send(tcp_fd, buf, bytes_to_send, 0);

        if (rv == -1) {
            fprintf(stderr, "Send: %s\n", strerror(errno));
            return -1;
        }
    }

    rv = free_spp_array(packets, packets_made);

    if (rv != 0) {
        return rv;
    }

    *packets_sent = packets_made;
    return 0;
}

void print_helpstring() {
    printf("-h: Print help string\n");
    printf("-t: Run TCP connection in client mode\n");
    printf("-p [port]: Set UDP port\n");
    printf("-u: Run UDP connection in client mode\n");
}

void deinit(int udp_fd, int tcp_fd) {
    close(udp_fd);
    close(tcp_fd);
}

int main(int argc, char **argv) {
    int rv, packets_sent;
    int tcp_fd, udp_fd;

    struct sockaddr_storage udp_remote, tcp_remote;
    socklen_t udp_remotelen = sizeof(udp_remote), tcp_remotelen = sizeof(tcp_remote);
    
    memset(&udp_remote, 0, udp_remotelen);
    memset(&tcp_remote, 0, tcp_remotelen);

    char opt;

    // List has a dummy node at the head
    incomplete_packet incomp_pkts;
    // The list is empty
    incomp_pkts.next = NULL;

    // Allocate the buffers here for performance (avoids allocating largeish memory on the stack for every call)
    uint8_t buf[BUF_SIZE];

    // Must manually track the UDP packets that pass through to allow for reconstruction
    uint8_t udp_count = 0;
    // Total number of spp packets sent, to keep track of packet numbers in SPP headers
    uint8_t spp_count = 0;

    struct pollfd polls[2];

    char *udp_target_port;
    int tcp_client = 0, udp_client = 0, udp_port_set = 0, udp_remote_set = 0;

    // Process option flags
    while ((opt = getopt(argc, argv, "htp:u")) != -1) {
        switch (opt){
            case 'h':
                print_helpstring();
                return 0;
                break;
            case 't':
                tcp_client = 1;
                break;
            case 'p':
                udp_target_port = optarg;
                udp_port_set = 1;
                break;
            case 'u':
                udp_client = 1;
                break;
            case '?':
                printf("Unknown option -%c\n", optopt);
                break;
        }
    }

    if (!udp_port_set) {
        fprintf(stderr, "Must set UDP port to listen on. See help string\n");
        return 0;
    }

    // Init the UDP socket
    if (udp_client) {
        // Connect to the provided UDP port
        rv = connect_udp_socket(&udp_fd, udp_target_port, (struct sockaddr*) &udp_remote, &udp_remotelen);
        udp_remote_set = 1;
    } else {
        // Listen on provided socket
        rv = bind_udp_socket(&udp_fd, udp_target_port);
    }

    if (rv != 0) {
        fprintf(stderr, "Error when establishing UDP connection\n");
        return rv;
    }
    
    // Init the TCP connection
    if (tcp_client) {
        // Have it initiate tcp connection
        rv = connect_tcp_socket(&tcp_fd, TCP_PORT, (struct sockaddr*) &tcp_remote, &tcp_remotelen);

    } else {
        // Opens a socket to listen for TCP connections on and binds it to TCP port
        // Must then listen on that port and accept 
        rv = bind_and_accept_tcp_socket(&tcp_fd, TCP_PORT, (struct sockaddr*) &tcp_remote, &tcp_remotelen);
    }
    
    if (rv != 0) {
        fprintf(stderr, "Error when establishing TCP connection\n");
        return rv;
    }

    polls[0].fd = tcp_fd;
    polls[1].fd = udp_fd;

    polls[0].events = polls[1].events = POLLIN;

    for (;;) {
        // Wait for either connection to have data
        poll(polls, 2, -1);

        if (polls[0].revents & POLLIN) {
            // printf("TCP message recieved\n");

            rv = recv(tcp_fd, buf, sizeof(buf), 0);

            if (rv == 0) {
                printf("Remote shutdown TCP connection\n");
                deinit(udp_fd, tcp_fd);
                return 0;
            } else if (rv == -1) {
                fprintf(stderr, "Error when receiving TCP message: %s\n", strerror(errno));
            }

            if (!udp_remote_set) {
                fprintf(stderr, "Warning: No UDP remote was set. Discarding TCP packet\n");
                continue;
            }

            // TCP packet recieved
            handle_tcp_packet(udp_fd, buf, sizeof(buf), rv, &incomp_pkts, (struct sockaddr*) &udp_remote, udp_remotelen);
        } else if (polls[1].revents & POLLIN) {
            // printf("UDP message recieved\n");
            
            if (!udp_remote_set) {
                rv = recvfrom(udp_fd, buf, sizeof(buf), 0, (struct sockaddr*) &udp_remote, &udp_remotelen);
                udp_remote_set = 1;
            } else {
                // Don't update the udp_remote struct. Otherwise the same as above.
                rv = recv(udp_fd, buf, sizeof(buf), 0);
            }

            if (rv == -1) {
                fprintf(stderr, "Error when receiving UDP message: %s\n", strerror(errno));
            }

            // UDP packet recieved
            handle_udp_packet(tcp_fd, buf, sizeof(buf), rv, spp_count, udp_count, &packets_sent);
            udp_count++;
            spp_count += packets_sent;
        }
    }
}
