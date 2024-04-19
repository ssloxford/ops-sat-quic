#include "utils.h"
#include "spp.h"
#include "errors.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <poll.h>
#include <netdb.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>

#define TCP_DEFAULT_PORT "11112"

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

static int connect_tcp_socket(int *fd, char *server_port, struct sockaddr *remoteaddr, socklen_t *remoteaddrlen) {
    int rv;

    struct in_addr inaddr;

    rv = inet_aton("127.0.0.1", &inaddr);

    // 0 for error is correct. https://linux.die.net/man/3/inet_aton
    if (rv == 0) {
        // Address provided is invalid
        return -1;
    }

    // Opens TCP socket and connects to localhost:target_port, saving the sockaddr to remoteaddr
    rv = resolve_and_process(inaddr.s_addr, atoi(server_port), IPPROTO_UDP, 0, NULL, NULL, remoteaddr, remoteaddrlen);

    if (rv < 0) {
        return rv;
    }

    *fd = rv;
    return 0;
}

static int bind_and_accept_tcp_socket(int *fd, char *server_port, struct sockaddr *remoteaddr, socklen_t *remoteaddrlen) {
    int rv, listen_fd;

    rv = resolve_and_process(INADDR_ANY, atoi(server_port), IPPROTO_TCP, 1, NULL, NULL, NULL, NULL);

    if (rv < 0) {
        return rv;
    }

    listen_fd = rv;

    // Marks the TCP socket as accepting connections. Connection queue of length 1
    rv = listen(listen_fd, 1);

    if (rv < 0) {
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

static void add_to_node(const SPP *spp, incomplete_packet *node) {
    int payload_length = SPP_PAYLOAD_LENGTH(spp->primary_header.packet_data_length);

    node->frags_recieved += 1;
    node->packet_length += payload_length;

    // TODO - Update timeout

    // Offset is the max data length times the packet frag number
    // We assume that all previous packets have carried the max data len
    memcpy(node->partial_payload + (SPP_MAX_DATA_LEN * spp->secondary_header.udp_frag_num), spp->user_data, payload_length);
}

static incomplete_packet* insert_new_node(const SPP *spp, incomplete_packet *last, incomplete_packet *next) {
    incomplete_packet *node = malloc(sizeof(incomplete_packet));

    if (node == NULL) {
        return NULL;
    }

    uint8_t *payload = malloc(MAX_UDP_PAYLOAD);

    if (payload == NULL) {
        fprintf(stderr, "Warning: Out of memory. Could not insert new node\n");
        free(node);
        return NULL;
    }

    node->partial_payload = payload;

    node->packet_number = spp->secondary_header.udp_packet_num;
    node->frag_count = spp->secondary_header.udp_frag_count;

    node->frags_recieved = 0;
    node->packet_length = 0;

    node->next = next;
    if (next != NULL) {
        next->last = node;
    }

    node->last = last;
    last->next = node;

    add_to_node(spp, node);

    return node;
}

static int handle_tcp_packet(int udp_fd, uint8_t *buf, size_t buflen, size_t pktlen, incomplete_packet *incomp_pkts, const struct sockaddr *udp_addr, socklen_t addrlen) {
    int rv;

    size_t bytes_deserialised = 0;

    SPP spp;
    uint8_t spp_payload[SPP_MAX_DATA_LEN];

    int node_udp_pkt_num, searching_udp_pkt_num;

    incomplete_packet *pkt_ptr, *found_pkt;

    spp.user_data = spp_payload;

    // Loop allows multiple contiguous SPP packets in the TCP payload
    // TODO - Check there's not an out by one error
    while (pktlen > bytes_deserialised) {
        rv = deserialise_spp(buf+bytes_deserialised, &spp);

        if (rv < 0) {
            return rv;
        }

        // Allows us to keep track of where to start the next SPP packet
        bytes_deserialised += rv;

        if (spp.primary_header.pkt_id.apid != SPP_APID) {
            // Packet not intended for me
            continue;
        }

        // UDP packet number we're searching for in the linked list of incomplete packets
        searching_udp_pkt_num = spp.secondary_header.udp_packet_num;

        // Search the incomplete packets list for this UDP packet number
        for (pkt_ptr = incomp_pkts;;) {
            if (pkt_ptr->next == NULL) {
                // At the end of the list. Insert new node on the end
                found_pkt = insert_new_node(&spp, pkt_ptr, pkt_ptr->next);
                if (found_pkt == NULL) {
                    return ERROR_OUT_OF_MEMORY;
                }
                break;
            }
            
            // UDP packet number of the node being checked
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
                if (found_pkt == NULL) {
                    return ERROR_OUT_OF_MEMORY;
                }
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

    if (bytes_deserialised != pktlen) {
        fprintf(stderr, "Warning: Bytes deserialised does not match bytes received\n");
    }

    return 0;
}

static int handle_udp_packet(int tcp_fd, uint8_t *buf, size_t buflen, size_t pktlen, uint16_t spp_count, uint8_t udp_count, int *packets_sent) {
    int rv, packets_made;
    size_t bytes_to_send;

    SPP *packets;

    // Updates packets to the head of the array containing the fragmented data
    rv = fragment_data(&packets, buf, pktlen, &packets_made, spp_count, udp_count);

    if (rv < 0) {
        return rv;
    }

    for (int i = 0; i < packets_made; i++) {
        rv = serialise_spp(buf, buflen, &packets[i]);

        if (rv < 0) {
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

    if (rv < 0) {
        return rv;
    }

    *packets_sent = packets_made;
    return 0;
}

void print_helpstring() {
    printf("-h: Print help string\n");
    printf("-p [port]: Set UDP port\n");
    printf("-q [port]: Set TCP port\n");
    printf("-u: Run UDP connection in client mode\n");
    printf("-t: Run TCP connection in client mode\n");
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

    char *udp_target_port, *tcp_target_port = TCP_DEFAULT_PORT;
    int tcp_client = 0, udp_client = 0, udp_port_set = 0, udp_remote_set = 0;

    // Process option flags
    while ((opt = getopt(argc, argv, "htp:q:u")) != -1) {
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
            case 'q':
                tcp_target_port = optarg;
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
        rv = connect_udp_socket(&udp_fd, "localhost", udp_target_port, (struct sockaddr*) &udp_remote, &udp_remotelen);
        udp_remote_set = 1;
    } else {
        // Listen on provided socket
        rv = bind_udp_socket(&udp_fd, udp_target_port);
    }

    if (rv < 0) {
        fprintf(stderr, "Error when establishing UDP connection\n");
        return rv;
    }
    
    // Init the TCP connection
    if (tcp_client) {
        // Have it initiate tcp connection
        rv = connect_tcp_socket(&tcp_fd, tcp_target_port, (struct sockaddr*) &tcp_remote, &tcp_remotelen);

    } else {
        // Opens a socket to listen for TCP connections on and binds it to TCP port
        // Must then listen on that port and accept 
        rv = bind_and_accept_tcp_socket(&tcp_fd, tcp_target_port, (struct sockaddr*) &tcp_remote, &tcp_remotelen);
    }
    
    if (rv < 0) {
        fprintf(stderr, "Error when establishing TCP connection\n");
        return rv;
    }

    polls[0].fd = udp_fd;
    polls[1].fd = tcp_fd;

    polls[0].events = polls[1].events = POLLIN;

    for (;;) {
        if (udp_remote_set) {
            // Wait for either connection to have data
            poll(polls, 2, -1);
        } else {
            // If no udp remote, only wait on the UDP socket.
            // TCP messages will stack up in the network buffer and be processed once the remote UDP address is known
            poll(polls, 1, -1);
        }

        if (polls[0].revents & POLLIN) {
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
                continue;
            }

            // UDP packet recieved
            handle_udp_packet(tcp_fd, buf, sizeof(buf), rv, spp_count, udp_count, &packets_sent);
            udp_count++;
            spp_count += packets_sent;
        } else if (polls[1].revents & POLLIN) {
            // printf("TCP message recieved\n");

            rv = recv(tcp_fd, buf, sizeof(buf), 0);

            if (rv == 0) {
                printf("Remote shutdown TCP connection\n");
                deinit(udp_fd, tcp_fd);
                return 0;
            } else if (rv == -1) {
                fprintf(stderr, "Error when receiving TCP message: %s\n", strerror(errno));
                continue;
            }

            // TCP packet recieved
            handle_tcp_packet(udp_fd, buf, sizeof(buf), rv, &incomp_pkts, (struct sockaddr*) &udp_remote, udp_remotelen);
        }
    }
}
