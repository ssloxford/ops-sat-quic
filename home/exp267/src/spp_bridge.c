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

#define TCP_DEFAULT_PORT "4096"
#define UDP_DEFAULT_PORT "11120"
// Destroy the packet if it's incomplete and no new fragment has been recieved in the last 10 seconds
#define TIMEOUT_MS (2 * 1000)

typedef struct _incomplete_packet {
    uint16_t packet_number;

    size_t packet_length;

    // How many fragments have we recieved 
    uint8_t frag_count;
    uint8_t frags_recieved;

    // Copy the payloads into here as the packets are recieved
    uint8_t *partial_payload;

    // millisecond timestamp to consider this packet lost and delete this node
    uint64_t timeout;

    // Doubly linked list to allow fast insert and removal
    struct _incomplete_packet *next, *last;
} incomplete_packet;

static void add_to_node(const SPP *spp, incomplete_packet *node) {
    int payload_length = SPP_PAYLOAD_LENGTH(spp->primary_header.packet_data_length);

    node->frags_recieved += 1;
    node->packet_length += payload_length;

    // Reset the timeout for this packet
    node->timeout = timestamp_ms() + TIMEOUT_MS;

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
        fprintf(stderr, "SPP bridge: Warning: Out of memory. Could not insert new node\n");
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

static int handle_spp(int udp_fd, const uint8_t *buf, incomplete_packet *incomp_pkts, const struct sockaddr *udp_addr, socklen_t addrlen, int debug) {
    int rv;

    uint64_t ts = timestamp_ms();

    SPP spp;
    uint8_t spp_payload[SPP_MAX_DATA_LEN];

    uint16_t node_udp_pkt_num, searching_udp_pkt_num;

    incomplete_packet *prev_ptr, *pkt_ptr, *found_pkt;

    spp.user_data = spp_payload;

    rv = deserialise_spp(buf, &spp);

    if (rv == -1) {
        // Packet had a corrupted header. Drop the packet
        if (debug >= 1) printf("Packet had corrupted header, dropping packet\n");
        return -1;
    }

    if (spp.primary_header.pkt_id.apid != SPP_APID) {
        // Packet not intended for me
        if (debug >= 1) printf("Packet application ID did not match, dropping packet\n");
        return -1;
    }

    if (debug >= 4) printf("Received SPP for UDP packet %"PRIu16"\n", spp.secondary_header.udp_packet_num);

    // UDP packet number we're searching for in the linked list of incomplete packets
    searching_udp_pkt_num = spp.secondary_header.udp_packet_num;

    prev_ptr = incomp_pkts;

    // Search the incomplete packets list for this UDP packet number. List is sorted by UDP packet number
    for (pkt_ptr = prev_ptr->next;;pkt_ptr = prev_ptr->next) {
        if (pkt_ptr == NULL) {
            // At the end of the list. Insert new node on the end
            found_pkt = insert_new_node(&spp, prev_ptr, pkt_ptr);
            if (found_pkt == NULL) {
                return ERROR_OUT_OF_MEMORY;
            }
            break;
        }
        
        if (pkt_ptr->timeout < ts) {
            // This packet has expired. Destroy it
            // It may be that this packet number matches the one we've received, but it should still be destroyed for correctness of the timeout
            prev_ptr->next = pkt_ptr->next;

            if (debug >= 1) printf("Packet timeout reached. Dropping partial packet with UDP packet number %d\n", pkt_ptr->packet_number);

            // Deallocate this node
            free(pkt_ptr->partial_payload);
            free(pkt_ptr);
            continue;
        }

        // UDP packet number of the node being checked
        node_udp_pkt_num = pkt_ptr->packet_number;

        if (node_udp_pkt_num == searching_udp_pkt_num) {
            found_pkt = pkt_ptr;
            add_to_node(&spp, found_pkt);
            break;
        } else if (node_udp_pkt_num < searching_udp_pkt_num) {
            // Search list will be ordered by udp packet number in increaing order, so if we've not reached it yet we can continue
            prev_ptr = pkt_ptr;
        } else {
            // next packet number is greater than the search number, so insert here
            found_pkt = insert_new_node(&spp, prev_ptr, pkt_ptr);
            if (found_pkt == NULL) {
                return ERROR_OUT_OF_MEMORY;
            }
            break;
        }
    }

    // found_pkt is a pointer to the node containing the relevant packet. Handle if the packet is now complete
    if (found_pkt->frag_count == found_pkt->frags_recieved) {
        // Packet is complete. Ready to be transmitted over UDP

        if (debug >= 2) printf("SPP bridge: Sending completed UDP packet\n");

        rv = sendto(udp_fd, found_pkt->partial_payload, found_pkt->packet_length, 0, udp_addr, addrlen);

        if (rv == -1) {
            fprintf(stderr, "SPP bridge: Sendto: %s\n", strerror(errno));
            if (errno == ECONNREFUSED) {
                // The remote has closed the UDP. 
                return ERROR_SOCKET;
            }
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

    return 0;
}

static int handle_udp_packet(int tcp_fd, uint8_t *buf, size_t buflen, size_t pktlen, uint16_t spp_count, uint8_t udp_count, int *packets_sent, const struct sockaddr* remote_addr, socklen_t remote_addrlen, int debug) {
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
            fprintf(stderr, "SPP bridge: Error serialising SPP\n");
            return rv;
        }

        bytes_to_send = SPP_TOTAL_LENGTH(packets[i].primary_header.packet_data_length);

        if (debug >= 2) printf("Sending SPP of length %zu\n", bytes_to_send);

        // Potentially blocking call if remote not able to recieve data
        rv = sendto(tcp_fd, buf, bytes_to_send, 0, remote_addr, remote_addrlen);

        if (rv == -1) {
            fprintf(stderr, "SPP bridge: Send: %s\n", strerror(errno));
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
    printf("-d: Enable debug. Default off\n");
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

    // Must be signed since we're checking for -1 and char on arm is unsigned
    signed char opt;

    // List has a dummy node at the head
    incomplete_packet incomp_pkts;
    // The list is empty
    incomp_pkts.next = NULL;

    // Allocate the buffers here for performance (avoids allocating largeish memory on the stack for every call)
    uint8_t buf[BUF_SIZE];

    // Must manually track the UDP packets that pass through to allow for reconstruction
    uint16_t udp_count = 0;
    // Total number of spp packets sent, to keep track of packet numbers in SPP headers
    uint16_t spp_count = 0;
    size_t spp_data_length;

    struct pollfd polls[2];

    char *udp_target_port, *tcp_target_port = TCP_DEFAULT_PORT;
    int tcp_client = 0, udp_client = 0, udp_port_set = 0, udp_remote_set = 0, debug = 0;

    size_t bytes_purged;

    uint64_t ts = timestamp_ms();

    // Process option flags
    while ((opt = getopt(argc, argv, "htp:q:ud")) != -1) {
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
            case 'd':
                debug += 1;
                break;
            case '?':
                printf("SPP bridge: Unknown option -%c\n", optopt);
                break;
        }
    }

    if (!udp_port_set) {
        fprintf(stderr, "SPP bridge: Must set UDP port to listen on. See help string\n");
        return 0;
    }

    // Init the UDP socket
    if (udp_client) {
        // Connect to the provided UDP port
        rv = connect_udp_socket(&udp_fd, "127.0.0.1", udp_target_port, (struct sockaddr*) &udp_remote, &udp_remotelen);
        udp_remote_set = 1;
    } else {
        // Listen on provided socket
        rv = bind_udp_socket(&udp_fd, udp_target_port);
    }

    if (rv < 0) {
        fprintf(stderr, "SPP bridge: Error when establishing UDP connection\n");
        return rv;
    }
    
    if (debug >= 1) printf("SPP bridge: Processing TCP port %s as %s\n", tcp_target_port, tcp_client ? "client" : "server");

    // Init the TCP connection
    if (tcp_client) {
        // Have it initiate tcp connection
        rv = connect_tcp_socket(&tcp_fd, "127.0.0.1", tcp_target_port, (struct sockaddr*) &tcp_remote, &tcp_remotelen);
    } else {
        // Opens a socket to listen for TCP connections on and binds it to TCP port
        // Must then listen on that port and accept 
        rv = bind_and_accept_tcp_socket(&tcp_fd, tcp_target_port, (struct sockaddr*) &tcp_remote, &tcp_remotelen);
    }
    
    if (rv < 0) {
        fprintf(stderr, "SPP bridge: Error when establishing TCP connection\n");
        return rv;
    }

    if (debug >= 1) printf("SPP bridge: Successfully established connections\n");

    polls[0].fd = udp_fd;
    polls[1].fd = tcp_fd;

    polls[0].events = polls[1].events = POLLIN;

    if (debug >= 3) printf("Intialisation took %"PRIu64"ms\n", timestamp_ms() - ts);

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
            if (debug >= 2) printf("SPP bridge: UDP message recieved\n");

            // If dealing with a new client, will update address. Lets bridge persist across clients
            rv = recvfrom(udp_fd, buf, sizeof(buf), 0, (struct sockaddr*) &udp_remote, &udp_remotelen);
            udp_remote_set = 1;

            if (rv == -1) {
                fprintf(stderr, "SPP bridge: Error when receiving UDP message: %s\n", strerror(errno));
                if (errno == ECONNREFUSED) {
                    // If the remote is a server that's terminated, also terminate
                    if (udp_client) {
                        rv = -1;
                        break;
                    }
                    // Otherwise, wait for the next connection to the local UDP server
                    udp_remote_set = 0;
                }
                continue;
            }

            // UDP packet recieved
            handle_udp_packet(tcp_fd, buf, sizeof(buf), rv, spp_count, udp_count, &packets_sent, (struct sockaddr*) &tcp_remote, tcp_remotelen, debug);
            udp_count++;
            if (udp_count == 0) printf("WARNING: UDP count overflowed\n");
            spp_count += packets_sent;
            if (spp_count >= SPP_SEQ_COUNT_MODULO) spp_count -= SPP_SEQ_COUNT_MODULO;
        } else if (polls[1].revents & POLLIN) {
            if (debug >= 2) printf("SPP bridge: TCP message recieved\n");

            // Wait to be able to read a full header
            rv = recv(tcp_fd, buf, SPP_HEADER_LEN, MSG_WAITALL);

            if (rv == 0) {
                printf("SPP bridge: Remote shutdown TCP connection\n");
                break;
            } else if (rv == -1) {
                fprintf(stderr, "SPP bridge: Error when receiving TCP message: %s\n", strerror(errno));
                continue;
            }

            if (!verify_checksum(buf)) {
                // The received header is invalid. The packet length may be corrupted so drop everything we've received and not yet processed
                if (debug >= 1) printf("Corrupted header received, purging TCP queue\n");
                bytes_purged = 0;
                for (;;) {
                    rv = recv(tcp_fd, buf, sizeof(buf), MSG_DONTWAIT);
                    if (rv == -1) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            // We've depleated the TCP receive queue
                            break;
                        }
                    }
                    bytes_purged += rv;
                }
                if (debug >= 1) printf("TCP queue purged after %zu bytes purged\n", bytes_purged);
                // Return to the top of the server loop
                continue;
            }

            // Data length field is one less than the actual length of the field
            spp_data_length = get_spp_data_length(buf) + 1 - SPP_SEC_HEADER_LEN;

            // Wait to recieve the body of the SPP, then process it
            rv = recv(tcp_fd, buf+SPP_HEADER_LEN, spp_data_length, MSG_WAITALL);

            if (debug >= 2) printf("SPP bridge: Packet of length %zu in total successfully read\n", spp_data_length+SPP_HEADER_LEN);

            if (rv == 0) {
                printf("SPP bridge: Remote shutdown TCP connection\n");
                break;
            } else if (rv == -1) {
                fprintf(stderr, "SPP bridge: Error when receiving TCP message: %s\n", strerror(errno));
                continue;
            }

            ts = timestamp_ms();
            // TCP packet recieved
            rv = handle_spp(udp_fd, buf, &incomp_pkts, (struct sockaddr*) &udp_remote, udp_remotelen, debug);

            if (debug >= 3) printf("Handling SPP took %"PRIu64"ms\n", timestamp_ms() - ts);

            if (rv < 0) {
                if (rv == ERROR_SOCKET) {
                    // If the remote is a server that's terminated, also terminate
                    if (udp_client) {
                        rv = -1;
                        deinit(udp_fd, tcp_fd);
                        return -1;
                    }
                    // Otherwise, wait for the next connection to the local UDP server
                    udp_remote_set = 0;
                }
                if (rv == -1) {
                    // Packet was dropped because it's not for me or was corrupted
                    continue;
                }
            }
        }
    }

    deinit(udp_fd, tcp_fd);

    return rv;
}
