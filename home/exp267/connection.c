#include <ngtcp2/ngtcp2.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#include "connection.h"
#include "utils.h"

int prepare_packet(ngtcp2_conn *conn, uint64_t stream_id, uint8_t* buf, size_t buflen, size_t *pktlen, struct iovec *iov) {
    // Write stream prepares the message to be sent into buf and returns size of the message
    ngtcp2_tstamp ts = timestamp();
    ngtcp2_pkt_info pi;
    ngtcp2_path_storage ps;
    ngtcp2_ssize wdatalen; // wdatalen is the length of data within STREAM (data) frames only

    int rv;

    ngtcp2_path_storage_zero(&ps);

    // Need to cast *iov to (ngtcp2_vec*). Apparently safe: https://nghttp2.org/ngtcp2/types.html#c.ngtcp2_vec
    rv = ngtcp2_conn_writev_stream(conn, &ps.path, &pi, buf, buflen, &wdatalen, NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id, (ngtcp2_vec*) iov, 1, ts);
    if (rv < 0) {
        fprintf(stderr, "Trying to write to stream failed: %s\n", ngtcp2_strerror(rv));
        return rv;
    }

    if (rv == 0) {
        fprintf(stderr, "Warning: Buffer to prepare packet into too small or packet is congestion limited\n");
    }

    // Update pktlen with the length of the produced packet
    *pktlen = rv;

    return 0;
}

int send_packet(int fd, uint8_t* pkt, size_t pktlen) {
    struct iovec msg_iov;
    struct msghdr msg;

    memset(&msg, 0, sizeof(msg));

    int rv;

    // Assume that there is a packet to be sent in the global buf array
    msg_iov.iov_base = pkt;
    msg_iov.iov_len = pktlen;

    msg.msg_iov = &msg_iov;
    msg.msg_iovlen = 1;

    // Don't need to poll ready to write since UDP sockets are connectinless, so can always write
    rv = sendmsg(fd, &msg, 0);

    // On success rv > 0 is the number of bytes sent

    if (rv == -1) {
        fprintf(stderr, "sendmsg: %s\n", strerror(errno));
        return rv;
    }

    return 0;
}

int await_message(int fd, struct iovec *iov, struct sockaddr *remote_addr, size_t remote_addrlen, size_t *bytes_read) {
    struct pollfd conn_poll;
    
    struct msghdr msg;

    int rv;

    // Create socket polling
    conn_poll.fd = fd;
    conn_poll.events = POLLIN;

    // Clear message structure
    memset(&msg, 0, sizeof(msg));

    // Sents the fields where the senders address will be saved to by recvmsg
    msg.msg_name = remote_addr;
    msg.msg_namelen = remote_addrlen;

    // msg_iov is an array of iovecs to write the recieved message into. msg_iovlen is the size of that array.
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    // Waits for the fd saved to the server to be ready to read. No timeout
    poll(&conn_poll, 1, -1);
    
    // TODO - Think about flags here. https://pubs.opengroup.org/onlinepubs/009695399/functions/recvmsg.html
    rv = recvmsg(fd, &msg, 0);

    if (rv == -1) {
        fprintf(stderr, "recvmsg: %s\n", strerror(errno));
        return rv;
    }

    // Warning when buffer is not big enough to store the recieved message
    if (msg.msg_flags & MSG_TRUNC) {
        fprintf(stderr, "Warning: Message data was truncated as it did not fit into the buffer\n");
    }

    *bytes_read = rv;

    return 0;
}