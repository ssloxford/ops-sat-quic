#include "spp.h"

#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

// TODO - Make all the error codes negative and macros

// TODO - Warning when truncating significant bits?
int construct_spp(SPP *spp, const uint8_t *payload, size_t payloadlen, uint8_t *data_field, pkt_type packet_type, seq_flag seq_flags, uint16_t spp_pkt_num, uint8_t udp_pkt_num, uint8_t udp_frag_count, uint8_t udp_frag_num) {
    if (payloadlen > SPP_MAX_DATA_LEN) {
        // TODO - Limits.h this: It's %ld on x86 and %d on ARM. Or suppress/ignore warning
        fprintf(stderr, "Data of %zu bytes does not fit into max payload field\n", payloadlen);
        return 1;
    }

    if (spp_pkt_num >= SPP_SEQ_COUNT_MODULO) spp_pkt_num -= SPP_SEQ_COUNT_MODULO;
    
    // Primary header
    spp->primary_header.packet_version_number = 0;

    spp->primary_header.pkt_id.packet_type = 0x01 & packet_type;
    spp->primary_header.pkt_id.secondary_header_present = 1;
    spp->primary_header.pkt_id.apid = 0x07ff & SPP_APID;

    spp->primary_header.pkt_seq_ctrl.sequence_flags = 0x03 & seq_flags;
    spp->primary_header.pkt_seq_ctrl.sequence_count = 0x3fff & spp_pkt_num;

    // data length field is one less than the number of data (non-primary header) bytes
    spp->primary_header.packet_data_length = payloadlen + SPP_SEC_HEADER_LEN - 1;

    // Secondary header
    spp->secondary_header.udp_packet_num = udp_pkt_num;
    spp->secondary_header.udp_frag_count = 0x0f & udp_frag_count;
    spp->secondary_header.udp_frag_num = 0x0f & udp_frag_num;
    // Checksum is calculated and verified when serialising. Not constructed here

    // Payload
    memcpy(data_field, payload, payloadlen);
    spp->user_data = data_field;

    return 0;
}

int serialise_spp(uint8_t *buf, size_t buflen, const SPP *spp) {
    size_t packet_length = SPP_TOTAL_LENGTH(spp->primary_header.packet_data_length);

    if (buflen < packet_length) {
        // Buffer is too small to hold the packet
        return -1;
    }

    memset(buf, 0, packet_length);

    buf[0] |= 0xe0 & (spp->primary_header.packet_version_number << 5);

    // Packet ID field
    buf[0] |= 0x10 & (spp->primary_header.pkt_id.packet_type << 4);
    buf[0] |= 0x08 & (spp->primary_header.pkt_id.secondary_header_present << 3);
    // 3 least significant bits of the 2nd byte (ie bits 10, 9, and 8)
    buf[0] |= 0x07 & (spp->primary_header.pkt_id.apid >> 8);
    buf[1] |= 0xff & (spp->primary_header.pkt_id.apid);

    // Packet sequence control field
    buf[2] |= 0xc0 & (spp->primary_header.pkt_seq_ctrl.sequence_flags << 6);
    buf[2] |= 0x3f & (spp->primary_header.pkt_seq_ctrl.sequence_count >> 8);
    buf[3] |= 0xff & (spp->primary_header.pkt_seq_ctrl.sequence_count);

    // Packet data length field takes 2 full bytes
    buf[4] |= 0xff & (spp->primary_header.packet_data_length >> 8);
    buf[5] |= 0xff & (spp->primary_header.packet_data_length);

    buf[6] |= 0xff & (spp->secondary_header.udp_packet_num >> 8);
    buf[7] |= 0xff & (spp->secondary_header.udp_packet_num);
    buf[8] |= 0xf0 & (spp->secondary_header.udp_frag_count << 4);
    buf[8] |= 0x0f & (spp->secondary_header.udp_frag_num);

    buf[9] |= 0xff & calculate_checksum(buf);

    size_t data_field_len = packet_length - SPP_HEADER_LEN;
    memcpy(buf+SPP_HEADER_LEN, spp->user_data, data_field_len);

    return 0;
}

uint8_t calculate_checksum(const uint8_t *header) {
    // We use a modified (8 bit rather than 16 bit) version of the Internet Checksum Algorithm (RFC1071)
    uint8_t check_sum = 0;

    for (int i = 0; i < SPP_HEADER_LEN; i++) {
        if (i != SPP_CHECKSUM_OFFSET) {
            // We don't add the checksum byte to the checksum
            if (check_sum > UINT8_MAX - ~header[i]) {
                // Overflow will occur. End around carry
                check_sum += 1;
            }
            // Add the 1s compliment
            check_sum += ~header[i];
        }
    }

    return check_sum;
}

int verify_checksum(const uint8_t *header) {
    return calculate_checksum(header) == header[SPP_CHECKSUM_OFFSET];
}

size_t get_spp_data_length(const uint8_t *buf) {
    uint16_t size = 0;

    size |= (buf[4] << 8);
    size |= buf[5];

    return size;
}

int deserialise_spp(const uint8_t *buf, SPP *spp) {
    if (!verify_checksum(buf)) {
        // Checksum showed corrupted packet header. Drop packet
        return -1;
    }

    // Primary header
    spp->primary_header.packet_version_number = 0x07 & (buf[0] >> 5);
    
    spp->primary_header.pkt_id.packet_type = 0x01 & (buf[0] >> 4);
    spp->primary_header.pkt_id.secondary_header_present = 0x01 & (buf[0] >> 3);
    spp->primary_header.pkt_id.apid = 0x07ff & ((buf[0] << 8) | buf[1]);

    spp->primary_header.pkt_seq_ctrl.sequence_flags = 0x03 & (buf[2] >> 6);
    spp->primary_header.pkt_seq_ctrl.sequence_count = 0x3fff & ((buf[2] << 8) | buf[3]);

    spp->primary_header.packet_data_length = get_spp_data_length(buf);

    // Secondary header
    spp->secondary_header.udp_packet_num = 0xffff & ((buf[6] << 8) | buf[7]);
    spp->secondary_header.udp_frag_count = 0x0f & (buf[8] >> 4);
    spp->secondary_header.udp_frag_num = 0x0f & buf[8];

    // It is assumed that the buffer in spp->user_data is big enough to take the data
    // It's also assumed that the buffer provided is long enough to hold all the promised data
    memcpy(spp->user_data, buf + SPP_HEADER_LEN, SPP_PAYLOAD_LENGTH(spp->primary_header.packet_data_length));

    return 0;
}

int fragment_data(SPP **spp, const uint8_t *data, size_t datalen, int *packets_made, uint16_t spp_pkt_count, uint8_t udp_pkt_num) {
    int data_written, data_this_packet;
    seq_flag seq_flag;

    uint8_t *user_data;

    int rv;

    // The division will truncate so need to make sure we "round up"
    int packets_needed = (datalen + SPP_MAX_DATA_LEN - 1) / SPP_MAX_DATA_LEN;

    *packets_made = 0;

    // Creates an array of SPPs with length packets_needed
    *spp = calloc(packets_needed, sizeof(SPP));

    if (*spp == NULL) {
        // Out of memory
        return -1;
    }

    for (int i = 0; i < packets_needed; i++) {
        data_written = i * SPP_MAX_DATA_LEN;

        // Ammount of data left to write
        data_this_packet = datalen - data_written;

        if (data_this_packet > SPP_MAX_DATA_LEN) {
            data_this_packet = SPP_MAX_DATA_LEN;
        }
        
        // Create the buffer that we'll point to in the SPP struct
        user_data = malloc(data_this_packet);

        if (user_data == NULL) {
            return -1;
        }

        // Set the segment sequence flag
        if (packets_needed == 1) {
            seq_flag = unseg;
        } else if (i == 0) {
            seq_flag = first;
        } else if (i == packets_needed - 1) {
            seq_flag = last;
        } else {
            seq_flag = cont;
        }

        // *spp + i is the address of the ith element in the array at *spp
        // TODO - Figure out if this should be TC or TM, or if it doesn't matter
        rv = construct_spp((*spp) + i, data + data_written, data_this_packet, user_data, telecommand, seq_flag, spp_pkt_count + i, udp_pkt_num, packets_needed, i);

        if (rv < 0) {
            return rv;
        }

        (*packets_made)++;
    }

    return 0;
}

int free_spp_array(SPP *array, size_t arraylen) {
    for (size_t i = 0; i < arraylen; i++) {
        free(array[i].user_data);
    }
    
    free(array);

    return 0;
}
