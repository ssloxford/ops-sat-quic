#include "spp.h"

#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

// TODO - Warning when truncating significant bits?
int construct_spp(SPP *spp, const uint8_t *payload, size_t payloadlen, uint8_t *data_field, pkt_type packet_type, seq_flag seq_flags, uint16_t spp_pkt_num, uint8_t udp_pkt_num, uint8_t udp_frag_count, uint8_t udp_frag_num) {
    if (payloadlen > SPP_MAX_DATA_LEN) {
        fprintf(stderr, "Data of %ld bytes does not fit into payload field\n", payloadlen);
        return 1;
    }
    
    // Primary header
    spp->primary_header.packet_version_number = 0;

    spp->primary_header.pkt_id.packet_type = 0x01 & packet_type;
    spp->primary_header.pkt_id.secondary_header_present = 1;
    spp->primary_header.pkt_id.apid = 0x07ff & SPP_APID;

    spp->primary_header.pkt_seq_ctrl.sequence_flags = 0x03 & seq_flags;
    spp->primary_header.pkt_seq_ctrl.sequence_count = 0x3fff & spp_pkt_num;

    // data length field is one less than the total number of bytes
    spp->primary_header.packet_data_length = payloadlen + SPP_HEADER_LEN - 1;

    // Secondary header
    spp->secondary_header.udp_packet_num = udp_pkt_num;
    spp->secondary_header.udp_frag_count = 0x0f & udp_frag_count;
    spp->secondary_header.udp_frag_num = 0x0f & udp_frag_num;

    // Payload
    memcpy(data_field, payload, payloadlen);
    spp->user_data = data_field;

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

    *spp = malloc(packets_needed * sizeof(SPP));

    if (*spp == NULL) {
        return -1;
    }

    for (int i = 0; i < packets_needed; i++) {
        data_written = i * SPP_MAX_DATA_LEN;

        // Ammount of data left to write
        data_this_packet = datalen - data_written;

        if (data_this_packet > SPP_MAX_DATA_LEN) {
            data_this_packet = SPP_MAX_DATA_LEN;
        }
        
        user_data = malloc(data_this_packet);

        if (user_data = NULL) {
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
        rv = construct_spp(*spp + i, data + data_written, data_this_packet, user_data, telecommand, seq_flag, spp_pkt_count + i, udp_pkt_num, packets_needed, i);

        if (rv != 0) {
            return rv;
        }

        *packets_made++;
    }

    return 0;
}

int free_spp_array(SPP *array, size_t arraylen) {
    for (int i = 0; i < arraylen; i++) {
        free(array[i].user_data);
    }
    
    free(array);

    return 0;
}

// Assume that data_field_len agrees with packet_data_length in the primary header
int serialise_spp(uint8_t *buf, size_t buflen, size_t data_field_len, const SPP *spp) {
    memset(buf, 0, buflen);

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

    buf[6] |= 0xff & (spp->secondary_header.udp_packet_num);
    buf[7] |= 0xf0 & (spp->secondary_header.udp_frag_count << 4);
    buf[7] |= 0x0f & (spp->secondary_header.udp_frag_num);

    memcpy(buf+SPP_HEADER_LEN, spp->user_data, data_field_len);

    return 0;
}

int deserialise_spp(const uint8_t *buf, SPP *spp) {
    spp->primary_header.packet_version_number = 0x07 & (buf[0] >> 5);
    
    spp->primary_header.pkt_id.packet_type = 0x01 & (buf[0] >> 4);
    spp->primary_header.pkt_id.secondary_header_present = 0x01 & (buf[0] >> 3);
    spp->primary_header.pkt_id.apid = 0x07ff & ((buf[0] << 8) | buf[1]);

    spp->primary_header.pkt_seq_ctrl.sequence_flags = 0x03 & (buf[2] >> 6);
    spp->primary_header.pkt_seq_ctrl.sequence_count = 0x3fff & ((buf[2] << 8) | buf[3]);

    spp->primary_header.packet_data_length = 0xffff & ((buf[4] << 8) | buf[5]);

    // Secondary header
    spp->secondary_header.udp_packet_num = 0xff & buf[6];
    spp->secondary_header.udp_frag_count = 0x0f & (buf[7] >> 4);
    spp->secondary_header.udp_frag_num = 0x0f & buf[7];

    // It is assumed that the buffer in spp->user_data is big enough to take the data
    // It's also assumed that the buffer provided is long enough to hold all the promised data
    memcpy(spp->user_data, buf + SPP_HEADER_LEN, spp->primary_header.packet_data_length + 1 - SPP_HEADER_LEN);

    return 0;
}
