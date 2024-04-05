#include "spp.h"

#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

int fragment_data(SPP **spp, const uint8_t *data, size_t datalen) {
    return 0;
}

// TODO - Checks that non byte aligned fields are safely truncated?
int construct_spp(SPP *spp, const uint8_t *payload, size_t payloadlen, uint8_t *data_field, uint8_t packet_type, seq_flag seq_flags, uint16_t spp_pkt_num, uint8_t udp_pkt_num, uint8_t udp_frag_count, uint8_t udp_frag_num) {
    if (payloadlen > SPP_MAX_DATA_LEN) {
        fprintf(stderr, "Data of %ld bytes does not fit into payload field\n", payloadlen);
        return 1;
    }
    
    // Primary header
    spp->primary_header.packet_version_number = 0;

    spp->primary_header.pkt_id.packet_type = packet_type;
    spp->primary_header.pkt_id.secondary_header_present = 1;
    spp->primary_header.pkt_id.apid = SPP_APID;

    spp->primary_header.pkt_seq_ctrl.sequence_flags = seq_flags;
    spp->primary_header.pkt_seq_ctrl.sequence_count = spp_pkt_num;

    // data length field is one less than the total number of bytes
    spp->primary_header.packet_data_length = payloadlen + SPP_HEADER_LEN - 1;

    // Secondary header
    spp->secondary_header.udp_packet_num = udp_pkt_num;
    spp->secondary_header.udp_frag_count = udp_frag_count;
    spp->secondary_header.udp_frag_num = udp_frag_num;

    // Payload
    memcpy(data_field, payload, payloadlen);
    spp->user_data = data_field;

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

static int main(int argc, char **argv) {
    SPP spp, de_spp;
    uint8_t data[SPP_MAX_DATA_LEN], de_data[SPP_MAX_DATA_LEN];
    uint8_t message[] = "Hello world!";

    de_spp.user_data = de_data;

    uint8_t buf[SPP_MTU];

    construct_spp(&spp, message, sizeof(message), data, 0, first, 0, 0, 1, 1);

    serialise_spp(buf, sizeof(buf), sizeof(data), &spp);
    deserialise_spp(buf, &de_spp);

    printf("%s\n", de_spp.user_data);

    return 0;
}