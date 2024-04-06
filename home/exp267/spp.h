#include <stdint.h>
#include <stddef.h>

#define SPP_PRIM_HEADER_LEN 6
#define SPP_SEC_HEADER_LEN 2
#define SPP_MTU 256
#define SPP_APID 1024 + 267

#define SPP_HEADER_LEN (SPP_PRIM_HEADER_LEN + SPP_SEC_HEADER_LEN)
#define SPP_MAX_DATA_LEN (SPP_MTU - SPP_HEADER_LEN)

// All fields have the first transmitted (left most) bit as most significant
// Field lengths are specified in comments

typedef enum _seq_flag {
    cont = 0,
    first = 1,
    last = 2,
    unseg = 3,
} seq_flag;

typedef enum _pkt_type {
    telecommand = 0,
    telemetry = 1,
} pkt_type;

// 13 bits
typedef struct _SPP_primary_packet_id {
    // 1 bit
    pkt_type packet_type;

    // 1 bit
    // 1 if the secondary header is present. 0 if the secondary header is not
    uint8_t secondary_header_present;

    // 11 bits
    // Application process ID
    uint16_t apid;
} SPP_primary_packet_id;

// 16 bits
typedef struct _SPP_primary_seq_ctrl {
    // 2 bits
    // See seq_flags enum
    seq_flag sequence_flags;

    // 14 bits
    // Can also have the packet name
    // Sequence is a global count per APID (does not reset for each segment)
    uint16_t sequence_count;
} SPP_primary_seq_ctrl;

// 6 bytes
typedef struct _SPP_primary_header {
    // 3 bits
    // Should be set to 000
    uint8_t packet_version_number;

    // 13 bits
    SPP_primary_packet_id pkt_id;

    // 16 bits
    SPP_primary_seq_ctrl pkt_seq_ctrl;

    // 16 bits
    // One less than the length (in bytes) of the overall packet
    uint16_t packet_data_length;
} SPP_primary_header;

// Must be an integer number of bytes
// 2 bytes total
typedef struct _SPP_secondary_header {
    // 8 bit field
    uint8_t udp_packet_num;

    // 4 bit field
    uint8_t udp_frag_count;

    // 4 bit field
    uint8_t udp_frag_num;
} SPP_secondary_header;

typedef struct _SPP {
    SPP_primary_header primary_header;

    SPP_secondary_header secondary_header;

    uint8_t* user_data;
} SPP;

int construct_spp(SPP *spp, const uint8_t *payload, size_t payloadlen, uint8_t *data_field, pkt_type packet_type, seq_flag seq_flags, uint16_t spp_pkt_num, uint8_t udp_pkt_num, uint8_t udp_frag_count, uint8_t udp_frag_num);

int serialise_spp(uint8_t *buf, size_t buflen, const SPP *spp);

int deserialise_spp(const uint8_t *buf, SPP *spp);

int fragment_data(SPP **spp, const uint8_t *data, size_t datalen, int *packets_made, uint16_t spp_pkt_count, uint8_t udp_pkt_num);

int free_spp_array(SPP *array, size_t arraylen);