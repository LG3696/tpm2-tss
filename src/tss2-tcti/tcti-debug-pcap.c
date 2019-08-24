/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2015 - 2018 Intel Corporation
 * All rights reserved.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>

#include "tcti-common.h"
#include "tcti-debug-pcap.h"

#define PCAP_TCP_HOST_PORT      50000   /* arbitrary */
#define PCAP_TCP_TPM_PORT       2321    /* port recognized by the TPM 2.0 protocol dissector */

/*
 * complies to pcap-ng
 * http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii#section_shb
 */

/* session header block */
typedef struct __attribute__((packed)) {
    uint32_t block_type;
    uint32_t block_len;
    uint32_t byte_order_magic;
    uint16_t major_version;
    uint16_t minor_version;
    uint64_t section_len;
    // options (optional)
    uint32_t block_len_cp;
} shb;


/* interface description block */
typedef struct __attribute__((packed)) {
    uint32_t block_type;
    uint32_t block_len;
    uint16_t link_type;
    uint16_t reserved;
    uint32_t snap_len;
    // options (optional)
    uint32_t block_len_cp;
} idb;


/* enhanced packet block */
typedef struct __attribute__((packed)) {
    uint32_t block_type;
    uint32_t block_len;
    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
    uint32_t captured_packet_len;
    uint32_t original_packet_len;
} epb_header;

typedef struct __attribute__((packed)) {
    // options (optional)
    uint32_t block_len_cp;
} epb_footer;

typedef struct __attribute__((packed)) {
    uint8_t source[6];
    uint8_t destination[6];
    uint16_t protocol;
} eth_header;

/* ipv4 packet */
typedef struct __attribute__((packed)) {
    uint8_t version_header_len;
    uint8_t type_of_service;
    uint16_t packet_len;
    uint16_t id;
    uint16_t flags;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t source;
    uint32_t destination;
    // options (optional)
} ip_header;

/* tcp segment */
typedef struct __attribute__((packed)) {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t seq_no;
    uint32_t ack_no;
    uint16_t header_len_flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;
    // options (optional)
} tcp_header;

#define PAD_TO_MULTIPLE_OF_4_BYTE(x)    (((x)-1)/4*4+4) * !!(x)

static int pcap_write_section_header_block(void *buf, size_t buf_len);  // joho static hier wirklich richtig?
static int pcap_write_interface_description_block(void *buf, size_t buf_len);
static int pcap_write_enhanced_packet_block(void* buf, size_t buf_len, uint64_t timestamp, const void* payload, size_t payload_len, int direction);
static int pcap_write_ethernet_frame(void* buf, size_t buf_len, const void* payload, size_t payload_len, int direction);
static int pcap_write_ip_packet(void* buf, size_t buf_len, const void* payload, size_t payload_len, int direction);
static int pcap_write_tcp_segment(void* buf, size_t buf_len, const void* payload, size_t payload_len, int direction);

static FILE *fp;

int pcap_init() {
    char *filename = getenv("TCTI_DEBUG_PATH"); // joho todo defines

    if (filename == NULL) {
        filename = "tpm2_tcti.pcapng";
    }

    if (!strcmp(filename, "stdout")) {
        fp = stdout;
    } else if (!strcmp(filename, "stderr")) {
        fp = stderr;
    } else {
        fp = fopen(filename, "wb");
    }

    char buf[sizeof(shb) + sizeof(idb)];
    size_t buf_len = sizeof(buf);
    size_t offset = 0;

    offset += pcap_write_section_header_block(buf, buf_len);
    offset += pcap_write_interface_description_block(buf + offset, buf_len - offset);

    fwrite(buf, 1, offset, fp);

    return 0;
}

int pcap_print(const void* payload, size_t payload_len, int direction) {
    if (!payload) {
        return TSS2_TCTI_RC_BAD_VALUE;  // joho todo return types
    }

    /* get required buffer size */
    size_t pdu_len = pcap_write_enhanced_packet_block(NULL, 0, 0, payload, payload_len, direction);
    
    char *buf = malloc(pdu_len);
    if (!buf) {
        return TSS2_BASE_RC_MEMORY;
    }

    struct timespec ts;      
    clock_gettime(CLOCK_REALTIME, &ts);

    pdu_len = pcap_write_enhanced_packet_block(buf, pdu_len, ts.tv_sec*1e6 + ts.tv_nsec/1e3, payload, payload_len, direction);

    fwrite(buf, 1, pdu_len, fp);
    fflush(fp);

    return pdu_len;
}

int pcap_deinit() {
    if (fp != stdout) {
        return fclose(fp);
    }

    return 0;
}


static int pcap_write_section_header_block(void *buf, size_t buf_len) {
    if (buf) {
        if (buf_len < sizeof(shb)) {
            return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
        }

        shb section_header = {
            .block_type = 0x0A0D0D0A,
            .block_len = sizeof(shb),
            .byte_order_magic = 0x1A2B3C4D,
            .major_version = 1,
            .minor_version = 0,
            .section_len = 0xFFFFFFFFFFFFFFFF,
            .block_len_cp = sizeof(shb),
        };

        memcpy(buf, &section_header, sizeof(shb));
    }

    return sizeof(shb);
}

static int pcap_write_interface_description_block(void *buf, size_t buf_len) {
    if (buf) {
        if (buf_len < sizeof(idb)) {
            return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
        }        

        idb interface_description = {
            .block_type = 1,
            .block_len = sizeof(idb),
            .link_type = 1,
            .reserved = 0,
            .snap_len = 0,
            .block_len_cp = sizeof(idb),
        };

        memcpy(buf, &interface_description, sizeof(idb));
    }

    return sizeof(ip_header);
}

static int pcap_write_enhanced_packet_block(void* buf, size_t buf_len, uint64_t timestamp, const void* payload, size_t payload_len, int direction) {
    size_t pdu_len, sdu_len, sdu_padded_len;

    /* get ethernet frame size */
    sdu_len = pcap_write_ethernet_frame(NULL, 0, payload, payload_len, direction);

    /* apply padding (multiple of 4 bytes) */
    sdu_padded_len = PAD_TO_MULTIPLE_OF_4_BYTE(sdu_len);

    pdu_len = sizeof(epb_header) + sdu_padded_len + sizeof(epb_footer);

    epb_header header = {
        .block_type = 6,
        // joho set dynamically!
        .block_len = pdu_len,
        .interface_id = 0,
        .timestamp_high = (timestamp >> 32) & 0xFFFFFFFF,
        .timestamp_low = timestamp & 0xFFFFFFFF,
        .captured_packet_len = sdu_len,
        .original_packet_len = sdu_len,
    };

    epb_footer footer = {
        .block_len_cp = pdu_len,
    };

    if (buf) {
        if (buf_len < pdu_len) {
            return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
        }

        memcpy(buf, &header, sizeof(epb_header));  
        buf += sizeof(epb_header);
        pcap_write_ethernet_frame(buf, sdu_len, payload, payload_len, direction);
        buf += sdu_len;
        memset(buf, 0, sdu_padded_len - sdu_len);
        buf += (sdu_padded_len - sdu_len);  // joho vll define für PADDING_NEEDED mit kommentar?
        memcpy(buf, &footer, sizeof(epb_footer));
    }

    return pdu_len;
}

static int pcap_write_ethernet_frame(void* buf, size_t buf_len, const void* payload, size_t payload_len, int direction) {
    size_t pdu_len, sdu_len;

    eth_header header = {
        .source[0] = 0,
        .source[1] = 0,
        .source[2] = 0,
        .source[3] = 0,
        .source[4] = 0,
        .source[5] = 0,
        .destination[0] = 0,
        .destination[1] = 0,
        .destination[2] = 0,
        .destination[3] = 0,
        .destination[4] = 0,
        .destination[5] = 0,
        .protocol = htons(0x0800), //TODO 0800?
    };

    /* get tcp frame size */
    sdu_len = pcap_write_ip_packet(NULL, 0, payload, payload_len, direction);

    pdu_len = sizeof(eth_header) + sdu_len;
    
    if (buf) {
        if (buf_len < pdu_len) {
            return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
        }

        memcpy(buf, &header, sizeof(eth_header));
        buf += sizeof(eth_header);
        pcap_write_ip_packet(buf, sdu_len, payload, payload_len, direction);
    }

    return pdu_len;
}



static int pcap_write_ip_packet(void* buf, size_t buf_len, const void* payload, size_t payload_len, int direction) {
    size_t pdu_len, sdu_len, sdu_padded_len;

    /* get tcp frame size */
    sdu_len = pcap_write_tcp_segment(NULL, 0, payload, payload_len, direction);

    /* apply padding (multiple of 4 bytes) */
    sdu_padded_len = PAD_TO_MULTIPLE_OF_4_BYTE(sdu_len);

    pdu_len = sizeof(ip_header) + sdu_padded_len;

    ip_header header = {
        .version_header_len = (4 << 4) | (sizeof(ip_header)/sizeof(uint32_t)),
        .type_of_service = 0,
        .packet_len = htons(pdu_len),
        .id = htons(0),
        .flags = htons(0x4000), // don't fragment
        .time_to_live = 0xFF,
        .protocol = 6,
        .checksum = htons(0),
        .source = htonl(0),
        .destination = htonl(0),
    };

    if (buf) {
        if (buf_len < pdu_len) {
            return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
        }

        memcpy(buf, &header, sizeof(ip_header));
        buf += sizeof(ip_header);
        pcap_write_tcp_segment(buf, sdu_len, payload, payload_len, direction);
        buf += payload_len;
        memset(buf, 0, sdu_padded_len - sdu_len);
    }

    return pdu_len;
}

static int pcap_write_tcp_segment(void* buf, size_t buf_len, const void* payload, size_t payload_len, int direction) {
    static uint32_t sequence_no_host_to_tpm = 0;
    static uint32_t sequence_no_tpm_to_host = 0;
    size_t pdu_len, payload_padded_len;

    /* apply padding (multiple of 4 bytes) */
    payload_padded_len = PAD_TO_MULTIPLE_OF_4_BYTE(payload_len);

    pdu_len = sizeof(tcp_header) + payload_padded_len;

    tcp_header header = {
        .ack_no = htonl(0),
        .header_len_flags = htons((sizeof(tcp_header)/sizeof(uint32_t) << 12) | 0x010), // joho todo introduce a define for sizeof(...)/sizeof(uint32_t)
        .window_size = htons(0xAAAA),
        .checksum = htons(0), // joho todo
        .urgent_ptr = htons(0),
    };

    if (direction == PCAP_DIR_HOST_TO_TPM) {
        header.source_port = htons(PCAP_TCP_HOST_PORT);
        header.destination_port = htons(PCAP_TCP_TPM_PORT);
        header.seq_no = htonl(sequence_no_host_to_tpm);
    } else if (direction == PCAP_DIR_TPM_TO_HOST) {
        header.source_port = htons(PCAP_TCP_TPM_PORT);
        header.destination_port = htons(PCAP_TCP_HOST_PORT);
        header.seq_no = htonl(sequence_no_tpm_to_host);
    }


    if (buf && payload) {
        if (buf_len < pdu_len) {
            return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
        }

        memcpy(buf, &header, sizeof(tcp_header));
        buf += sizeof(tcp_header);
        memcpy(buf, payload, payload_len);
        buf += payload_len;
        memset(buf, 0, payload_padded_len - payload_len);

        if (direction == PCAP_DIR_HOST_TO_TPM) {
            sequence_no_host_to_tpm += payload_padded_len;
        } else if (direction == PCAP_DIR_TPM_TO_HOST) {
            sequence_no_tpm_to_host += payload_padded_len;
        }
    }

    return pdu_len;
}