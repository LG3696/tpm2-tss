/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018 Intel Corporation
 * All rights reserved.
 */
#ifndef TCTI_DEBUG_PCAP_H
#define TCTI_DEBUG_PCAP_H

#include <stddef.h>

#define PCAP_DIR_HOST_TO_TPM        0
#define PCAP_DIR_TPM_TO_HOST        1

int pcap_init(void);
int pcap_print(const void* payload, size_t payload_len, int direction);
int pcap_deinit(void);

#endif /* TCTI_DEBUG_PCAP_H */