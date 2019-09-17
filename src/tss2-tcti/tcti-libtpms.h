/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019 Infineon Technologies AG
 * All rights reserved.
 */
#ifndef TCTI_LIBTPMS_H
#define TCTI_LIBTPMS_H

#include "tcti-common.h"

#define TCTI_LIBTPMS_MAGIC 0x496e66696e656f6eULL

#define TCTI_LIBTPMS_MAX_RESPONSE_SIZE 4096

typedef struct {
    TSS2_TCTI_COMMON_CONTEXT common;
    uint8_t *response_buffer;
    uint32_t response_buffer_size;
    uint32_t response_size;
} TSS2_TCTI_LIBTPMS_CONTEXT;

#endif /* TCTI_LIBTPMS_H */
