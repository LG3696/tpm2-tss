/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018 Intel Corporation
 * All rights reserved.
 */

#ifndef TCTI_DEBUG_H
#define TCTI_DEBUG_H

#include <limits.h>

#include "tcti-common.h"
#include "util/io.h"

/*
 * longest possible conf string:
 * HOST_NAME_MAX + max char uint16 (5) + strlen ("host=,port=") (11)
 */
#define TCTI_DEBUG_CONF_MAX (_HOST_NAME_MAX + 16)

/*
 * joho todo maybe add default tcti module here (see default defines for mssim)
 */

#define TCTI_DEBUG_MAGIC 0x9cf45c5d7d9d0d3fULL

typedef struct {
    const char *child_tcti;
} tcti_debug_conf_t;

typedef struct {
    TSS2_TCTI_COMMON_CONTEXT common;
    TSS2_TCTI_CONTEXT *tcti_child;
} TSS2_TCTI_DEBUG_CONTEXT;

#endif /* TCTI_DEBUG_H */
