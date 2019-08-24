/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2015 - 2018, Intel Corporation // joho todo update all licences
 * All rights reserved.
 */
#ifndef TSS2_TCTI_DEBUG_H
#define TSS2_TCTI_DEBUG_H

#include "tss2_tcti.h"

#ifdef __cplusplus
extern "C" {
#endif

TSS2_RC Tss2_Tcti_Debug_Set_Child (
    TSS2_TCTI_CONTEXT *tcti_ctx,
    TSS2_TCTI_CONTEXT *tcti_child);

TSS2_RC Tss2_Tcti_Debug_Init (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *size,
    const char *conf);

#ifdef __cplusplus
}
#endif

#endif /* TSS2_TCTI_DEBUG_H */
