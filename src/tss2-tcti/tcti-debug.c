/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2015 - 2018 Intel Corporation
 * All rights reserved.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#ifndef _WIN32              // joho todo check includes
#include <sys/time.h>
#include <unistd.h>
#endif

#include <dlfcn.h>

#include "tss2_mu.h"

#include "tcti-debug.h"
#include "tcti-common.h"
#include "tss2_tctildr.h"
#define LOGMODULE tcti
#include "util/log.h"

#include "tss2_tcti.h"
#ifdef _WIN32
#include "tss2_tcti_tbs.h"
#else /* _WIN32 */
#include "tss2_tcti_device.h"
#endif /* else */

#include "tcti-debug-pcap.h"

/*
 * This function wraps the "up-cast" of the opaque TCTI context type to the
 * type for the debug TCTI context. The only safeguard we have to ensure this
 * operation is possible is the magic number in the debug TCTI context.
 * If passed a NULL context, or the magic number check fails, this function
 * will return NULL.
 */
TSS2_TCTI_DEBUG_CONTEXT*
tcti_debug_context_cast (TSS2_TCTI_CONTEXT *tcti_ctx)
{
    if (tcti_ctx != NULL && TSS2_TCTI_MAGIC (tcti_ctx) == TCTI_DEBUG_MAGIC) {
        return (TSS2_TCTI_DEBUG_CONTEXT*)tcti_ctx;
    }
    return NULL;
}

/*
 * This function down-casts the debug TCTI context to the common context
 * defined in the tcti-common module.
 */
TSS2_TCTI_COMMON_CONTEXT*
tcti_debug_down_cast (TSS2_TCTI_DEBUG_CONTEXT *tcti_debug)
{
    if (tcti_debug == NULL) {
        return NULL;
    }
    return &tcti_debug->common;
}

TSS2_RC
tcti_debug_transmit (
    TSS2_TCTI_CONTEXT *tcti_ctx,
    size_t size,
    const uint8_t *cmd_buf)
{
    TSS2_TCTI_DEBUG_CONTEXT *tcti_debug = tcti_debug_context_cast (tcti_ctx);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_debug_down_cast (tcti_debug);
    TSS2_RC rc;

    if (tcti_debug == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    rc = tcti_common_transmit_checks (tcti_common, cmd_buf);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    LOGBLOB_DEBUG (cmd_buf,
                   size,
                   "sending %zu byte command buffer:",
                   size);

    // joho TODO return code -> Warning
    rc = pcap_print(cmd_buf, size, PCAP_DIR_HOST_TO_TPM);

    rc = Tss2_Tcti_Transmit(tcti_debug->tcti_child, size, cmd_buf);

    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR("Calling TCTI transmit of child TCTI module");
        return rc;
    }

    tcti_common->state = TCTI_STATE_RECEIVE;
    return TSS2_RC_SUCCESS;
}

// joho implement receive properly (e.g. partial reads)?
//      well, should not be necessary (job of overlaying app), right?
//      alas, wireshark will probably not be able to dissect partial responses
// joho TODO if the responsebuffer is NULL, we need to set repsonsebuffer size,
//           see mssim
TSS2_RC
tcti_debug_receive (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *response_size,
    unsigned char *response_buffer,
    int32_t timeout)
{
    TSS2_TCTI_DEBUG_CONTEXT *tcti_debug = tcti_debug_context_cast (tctiContext);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_debug_down_cast (tcti_debug);
    TSS2_RC rc;

    if (tcti_debug == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    rc = tcti_common_receive_checks (tcti_common, response_size);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    LOGBLOB_DEBUG(response_buffer, *response_size, "Response Received");

    // joho TODO return code
    rc = pcap_print(response_buffer, *response_size, PCAP_DIR_TPM_TO_HOST);

    // jodo TODO what if it's a partial read?
    // in this case we would get TSS2_TCTI_RC_TRY_AGAIN (and maybe other rcs?)
    // would this lead to incomplete PCAP blocks? (but wouldn't this also be what we want, a realistic log?)
    // in any case, we'd pobably need sth like tcti_common->partial = true;
    // look for tests with parthial read.
    rc = Tss2_Tcti_Receive(tcti_debug->tcti_child, response_size, response_buffer, timeout);

    tcti_common->state = TCTI_STATE_TRANSMIT;
    return rc;
}

TSS2_RC
tcti_debug_cancel (
    TSS2_TCTI_CONTEXT *tctiContext)
{
    TSS2_TCTI_DEBUG_CONTEXT *tcti_debug = tcti_debug_context_cast (tctiContext);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_debug_down_cast (tcti_debug);
    TSS2_RC rc;

    if (tcti_debug == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    rc = tcti_common_cancel_checks (tcti_common);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    /*
     * joho TODO log cancelling(?), see mssim platform command
     */

    rc = Tss2_Tcti_Cancel(tcti_debug->tcti_child);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    tcti_common->state = TCTI_STATE_TRANSMIT;
    return rc;
}

TSS2_RC
tcti_debug_set_locality (
    TSS2_TCTI_CONTEXT *tctiContext,
    uint8_t locality)
{
    TSS2_TCTI_DEBUG_CONTEXT *tcti_debug = tcti_debug_context_cast (tctiContext);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_debug_down_cast (tcti_debug);
    TSS2_RC rc;

    if (tcti_debug == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }

    rc = tcti_common_set_locality_checks (tcti_common);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    /*
     * joho TODO log setting locality? see mssim platform
     * I guess this is not a real transmission but the locality is a value
     * in the header of the following TPM commands
     */

    rc = Tss2_Tcti_SetLocality(tcti_debug->tcti_child, locality);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    tcti_common->locality = locality;
    return rc;
}

TSS2_RC
tcti_debug_get_poll_handles (
    TSS2_TCTI_CONTEXT *tctiContext,
    TSS2_TCTI_POLL_HANDLE *handles,
    size_t *num_handles)
{
#ifdef TCTI_ASYNC
    TSS2_TCTI_DEBUG_CONTEXT *tcti_debug = tcti_debug_context_cast (tctiContext);

    if (tcti_debug == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }

    return Tss2_Tcti_GetPollHandles (tcti_debug->tcti_child, handles,
                                     num_handles);
#else
    (void)(tctiContext);
    (void)(handles);
    (void)(num_handles);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
#endif
}

void
tcti_debug_finalize(
    TSS2_TCTI_CONTEXT *tctiContext)
{
    TSS2_TCTI_DEBUG_CONTEXT *tcti_debug = tcti_debug_context_cast (tctiContext);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_debug_down_cast (tcti_debug);

    if (tcti_debug == NULL) {
        return;
    }

    pcap_deinit();

    // joho todo free tcti child?

    Tss2_Tcti_Finalize (tcti_debug->tcti_child);

    tcti_common->state = TCTI_STATE_FINAL;
}

/*
 * joho todo doc (everything)
 */
TSS2_RC
Tss2_Tcti_Debug_Set_Child (TSS2_TCTI_CONTEXT *tcti_ctx,
                           TSS2_TCTI_CONTEXT *tcti_child)
{
    TSS2_TCTI_DEBUG_CONTEXT *debug_tcti = tcti_debug_context_cast (tcti_ctx);

    if (debug_tcti != NULL && tcti_child != NULL) {
        debug_tcti->tcti_child = tcti_child;
        return TSS2_RC_SUCCESS;
    }

    // joho what with the maybe already allocated memory?
    // joho generally: both this tcti and child tcti have to be freed somewhere
    //                 -> deinit?
    return TSS2_TCTI_RC_BAD_CONTEXT;
}

/*
 * This is an implementation of the standard TCTI initialization function for
 * this module.
 */
TSS2_RC
Tss2_Tcti_Debug_Init (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *size,
    const char *conf)
{
    TSS2_TCTI_DEBUG_CONTEXT *tcti_debug = (TSS2_TCTI_DEBUG_CONTEXT*) tctiContext;
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_debug_down_cast (tcti_debug);
    TSS2_RC rc = TSS2_RC_SUCCESS;

    if (tctiContext == NULL && size == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    } else if (tctiContext == NULL) {
        *size = sizeof (TSS2_TCTI_DEBUG_CONTEXT);
        return TSS2_RC_SUCCESS;
    }

    if (conf == NULL) {
        LOG_TRACE ("tctiContext: 0x%" PRIxPTR ", size: 0x%" PRIxPTR ""
                   " no configuration will be used.",
                   (uintptr_t)tctiContext, (uintptr_t)size);
    } else {
        LOG_TRACE ("tctiContext: 0x%" PRIxPTR ", size: 0x%" PRIxPTR ", conf: %s",
                   (uintptr_t)tctiContext, (uintptr_t)size, conf);
    }

    rc = Tss2_TctiLdr_Initialize_Exclude(conf,
                                         &tcti_debug->tcti_child,
                                         "libtss2-tcti-debug.so");
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Error loading TCTI: %s", conf);
        rc = TSS2_TCTI_RC_BAD_VALUE;
        goto error;
    }




    TSS2_TCTI_MAGIC (tcti_common) = TCTI_DEBUG_MAGIC;
    TSS2_TCTI_VERSION (tcti_common) = TCTI_VERSION;
    TSS2_TCTI_TRANSMIT (tcti_common) = tcti_debug_transmit;
    TSS2_TCTI_RECEIVE (tcti_common) = tcti_debug_receive;
    TSS2_TCTI_FINALIZE (tcti_common) = tcti_debug_finalize;
    TSS2_TCTI_CANCEL (tcti_common) = tcti_debug_cancel;
    TSS2_TCTI_GET_POLL_HANDLES (tcti_common) = tcti_debug_get_poll_handles;
    TSS2_TCTI_SET_LOCALITY (tcti_common) = tcti_debug_set_locality;
    TSS2_TCTI_MAKE_STICKY (tcti_common) = tcti_make_sticky_not_implemented;
    tcti_common->state = TCTI_STATE_TRANSMIT;
    tcti_common->locality = 3;
    memset (&tcti_common->header, 0, sizeof (tcti_common->header));

    pcap_init();    //TODO joho error checking

    return TSS2_RC_SUCCESS;

error:
    return rc;
}

/* public info structure */
const TSS2_TCTI_INFO tss2_tcti_info = {
    .version = TCTI_VERSION,
    .name = "tcti-debug",
    .description = "TCTI module for logging TPM commands in pcapng format.",
    .config_help = "The child tcti module and its config string: <name>:<conf>",
    .init = Tss2_Tcti_Debug_Init,
};

const TSS2_TCTI_INFO*
Tss2_Tcti_Info (void)
{
    return &tss2_tcti_info;
}
