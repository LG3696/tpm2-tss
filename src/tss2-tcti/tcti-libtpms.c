/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019 Infineon Technologies AG
 * All rights reserved.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "tss2_tcti.h"
#include "tss2_tcti_libtpms.h"
#include "tss2_mu.h"
#include "tcti-common.h"
#include "tcti-libtpms.h"
#define LOGMODULE tcti
#include "util/log.h"

#include <string.h>

#include <libtpms/tpm_library.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_memory.h>

/*
 * There can only be one libtpms TPM per executable. Its locality is stored
 * globally due to library constraints.
 * TODO add an API function SetLocality to libtpms OR
 *      add a user-defined data parameter to the callbacks
 */
static uint8_t locality;

/*
 * This function wraps the "up-cast" of the opaque TCTI context type to the
 * type for the libtpms TCTI context. The only safe-guard we have to ensure
 * this operation is possible is the magic number for the libtpms TCTI context.
 * If passed a NULL context, or the magic number check fails, this function
 * will return NULL.
 */
TSS2_TCTI_LIBTPMS_CONTEXT*
tcti_libtpms_context_cast (TSS2_TCTI_CONTEXT *tcti_ctx)
{
    if (tcti_ctx != NULL && TSS2_TCTI_MAGIC (tcti_ctx) == TCTI_LIBTPMS_MAGIC) {
        return (TSS2_TCTI_LIBTPMS_CONTEXT*)tcti_ctx;
    }
    return NULL;
}
/*
 * This function down-casts the libtpms TCTI context to the common context
 * defined in the tcti-common module.
 */
TSS2_TCTI_COMMON_CONTEXT*
tcti_libtpms_down_cast (TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms)
{
    if (tcti_libtpms == NULL) {
        return NULL;
    }
    return &tcti_libtpms->common;
}

TSS2_RC
tcti_libtpms_transmit (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t command_size,
    const uint8_t *command_buffer)
{
    TSS2_RC rc = TSS2_RC_SUCCESS;
    TPM_RESULT res;

    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms = tcti_libtpms_context_cast (tctiContext);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_libtpms_down_cast (tcti_libtpms);

    if (tcti_libtpms == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    rc = tcti_common_transmit_checks (tcti_common, command_buffer);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }
    LOGBLOB_DEBUG (command_buffer,
                   command_size,
                   "sending %zu byte command buffer:",
                   command_size);

    res = TPMLIB_Process(&tcti_libtpms->response_buffer,
                         &tcti_libtpms->response_size,
                         &tcti_libtpms->response_buffer_size,
                         (unsigned char *) command_buffer,
                         command_size);

    if (res != TPM_SUCCESS) {
        LOG_ERROR ("could not transmit command to libtpms. TPMLIB_Process() "
                    "returned %d.", res);
        return TSS2_TCTI_RC_IO_ERROR;
    }

    tcti_common->state = TCTI_STATE_RECEIVE;
    return TSS2_RC_SUCCESS;
}

TSS2_RC
tcti_libtpms_receive (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *response_size,
    uint8_t *response_buffer,
    int32_t timeout)
{
    (void) timeout;

    TSS2_RC rc;
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms = tcti_libtpms_context_cast (tctiContext);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_libtpms_down_cast (tcti_libtpms);

    if (tcti_libtpms == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    rc = tcti_common_receive_checks (tcti_common, response_size);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    if (response_size == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    if (response_buffer == NULL) {
        *response_size = tcti_libtpms->response_size;
        return TSS2_RC_SUCCESS;
    }

    /* TCTI_PARTIAL_READ is not supported */
    if (*response_size < tcti_libtpms->response_size) {
        *response_size = tcti_libtpms->response_size;
        return TSS2_BASE_RC_INSUFFICIENT_BUFFER;
    }

    *response_size = tcti_libtpms->response_size;
    memcpy (response_buffer, tcti_libtpms->response_buffer,
            tcti_libtpms->response_size);

    tcti_common->state = TCTI_STATE_TRANSMIT;

    return TPM2_RC_SUCCESS;
}

void
tcti_libtpms_finalize (
    TSS2_TCTI_CONTEXT *tctiContext)
{
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms = tcti_libtpms_context_cast (tctiContext);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_libtpms_down_cast (tcti_libtpms);

    if (tcti_libtpms == NULL) {
        return;
    }
    free (tcti_libtpms->response_buffer);
    tcti_libtpms->response_size = 0;
    tcti_libtpms->response_buffer_size = 0;
    tcti_common->state = TCTI_STATE_FINAL;

    /* Power off TPM */
    TPMLIB_Terminate();
}

TSS2_RC
tcti_libtpms_cancel (
    TSS2_TCTI_CONTEXT *tctiContext)
{
    /* The libtpms API provides a cancel function: TPMLIB_CancelCommand().
     * However, the function to process TPM commands TPMLIB_Process() is
     * blocking anyway and returns the response right away, so cancelling does
     * not really make sense.
     */
    (void)(tctiContext);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC
tcti_libtpms_get_poll_handles (
    TSS2_TCTI_CONTEXT *tctiContext,
    TSS2_TCTI_POLL_HANDLE *handles,
    size_t *num_handles)
{
    (void)(tctiContext);
    (void)(handles);
    (void)(num_handles);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

/* Locality callback for libtpms. Does not distinguish TCTI contexts. */
static TPM_RESULT tcti_libtpms_get_locality (
    TPM_MODIFIER_INDICATOR *localityModifer,
    uint32_t tpm_number)
{
    (void) tpm_number;

    LOG_TRACE("Returning locality %d to the libtpms TPM.", locality);
    *localityModifer = locality;
    return TPM_SUCCESS;
}

TSS2_RC
tcti_libtpms_set_locality (
    TSS2_TCTI_CONTEXT *tctiContext,
    uint8_t loc)
{
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms = tcti_libtpms_context_cast (tctiContext);
    TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_libtpms_down_cast (tcti_libtpms);

    /*
     * The locality has to be set globally. This is redundant but necessary
     * due to library constraints.
     */
    LOG_DEBUG("Setting the locality to %d.", loc);
    tcti_common->locality = loc;
    locality = loc;

    return TSS2_RC_SUCCESS;
}

TSS2_RC
Tss2_Tcti_Libtpms_Init (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *size,
    const char *conf)
{
    (void) conf;

    TPM_RESULT res;
    TSS2_TCTI_LIBTPMS_CONTEXT *tcti_libtpms;
    TSS2_TCTI_COMMON_CONTEXT *tcti_common;

    if (tctiContext == NULL && size == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    } else if (tctiContext == NULL) {
        *size = sizeof (TSS2_TCTI_LIBTPMS_CONTEXT);
        return TSS2_RC_SUCCESS;
    }

    /* Init TCTI context */
    TSS2_TCTI_MAGIC (tctiContext) = TCTI_LIBTPMS_MAGIC;
    TSS2_TCTI_VERSION (tctiContext) = TCTI_VERSION;
    TSS2_TCTI_TRANSMIT (tctiContext) = tcti_libtpms_transmit;
    TSS2_TCTI_RECEIVE (tctiContext) = tcti_libtpms_receive;
    TSS2_TCTI_FINALIZE (tctiContext) = tcti_libtpms_finalize;
    TSS2_TCTI_CANCEL (tctiContext) = tcti_libtpms_cancel;
    TSS2_TCTI_GET_POLL_HANDLES (tctiContext) = tcti_libtpms_get_poll_handles;
    TSS2_TCTI_SET_LOCALITY (tctiContext) = tcti_libtpms_set_locality;
    TSS2_TCTI_MAKE_STICKY (tctiContext) = tcti_make_sticky_not_implemented;
    tcti_libtpms = tcti_libtpms_context_cast (tctiContext);
    tcti_common = tcti_libtpms_down_cast (tcti_libtpms);
    tcti_common->state = TCTI_STATE_TRANSMIT;
    memset (&tcti_common->header, 0, sizeof (tcti_common->header));

    tcti_libtpms->response_buffer = NULL;
    tcti_libtpms->response_buffer_size = 0;
    tcti_libtpms->response_size = 0;

    /* Set TPM version to 2.0 */
    res = TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2);
    if (res != TPM_SUCCESS) {
        LOG_ERROR("TPMLIB_ChooseTPMVersion() failed: 0x%02x\n", res);
        return TSS2_TCTI_RC_IO_ERROR;
    }

    /* Register locality callback and set locality to 3 */
    struct libtpms_callbacks callbacks = {
        .sizeOfStruct = sizeof(struct libtpms_callbacks),
        .tpm_io_getlocality = tcti_libtpms_get_locality,
    };
    res = TPMLIB_RegisterCallbacks(&callbacks);
    if (res != TPM_SUCCESS) {
        LOG_ERROR("TPMLIB_RegisterCallbacks() returned an unexpected value: 0x%02x\n", res);
        return TSS2_TCTI_RC_IO_ERROR;
    }
    tcti_libtpms_set_locality(tctiContext, 3);

    /* Power on TPM */
    res = TPMLIB_MainInit();
    if (res) {
        LOG_ERROR("TPMLIB_MainInit() failed: 0x%02x\n", res);
        return TSS2_TCTI_RC_IO_ERROR;
    }

    return TSS2_RC_SUCCESS;
}

const TSS2_TCTI_INFO tss2_tcti_info = {
    .version = TCTI_VERSION,
    .name = "tcti-libtpms",
    .description = "TCTI module for communication with Linux kernel interface.",
    .config_help = "Path to TPM character libtpms. Default value is: "
        "TCTI_LIBTPMS_DEFAULT",
    .init = Tss2_Tcti_Libtpms_Init,
};

const TSS2_TCTI_INFO*
Tss2_Tcti_Info (void)
{
    return &tss2_tcti_info;
}
