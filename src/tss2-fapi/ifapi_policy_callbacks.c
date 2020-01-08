/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2018-2019, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>

#include "fapi_util.h"
#include "fapi_policy.h"
#include "ifapi_helpers.h"
#include "fapi_crypto.h"
#include "ifapi_policy_instantiate.h"
#include "ifapi_policyutil_execute.h"
#include "ifapi_policy_execute.h"
#include "ifapi_policy_callbacks.h"
#include "tss2_mu.h"

#define LOGMODULE fapi
#include "util/log.h"
#include "util/aux_util.h"

static void
get_nv_auth_object(
    IFAPI_OBJECT *nv_object,
    ESYS_TR nv_index,
    IFAPI_OBJECT *auth_object,
    ESYS_TR *auth_index)
{
    if (nv_object->misc.nv.public.nvPublic.attributes & TPMA_NV_PPREAD) {
        ifapi_init_hierarchy_object(auth_object, ESYS_TR_RH_PLATFORM);
        *auth_index = ESYS_TR_RH_PLATFORM;
    } else {
        if (nv_object->misc.nv.public.nvPublic.attributes & TPMA_NV_OWNERREAD) {
            ifapi_init_hierarchy_object(auth_object, ESYS_TR_RH_OWNER);
            *auth_index = ESYS_TR_RH_OWNER;
        } else {
            *auth_index = nv_index;
            *auth_object = *nv_object;
        }
    }
}

/** Get public data of a key from keystore.
 *
 * @parm[in] path The relative path of the key.
 * @parm[out] public The caller allocated public structure.
 * @parm[in,out] ctx The context to access io and keystore module and to store
*                    the io state.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be loaded.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_FAPI_RC_BAD_TEMPLATE If the loaded template is not
 *         appropriate for this operation.
 */
TSS2_RC
ifapi_get_key_public(
    const char *path,
    TPMT_PUBLIC *public,
    void *ctx)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    IFAPI_OBJECT object;
    FAPI_CONTEXT *context = ctx;

    switch (context->io_state) {
    statecase(context->io_state, IO_INIT)
        /* Prepare the loading of the object. */
        r = ifapi_keystore_load_async(&context->keystore, &context->io, path);
        return_if_error2(r, "Could not open: %s", path);
        fallthrough;

    statecase(context->io_state, IO_ACTIVE)
        /* Finalize or retry the reading and check the object type */
        r = ifapi_keystore_load_finish(&context->keystore, &context->io,
                                       &object);
        return_try_again(r);
        return_if_error(r, "read_finish failed");

        switch(object.objectType) {
        case IFAPI_KEY_OBJ:
            *public = object.misc.key.public.publicArea;
            break;
        case IFAPI_EXT_PUB_KEY_OBJ:
            *public = object.misc.ext_pub_key.public.publicArea;
            break;
        default:
            goto_error(r, TSS2_FAPI_RC_BAD_TEMPLATE, "Object %s is not a key.",
                       cleanup, path);
        }
        break;

    statecasedefault_error(context->state, r, cleanup);
    }

 cleanup:
    context->io_state = IO_INIT;
    ifapi_cleanup_ifapi_object(&object);
    return r;
}

/** Get TPM name of an object from  key keystore.
 *
 * @parm[in] path The relative path of the object.
 * @parm[out] name The caller allocate public structure.
 * @parm[in,out] ctx The context to access io and keystore module and to store
 *               the io state.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be loaded.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_FAPI_RC_BAD_TEMPLATE If the loaded template is not
 *         appropriate for this operation.
 */
TSS2_RC
ifapi_get_object_name(
    const char *path,
    TPM2B_NAME *name,
    void *ctx)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    IFAPI_OBJECT object;
    FAPI_CONTEXT *context = ctx;

    switch (context->io_state) {
    statecase(context->io_state, IO_INIT)
        /* Prepare the loading of the object. */
        r = ifapi_keystore_load_async(&context->keystore, &context->io, path);
        return_if_error2(r, "Could not open: %s", path);
        fallthrough;

    statecase(context->io_state, IO_ACTIVE)
        /* Finalize or retry the reading and check the object type */
        r = ifapi_keystore_load_finish(&context->keystore, &context->io,
                                       &object);
        return_try_again(r);
        return_if_error(r, "read_finish failed");

        switch(object.objectType) {
        case IFAPI_KEY_OBJ:
            r = ifapi_get_name(&object.misc.key.public.publicArea,
                               (TPM2B_NAME *)name);
            break;
        case IFAPI_EXT_PUB_KEY_OBJ:
            r = ifapi_get_name(&object.misc.ext_pub_key.public.publicArea,
                               (TPM2B_NAME *)name);
            break;
        case IFAPI_NV_OBJ:
            r = ifapi_nv_get_name(&object.misc.nv.public, name);
            break;
        default:
            goto_error(r, TSS2_FAPI_RC_BAD_TEMPLATE, "Invalid object %s.",
                       cleanup, path);
        }
        goto_if_error(r, "Get object name.", cleanup);
        break;

    statecasedefault(context->state);
    }

 cleanup:
    ifapi_cleanup_ifapi_object(&object);
    return r;
}

/** Get public data of a NV object from keystore.
 *
 * @parm[in] path The relative path of the NV object.
 * @parm[out] public The caller allocated public structure.
 * @parm[in,out] ctx The context to access io and keystore module and to store
     *           the io state.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_FAPI_RC_IO_ERROR: if the data cannot be loaded.
 * @retval TSS2_FAPI_RC_MEMORY: if the FAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_FAPI_RC_BAD_TEMPLATE If the loaded template is not
 *         appropriate for this operation.
 */
TSS2_RC
ifapi_get_nv_public(
    const char *path,
    TPM2B_NV_PUBLIC *nv_public,
    void *ctx)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    IFAPI_OBJECT object;
    FAPI_CONTEXT *context = ctx;

    switch (context->io_state) {
    statecase(context->io_state, IO_INIT)
        /* Prepare the loading of the object. */
        r = ifapi_keystore_load_async(&context->keystore, &context->io, path);
        return_if_error2(r, "Could not open: %s", path);
        fallthrough;

    statecase(context->io_state, IO_ACTIVE)
        /* Finalize or retry the reading and check the object type */
        r = ifapi_keystore_load_finish(&context->keystore, &context->io,
                                       &object);
        return_try_again(r);
        return_if_error(r, "read_finish failed");

        if (object.objectType != IFAPI_NV_OBJ) {
            goto_error(r, TSS2_FAPI_RC_BAD_TEMPLATE, "Object %s is not a key.",
                       cleanup, path);
        }

        *nv_public = object.misc.nv.public;
        context->io_state = IO_INIT;
        break;

    statecasedefault(context->state);
    }

 cleanup:
    ifapi_cleanup_ifapi_object(&object);
    return r;
}

/** Read values of PCR registers and clear selection.
 *
 * @parm[in,out] pcr_select The registers to be read (bank selection from profile).
 * @parm[in,out] pcr_selection The registers to be read (with bank selection).
 * @parm[out] pcr_values The callee-allocated public structure.
 * @parm[in,out] ctx The context to access io and keystore module and to store
 *               the io state.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_CONTEXT: if esysContext corruption is detected.
 * @retval TSS2_ESYS_RC_MEMORY: if the ESAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_ESYS_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_ESYS_RC_TRY_AGAIN: if the timeout counter expires before the
 *         TPM response is received.
 * @retval TSS2_ESYS_RC_INSUFFICIENT_RESPONSE: if the TPM's response does not
 *         at least contain the tag, response length, and response code.
 * @retval TSS2_ESYS_RC_RSP_AUTH_FAILED: if the response HMAC from the TPM did
 *         not verify.
 * @retval TSS2_ESYS_RC_MALFORMED_RESPONSE: if the TPM's response is corrupted.
 *         internal operations or return parameters.
 *         appropriate for this operation.
 */
TSS2_RC
ifapi_read_pcr(
    TPMS_PCR_SELECT *pcr_select,
    TPML_PCR_SELECTION *pcr_selection,
    TPML_PCRVALUES **pcr_values,
    void *ctx)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    FAPI_CONTEXT *context = ctx;
    UINT32 update_counter;
    TPML_PCR_SELECTION *out_selection = NULL;
    TPML_PCR_SELECTION *profile_selection;
    TPML_DIGEST *pcr_digests = NULL;
    size_t i, pcr, n_pcrs = 0, i_pcr;

    switch (context->io_state) {
    statecase(context->io_state, IO_INIT)
        if (pcr_select->sizeofSelect) {
            if (pcr_selection->count) {
                /* If pcr_select is used pcr_selection can't be initialized */
                return_error(TSS2_FAPI_RC_BAD_TEMPLATE,
                             "Policy PCR: pcr_selection can't be used if pcr_selection is used.");
            }
            /* Determine hash alg */
            profile_selection = &context->profiles.default_profile.pcr_selection;
            for (i = 0; i < profile_selection->count; i++) {
                for (pcr = 0; pcr < TPM2_MAX_PCRS; pcr++) {
                    uint8_t byte_idx = pcr / 8;
                    uint8_t flag = 1 << (pcr % 8);
                    /* Check whether PCR is used. */
                    if (flag & profile_selection->pcrSelections[i].pcrSelect[byte_idx] &&
                        flag & pcr_select->pcrSelect[byte_idx]) {
                        pcr_selection->pcrSelections[0].hash = profile_selection->pcrSelections[i].hash;
                    }
                }
            }
            if (!pcr_selection->pcrSelections[0].hash) {
                /* hash for current pcr_select can't be determined */
                return_error(TSS2_FAPI_RC_BAD_TEMPLATE,
                             "Policy PCR: pcr_select does not match profile.");
            }
            /* Only one bank will be used. The hash alg from profile will be used */
            pcr_selection->count = 1;
            pcr_selection->pcrSelections[0].sizeofSelect = pcr_select->sizeofSelect;
            for (i = 0; i < pcr_select->sizeofSelect; i++)
                pcr_selection->pcrSelections[0].pcrSelect[i] = pcr_select->pcrSelect[i];
        }

        /* Prepare the PCR Reading. */
        r = Esys_PCR_Read_Async(context->esys,
                                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                pcr_selection);
        return_if_error(r, "PCR Read");
        fallthrough;

    statecase(context->io_state, IO_ACTIVE)
        /* Finalize or retry the reading and check the object type */
        r = Esys_PCR_Read_Finish(context->esys,
                                 &update_counter,
                                 &out_selection,
                                 &pcr_digests);

        if ((r & ~TSS2_RC_LAYER_MASK) == TSS2_BASE_RC_TRY_AGAIN)
            return TSS2_FAPI_RC_TRY_AGAIN;

        return_if_error(r, "PCR_Read_Finish");

        /* Count pcrs */
        for (i = 0; i < out_selection->count; i++) {
            for (pcr = 0; pcr < TPM2_MAX_PCRS; pcr++) {
                uint8_t byte_idx = pcr / 8;
                uint8_t flag = 1 << (pcr % 8);
                /* Check whether PCR is used. */
                if (flag & out_selection->pcrSelections[i].pcrSelect[byte_idx])
                    n_pcrs += 1;
            }
        }

        *pcr_values = calloc(1, sizeof(TPML_PCRVALUES) + n_pcrs* sizeof(TPMS_PCRVALUE));
        goto_if_null2(*pcr_values, "Out of memory.", r, TSS2_FAPI_RC_MEMORY, cleanup);

        /* Initialize digest list with pcr values from TPM */
        i_pcr = 0;
        for (i = 0; i < out_selection->count; i++) {
            for (pcr = 0; pcr < TPM2_MAX_PCRS; pcr++) {
                uint8_t byte_idx = pcr / 8;
                uint8_t flag = 1 << (pcr % 8);
                /* Check whether PCR is used. */
                if (flag & out_selection->pcrSelections[i].pcrSelect[byte_idx]) {
                    (*pcr_values)->pcrs[i_pcr].pcr = pcr;
                    (*pcr_values)->pcrs[i_pcr].hashAlg = out_selection->pcrSelections[i].hash;
                    memcpy(&(*pcr_values)->pcrs[i_pcr].digest,
                           &pcr_digests->digests[i_pcr].buffer[0],
                           pcr_digests->digests[i_pcr].size);
                    i_pcr +=1;
                }
            }
        }

        context->io_state = IO_INIT;
        break;

    statecasedefault(context->state);
    }

 cleanup:
    SAFE_FREE(out_selection);
    SAFE_FREE(pcr_digests);
    return r;
}

/** Callback for authorization of objects used by policy.
 *
 * @parm[in] name The name of the object to be authorized.
 * @parm[in] object_handle The ESYS handle of the used object.
 * @parm[in] auth_handle will be used for object authorization. For
             keys it will we equal to the object handle.
 * @parm[out] authSession The session used for object authorization.
 * @parm[in,out] userdata The Fapi context which will be used for keystore
 *               access, and storing the policy execution state.
 *               the io state.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_MEMORY: if it's not possible to allocate enough memory.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE If no user data is passed.
 */
TSS2_RC
ifapi_policyeval_cbauth(
    TPM2B_NAME *name,
    ESYS_TR *object_handle,
    ESYS_TR *auth_handle,
    ESYS_TR *authSession,
    void *userdata)
{
    TSS2_RC r;
    FAPI_CONTEXT *fapi_ctx = userdata;
    IFAPI_POLICY_EXEC_CTX *current_policy;
    IFAPI_POLICY_EXEC_CB_CTX *cb_ctx;
    bool next_case;

    return_if_null(fapi_ctx, "Bad user data.", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(fapi_ctx->policy.policyutil_stack, "Policy not initialized.",
                   TSS2_FAPI_RC_BAD_REFERENCE);

    if (fapi_ctx->policy.util_current_policy) {
        /* Use the current policy in the policy stack. */
        current_policy = fapi_ctx->policy.util_current_policy->pol_exec_ctx;
    } else {
        /* Start with the bottom of the policy stack */
        current_policy = fapi_ctx->policy.policyutil_stack->pol_exec_ctx;
    }
    cb_ctx = current_policy->app_data;

    do {
        next_case = false;
        switch(cb_ctx->cb_state) {
        statecase(cb_ctx->cb_state, POL_CB_EXECUTE_INIT);
            cb_ctx->auth_index = ESYS_TR_NONE;
            r = ifapi_keystore_search_obj(&fapi_ctx->keystore, &fapi_ctx->io,
                                          name,
                                          &cb_ctx->object_path);
            FAPI_SYNC(r, "Search Object", cleanup);

            r = ifapi_keystore_load_async(&fapi_ctx->keystore, &fapi_ctx->io,
                                          cb_ctx->object_path);
            return_if_error2(r, "Could not open: %s", cb_ctx->object_path);
            SAFE_FREE(cb_ctx->object_path);
            fallthrough;

        statecase(cb_ctx->cb_state, POL_CB_READ_OBJECT);
            /* Get object from file */
            r = ifapi_keystore_load_finish(&fapi_ctx->keystore, &fapi_ctx->io,
                                           &cb_ctx->object);
            return_try_again(r);
            return_if_error(r, "read_finish failed");

            r = ifapi_initialize_object(fapi_ctx->esys, &cb_ctx->object);
            goto_if_error(r, "Initialize NV object", cleanup);

            if (cb_ctx->object.objectType == IFAPI_NV_OBJ) {
                /* NV Authorization */

                cb_ctx->nv_index = cb_ctx->object.handle;

                get_nv_auth_object(&cb_ctx->object,
                                   cb_ctx->object.handle,
                                   &cb_ctx->auth_object,
                                   &cb_ctx->auth_index);

                goto_if_error(r, "PolicySecret set authorization", cleanup);
                cb_ctx->cb_state = POL_CB_AUTHORIZE_OBJECT;

                cb_ctx->auth_object_ptr = &cb_ctx->auth_object;
                next_case = true;
                break;
            } else if (cb_ctx->object.objectType == IFAPI_HIERARCHY_OBJ) {
                cb_ctx->cb_state = POL_CB_AUTHORIZE_OBJECT;
                next_case = true;
                break;
            } else {
                cb_ctx->key_handle = cb_ctx->object.handle;
                cb_ctx->cb_state = POL_CB_LOAD_KEY;
            }
            fallthrough;

        statecase(cb_ctx->cb_state, POL_CB_LOAD_KEY);
            /* Key loading and authorization */
            r = ifapi_load_key(fapi_ctx, cb_ctx->object_path,
                               &cb_ctx->auth_object_ptr);
            FAPI_SYNC(r, "Fapi load key.", cleanup);

            cb_ctx->object = *cb_ctx->key_object_ptr;
            SAFE_FREE(cb_ctx->key_object_ptr);
            cb_ctx->auth_object_ptr = &cb_ctx->object;
            fallthrough;

        statecase(cb_ctx->cb_state, POL_CB_AUTHORIZE_OBJECT);
            r = ifapi_authorize_object(fapi_ctx, cb_ctx->auth_object_ptr, authSession);
            return_try_again(r);
            goto_if_error(r, "Authorize  object.", cleanup);

            cb_ctx->cb_state = POL_CB_EXECUTE_INIT;
            break;
            /* FALLTHRU */

        statecasedefault(cb_ctx->cb_state);
        }
    } while (next_case);
    *object_handle = cb_ctx->object.handle;
    if (cb_ctx->object.objectType == IFAPI_NV_OBJ)
        *auth_handle = cb_ctx->auth_index;
    else
        *auth_handle = cb_ctx->object.handle;

    if (current_policy->policySessionSav != ESYS_TR_NONE)
        fapi_ctx->policy.session = current_policy->policySessionSav;

 cleanup:
    ifapi_cleanup_ifapi_object(&cb_ctx->object);
    if (current_policy->policySessionSav
        && current_policy->policySessionSav != ESYS_TR_NONE)
        fapi_ctx->policy.session = current_policy->policySessionSav;
    return r;
}

/** Callback for branch selection of policy or.
 *
 * @parm[in] name The name of the object to be authorized.
 * @parm[in] object_handle The ESYS handle of the used object.
 * @parm[in] auth_handle will be used for object authorization. For
             keys it will we equal to the object handle.
 * @parm[out] authSession The session used for object authorization.
 * @parm[in,out] userdata The Fapi context which will be used for keystore
 *               access, and storing the policy execution state.
 *               the io state.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_MEMORY: if it's not possible to allocate enough memory.
 * @retval TSS2_FAPI_RC_AUTHORIZATION_UNKNOWN If the callback for branch selection is
 *         not defined. This callback will be needed of or policies have to be
 *         executed.
 * @retval TSS2_FAPI_RC_BAD_VALUE If the computed branch index deliverd by the
 *         callback does not identify a branch.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE If no user data is passed.
 */
TSS2_RC
ifapi_branch_selection(
    TPML_POLICYBRANCHES *branches,
    size_t *branch_idx,
    void *userdata)
{
    TSS2_RC r;
    FAPI_CONTEXT *fapi_ctx = userdata;
    size_t i;
    const char *names[8];

    return_if_null(fapi_ctx, "Bad user data.", TSS2_FAPI_RC_BAD_REFERENCE);

    if (!fapi_ctx->callbacks.branch) {
        return_error(TSS2_FAPI_RC_AUTHORIZATION_UNKNOWN,
                     "No branch selection callback");
    }
    for (i = 0; i < branches->count; i++)
        names[i] = branches->authorizations[i].name;

    r = fapi_ctx->callbacks.branch(fapi_ctx, "PolicyOR",
                                   &names[0],
                                   branches->count,
                                   branch_idx,
                                   fapi_ctx->callbacks.branchData);
    return_if_error(r, "policyBranchSelectionCallback");

    if (*branch_idx > branches->count) {
        return_error2(TSS2_FAPI_RC_BAD_VALUE, "Invalid branch number.");
    }
    return TSS2_RC_SUCCESS;
}

/** Callback for policyaction.
 *
 * @parm[in] name The name of the object to be authorized.
 * @parm[in] object_handle The ESYS handle of the used object.
 * @parm[in] auth_handle will be used for object authorization. For
             keys it will we equal to the object handle.
 * @parm[out] authSession The session used for object authorization.
 * @parm[in,out] userdata The Fapi context which will be used for keystore
 *               access, and storing the policy execution state.
 *               the io state.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_MEMORY: if it's not possible to allocate enough memory.
 * @retval TSS2_FAPI_RC_AUTHORIZATION_UNKNOWN If the callback for branch selection is
 *         not defined. This callback will be needed of or policies have to be
 *         executed.
 * @retval TSS2_FAPI_RC_BAD_VALUE If the computed branch index deliverd by the
 *         callback does not identify a branch.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE If no user data is passed.
 */
TSS2_RC
ifapi_policy_action(
    const char *action,
    void *userdata)
{
    TSS2_RC r;
    FAPI_CONTEXT *fapi_ctx = userdata;
    return_if_null(fapi_ctx, "Bad user data.", TSS2_FAPI_RC_BAD_REFERENCE);

    if (!fapi_ctx->callbacks.action) {
        return_error(TSS2_FAPI_RC_AUTHORIZATION_UNKNOWN,
                     "No action callback");
    }
    r = fapi_ctx->callbacks.action(fapi_ctx, action,
                                   fapi_ctx->callbacks.actionData);
    return_if_error(r, "ifapi_policy_action callback");

    return TSS2_RC_SUCCESS;
}

/** Callback for signing a byte buffer.
 *
 * @parm[in] key_pem The pem key used for signing operation.
 * @parm[in] key_pem_hash_alg The hash alg used for digest computation.
 * @parm[in] buffer the byte array to be signed.
 * @parm[in] buffer_size The size of the buffer to be signed.
 * @parm[out] signature The signature in DER format.
 * @parm[out] signature_size The size of the signature.
 * @parm[in] userdata The user context to retrieve the signing function.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_MEMORY: if it's not possible to allocate enough memory.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE If no user data is passed.
 */
TSS2_RC
ifapi_sign_buffer(
    char *key_pem,
    TPMI_ALG_HASH key_pem_hash_alg,
    uint8_t *buffer,
    size_t buffer_size,
    uint8_t **signature,
    size_t *signature_size,
    void *userdata)
{
    TSS2_RC r;
    FAPI_CONTEXT *fapi_ctx = userdata;

    return_if_null(fapi_ctx, "Bad user data.", TSS2_FAPI_RC_BAD_REFERENCE);

    if (!fapi_ctx->callbacks.sign) {
        return_error2(TSS2_FAPI_RC_AUTHORIZATION_UNKNOWN,
                      "No signature callback.");
    }
    r = fapi_ctx->callbacks.sign(fapi_ctx, "PolicySigned", key_pem, "",       // TODO check publicKeyHint
                                 key_pem_hash_alg,
                                 buffer, buffer_size,
                                 signature, signature_size,
                                 fapi_ctx->callbacks.signData);
    try_again_or_error(r, "Execute policy signature callback.");

    return TSS2_RC_SUCCESS;
}

/**  Check whether public data of key is assigned to policy.
 *
 * It will be checked whether policy was authorized with key with public
 * data of type TPMT_PUBLIC.
 */
static TSS2_RC
equal_policy_authorization(
    TPMS_POLICY_HARNESS *policy,
    void *publicVoid,
    void *nameAlgVoid,
    bool *equal)
{
    TPMT_PUBLIC *public = publicVoid;
    (void)nameAlgVoid;
    size_t i;
    TPML_POLICYAUTHORIZATIONS *authorizations = policy->policyAuthorizations;

    *equal = false;
    if (authorizations) {
        for (i = 0; i < authorizations->count; i++) {
            if (ifapi_TPMT_PUBLIC_cmp
                (public, &authorizations->authorizations[i].key)) {
                *equal = true;
                return TSS2_RC_SUCCESS;
            }
        }
    }
    return TSS2_RC_SUCCESS;
}

/** Check whether policy digest can be found in policy.
 *
 * It will be testes whether the policy has been instatiated with the
 * passed digest.
 */
static TSS2_RC
compare_policy_digest(
    TPMS_POLICY_HARNESS *policy,
    void *authPolicyVoid,
    void *nameAlgVoid,
    bool *equal)
{
    TPM2B_DIGEST *authPolicy = authPolicyVoid;
    TPMI_ALG_HASH *hash_alg_ptr = nameAlgVoid;
    TPMI_ALG_HASH hash_alg = *hash_alg_ptr;
    size_t i;
    TPML_DIGEST_VALUES *digest_values;

    *equal = false;

    digest_values = &policy->policyDigests;

    if (digest_values) {
        for (i = 0; i < digest_values->count; i++) {
            if (digest_values->digests[i].hashAlg == hash_alg) {
                if (memcmp(&digest_values->digests[i].digest,
                           &authPolicy->buffer[0],
                           authPolicy->size))
                    continue;
                *equal = true;
                return TSS2_RC_SUCCESS;
            }
        }
    }
    return TSS2_RC_SUCCESS;
}

/** Search a policy file which fulfills a certain predicate.
 */
static TSS2_RC
search_policy(
    FAPI_CONTEXT *context,
    Policy_Compare_Object compare,
    bool all_objects,
    void *object1,
    void *object2,
    struct POLICY_LIST **policy_found)
{
    TSS2_RC r = TSS2_RC_SUCCESS;
    char *path;
    TPMS_POLICY_HARNESS policy = {0};
    bool found;
    struct POLICY_LIST *policy_object;
    struct POLICY_LIST *second;

    switch (context->fsearch.state) {
    case FSEARCH_INIT:
        LOG_DEBUG("** STATE ** FSEARCH_INIT");
        memset(&context->fsearch, 0, sizeof(IFAPI_FILE_SEARCH_CTX));
        r = ifapi_keystore_list_all(&context->keystore, IFAPI_POLICY_DIR, &context->fsearch.pathlist,
                                    &context->fsearch.numPaths);
        return_if_error(r, "get entities.");
        context->fsearch.path_idx = context->fsearch.numPaths;

        context->fsearch.state = FSEARCH_OBJECT;
    /* FALLTHRU */

    case FSEARCH_OBJECT:
        LOG_DEBUG("** STATE ** FSEARCH_OBJECT");
        if (context->fsearch.path_idx == 0) {
            if (*policy_found) {
                context->fsearch.state = FSEARCH_INIT;
                for (size_t i = 0; i < context->fsearch.numPaths; i++) {
                    SAFE_FREE(context->fsearch.pathlist[i]);
                }
                SAFE_FREE(context->fsearch.pathlist);
                return TSS2_RC_SUCCESS;
            }
            goto_error(r, TSS2_FAPI_RC_POLICY_UNKNOWN, "Policy not found.", cleanup);
        }
        context->fsearch.path_idx -= 1;
        path =  context->fsearch.pathlist[context->fsearch.path_idx];
        context->fsearch.current_path = path;
        LOG_DEBUG("Check file: %s %zu", path, context->fsearch.path_idx);

        r = ifapi_policy_store_load_async(&context->pstore, &context->io, path);
        goto_if_error2(r, "Can't open: %s", cleanup, path);

        context->fsearch.state = FSEARCH_READ;
    /* FALLTHRU */

    case FSEARCH_READ:
        LOG_DEBUG("** STATE ** FSEARCH_READ");
        r = ifapi_policy_store_load_finish(&context->pstore, &context->io, &policy);
        return_try_again(r);
        goto_if_error(r, "read_finish failed", cleanup);

        r = compare(&policy, object1, object2, &found);
        if (found) {
            LOG_DEBUG("compare true  %s",
                      context->fsearch.pathlist[context->fsearch.path_idx]);
        } else {
            LOG_DEBUG("compare false  %s",
                      context->fsearch.pathlist[context->fsearch.path_idx]);
        }
        goto_if_error(r, "Invalid cipher object.", cleanup);

        if (!found) {
            if (!all_objects && context->fsearch.path_idx == 0) {
                context->fsearch.state = FSEARCH_INIT;
                ifapi_cleanup_policy_harness(&policy);
                return TSS2_BASE_RC_POLICY_UNKNOWN;
            } else {
                context->fsearch.state = FSEARCH_OBJECT;
                ifapi_cleanup_policy_harness(&policy);
                return TSS2_FAPI_RC_TRY_AGAIN;
            }
        }
        policy_object = calloc(sizeof(struct POLICY_LIST), 1);
        return_if_null(policy_object, "Out of memory.", TSS2_FAPI_RC_MEMORY);

        policy_object->path = context->fsearch.current_path;
        policy_object->policy = policy;
        if (*policy_found != NULL) {
            second = *policy_found;
            policy_object->next = second;
        }
        *policy_found = policy_object;

        if (context->fsearch.path_idx == 0) {
            context->fsearch.state = FSEARCH_INIT;
            for (size_t i = 0; i < context->fsearch.numPaths; i++) {
                SAFE_FREE(context->fsearch.pathlist[i]);
            }
            SAFE_FREE(context->fsearch.pathlist);
            return TSS2_RC_SUCCESS;
        }

        if (all_objects) {
            context->fsearch.state = FSEARCH_OBJECT;
            return TSS2_FAPI_RC_TRY_AGAIN;
        }

        break;

    default:
        context->state = _FAPI_STATE_INTERNALERROR;
        goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Invalid state for load key.", cleanup);
    }
    context->fsearch.state = FSEARCH_INIT;
    for (size_t i = 0; i < context->fsearch.numPaths; i++) {
        SAFE_FREE(context->fsearch.pathlist[i]);
    }
    SAFE_FREE(context->fsearch.pathlist);
    return TSS2_RC_SUCCESS;
cleanup:
    ifapi_cleanup_policy_harness(&policy);
    for (size_t i = 0; i < context->fsearch.numPaths; i++) {
        SAFE_FREE(context->fsearch.pathlist[i]);
    }
    SAFE_FREE(context->fsearch.pathlist);
    context->fsearch.state = FSEARCH_INIT;
    return r;
}

/** Get policy digeset  for a certain hash alg.
 */
static TSS2_RC
get_policy_digest(TPMS_POLICY_HARNESS *harness,
                  TPMI_ALG_HASH hashAlg,
                  TPM2B_DIGEST *digest)
{
    size_t i;

    if (!(digest->size = ifapi_hash_get_digest_size(hashAlg))) {
        return_error2(TSS2_ESYS_RC_NOT_IMPLEMENTED,
                      "Unsupported hash algorithm (%" PRIu16 ")", hashAlg);
    }

    for (i = 0; i < harness->policyDigests.count; i++) {
        if (harness->policyDigests.digests[i].hashAlg == hashAlg) {
            memcpy(&digest->buffer[0],
                   &harness->policyDigests.digests[i].digest, digest->size);
            return TSS2_RC_SUCCESS;
        }
    }
    return TSS2_FAPI_RC_GENERAL_FAILURE;
}

/** Get policy authorization for a certain public key
 */
static TSS2_RC
get_policy_signature(
    TPMS_POLICY_HARNESS *harness,
    TPMT_PUBLIC *public,
    TPMT_SIGNATURE *signature)
{
    size_t i;

    for (i = 0; i < harness->policyAuthorizations->count; i++) {
        if (ifapi_TPMT_PUBLIC_cmp(public,
                                  &harness->policyAuthorizations->authorizations[i].key)) {
            *signature = harness->policyAuthorizations->authorizations[i].signature;
            return TSS2_RC_SUCCESS;
        }
    }
    /* Appropriate authorization should always exist */
    return TSS2_FAPI_RC_GENERAL_FAILURE;
}

static void cleanup_policy_list(struct POLICY_LIST * list) {
    if (list) {
        struct POLICY_LIST * branch = list;
        while (branch) {
            struct POLICY_LIST *next = branch->next;
            ifapi_cleanup_policy_harness(&branch->policy);
            SAFE_FREE(branch);
            branch = next;
        }
    }
}

/** Callback for retrieving, selecting and execute a authorized policy.
 *
 * All policies authorized by a certain key will be retrieved and one policy
 * will be selected via a branch selection callback.
 *
 * @parm[in] key_public the public data of the key which was used for policy
 *           authorization.
 * @parm[in] hash_alg The hash algorithm used for policy computation.
 * @parm[out] digest The policy digest of the authorized policy.
 * @parm[out] signature The signature produced during policy authorization.
 * @parm[in] userdata The user context to retrieve the policy.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_MEMORY: if it's not possible to allocate enough memory.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE If no user data id passed or context stack
 *         is not initialized.
 * @retval TSS2_FAPI_RC_IO_ERROR If an error occurs during access to the policy
 *         store.
 * @retval TSS2_FAPI_RC_PATH_NOT_FOUND If a policy for a certain path was not found.
 * @retval TSS2_FAPI_RC_POLICY_UNKNOWN If policy search for a certain policy diges was
           not successful.
 * @retval TPM2_RC_BAD_AUTH If the authentication for an object needed for policy
 *         execution fails.
 */
TSS2_RC
ifapi_exec_auth_policy(
    TPMT_PUBLIC *key_public,
    TPMI_ALG_HASH hash_alg,
    TPM2B_DIGEST *digest,
    TPMT_SIGNATURE *signature,
    void *userdata)
{
    TSS2_RC r;
    FAPI_CONTEXT *fapi_ctx = userdata;
    IFAPI_POLICY_EXEC_CTX *current_policy;
    IFAPI_POLICY_EXEC_CB_CTX *cb_ctx;
    size_t n, i;
    struct POLICY_LIST *branch;
    const char **names = NULL;
    size_t branch_idx;
    bool harness_set = false;

    return_if_null(fapi_ctx, "Bad user data.", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(fapi_ctx->policy.policyutil_stack, "Policy not initialized.",
                   TSS2_FAPI_RC_BAD_REFERENCE);

    if (fapi_ctx->policy.util_current_policy) {
        /* Use the current policy in the policy stack. */
        current_policy = fapi_ctx->policy.util_current_policy->pol_exec_ctx;
    } else {
        /* Start with the bottom of the policy stack */
        current_policy = fapi_ctx->policy.policyutil_stack->pol_exec_ctx;
    }
    cb_ctx = current_policy->app_data;

    switch(cb_ctx->cb_state) {
        statecase(cb_ctx->cb_state, POL_CB_EXECUTE_INIT)
            current_policy->object_handle = ESYS_TR_NONE;
            current_policy->policy_list = NULL;
            fallthrough;

        statecase(cb_ctx->cb_state, POL_CB_SEARCH_POLICY)
            r = search_policy(fapi_ctx,
                              equal_policy_authorization, true,
                              key_public, NULL,
                              &current_policy->policy_list);
            FAPI_SYNC(r, "Search policy", cleanup);

            if (current_policy->policy_list->next) {
                /* More than one policy policy has to be selected via
                   callback */
                if (!fapi_ctx->callbacks.branch) {
                    return_error(TSS2_FAPI_RC_AUTHORIZATION_UNKNOWN,
                                 "No branch selection callback");
                }
                n = 1;

                /* Count policies */
                for (branch = current_policy->policy_list; branch->next;
                     branch = branch->next)
                    n += 1;
                names = malloc(sizeof(char *) * n);
                return_if_null(names, "Out of memory.", TSS2_FAPI_RC_MEMORY);
                i = 0;
                branch = current_policy->policy_list;
                /* Compute name list for slectiion callback. */
                do {
                    names[i] = branch->policy.description;
                    i += 1;
                    branch = branch->next;
                } while (branch);

                /* Policy selection */
                r = fapi_ctx->callbacks.branch(fapi_ctx, "PolicyAuthorize",
                                               &names[0], n, &branch_idx,
                                               fapi_ctx->callbacks.branchData);
                return_if_error(r, "policyBranchSelectionCallback");

                if (branch_idx > n) {
                    goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Invalid branch number.",
                               cleanup);
                }
                /* Get harness from policy list */
                n = 1;
                branch = current_policy->policy_list;
                do {
                    if (n == branch_idx) {
                        cb_ctx->harness = &branch->policy;
                        harness_set = true;
                        break;
                    }
                    n += 1;
                    branch = branch->next;
                }  while (branch);

            } else {
                /* Only one policy found. */
                cb_ctx->harness = &current_policy->policy_list->policy;
                harness_set = true;
            }
            if (!harness_set) {
                goto_error(r, TSS2_FAPI_RC_GENERAL_FAILURE, "Policy could not be set.",
                           cleanup);
            }
            /* Prepare policy execution */
            r = ifapi_policyutil_execute_prepare(fapi_ctx, current_policy->hash_alg,
                                                 cb_ctx->harness);
            /* Next state will switch from prev context to next context. */
            return_if_error(r, "Prepare policy execution.");
            fallthrough;

        statecase(cb_ctx->cb_state, POL_CB_EXECUTE_SUB_POLICY)
            ESYS_TR session = current_policy->session;
            r = ifapi_policyutil_execute(fapi_ctx, &session);
            if (r == TSS2_FAPI_RC_TRY_AGAIN){
                return r;
            }

            goto_if_error(r, "Execute policy.", cleanup);

            r = get_policy_signature(cb_ctx->harness, key_public,
                                     signature);
            goto_if_error(r, "Get authorization", cleanup);

            r = get_policy_digest(cb_ctx->harness, hash_alg, digest);
            goto_if_error(r, "Get authorization", cleanup);
            cb_ctx->cb_state = POL_CB_EXECUTE_INIT;
            break;

        statecasedefault_error(cb_ctx->state, r, cleanup);
    }
 cleanup:
    SAFE_FREE(names);
    cleanup_policy_list(current_policy->policy_list);
    return r;
}

/** Callback for executing a policy identified by a digest stored in a nv object.
 *
 * @parm[in] nv_public the public data of the nv object which stores the diges
 *           of the authorized policy.
 * @parm[in] hash_alg The hash algorithm used for policy computation.
 * @parm[out] The policy digest read from nv ram.
 * @parm[in] userdata The user context to retrieve the policy.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_MEMORY: if it's not possible to allocate enough memory.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE If no user data id passed or context stack
 *         is not initialized.
 * @retval TSS2_FAPI_RC_IO_ERROR If an error occurs during access to the policy
 *         store.
 * @retval TSS2_FAPI_RC_PATH_NOT_FOUND If a policy for a certain path was not found.
 * @retval TSS2_FAPI_RC_POLICY_UNKNOWN If policy search for a certain policy diges was
           not successful.
 * @retval TPM2_RC_BAD_AUTH If the authentication for an object needed for policy
 *         execution fails.
 */
TSS2_RC
ifapi_exec_auth_nv_policy(
    TPM2B_NV_PUBLIC *nv_public,
    TPMI_ALG_HASH hash_alg,
    void *userdata)
{
    TSS2_RC r;
    TPM2B_MAX_NV_BUFFER *aux_data;
    FAPI_CONTEXT *fapi_ctx = userdata;
    IFAPI_POLICY_EXEC_CTX *current_policy;
    IFAPI_POLICY_EXEC_CB_CTX *cb_ctx;
    char *nv_path = NULL;
    ESYS_CONTEXT *esys_ctx;
    size_t digest_size, offset;
    TPMT_HA nv_policy;

    return_if_null(fapi_ctx, "Bad user data.", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(fapi_ctx->policy.policyutil_stack, "Policy not initialized.",
                   TSS2_FAPI_RC_BAD_REFERENCE);

    if (fapi_ctx->policy.util_current_policy) {
        /* Use the current policy in the policy stack. */
        current_policy = fapi_ctx->policy.util_current_policy->pol_exec_ctx;
    } else {
        /* Start with the bottom of the policy stack */
        current_policy = fapi_ctx->policy.policyutil_stack->pol_exec_ctx;
    }
    cb_ctx = current_policy->app_data;
    esys_ctx = fapi_ctx->esys;

    if (!(digest_size = ifapi_hash_get_digest_size(hash_alg))) {
        return_error2(TSS2_ESYS_RC_NOT_IMPLEMENTED,
                      "Unsupported hash algorithm (%" PRIu16 ")", hash_alg);
    }

    switch(cb_ctx->cb_state) {
        statecase(cb_ctx->cb_state, POL_CB_EXECUTE_INIT)
            r = ifapi_keystore_search_nv_obj(&fapi_ctx->keystore, &fapi_ctx->io,
                                             nv_public, &nv_path);
            FAPI_SYNC(r, "Search Object", cleanup);

            r = ifapi_keystore_load_async(&fapi_ctx->keystore, &fapi_ctx->io, nv_path);
            SAFE_FREE(nv_path);
            return_if_error2(r, "Could not open: %s", nv_path);

            fallthrough;

        statecase(cb_ctx->cb_state, POL_CB_NV_READ)
            /* Get object from file */
            r = ifapi_keystore_load_finish(&fapi_ctx->keystore, &fapi_ctx->io,
                                           &cb_ctx->object);
            return_try_again(r);
            return_if_error(r, "read_finish failed");

            r = ifapi_initialize_object(esys_ctx, &cb_ctx->object);
            goto_if_error(r, "Initialize NV object", cleanup);

            current_policy->nv_index = cb_ctx->object.handle;
            ifapi_cleanup_ifapi_object(&cb_ctx->object);
            get_nv_auth_object(&cb_ctx->object,
                               current_policy->nv_index,
                               &current_policy->auth_object,
                               &current_policy->auth_handle);
            fallthrough;

        statecase(cb_ctx->cb_state, POL_CB_AUTHORIZE_OBJECT)
            r = ifapi_authorize_object(fapi_ctx, &cb_ctx->auth_object, &cb_ctx->session);
            return_try_again(r);
            goto_if_error(r, "Authorize  object.", cleanup);

            r = Esys_NV_Read_Async(esys_ctx,
                            current_policy->auth_handle, current_policy->nv_index,
                            cb_ctx->session, ESYS_TR_NONE, ESYS_TR_NONE,
                            sizeof(TPMI_ALG_HASH) + digest_size, 0);
            goto_if_error(r, "Unmarshal policy", cleanup);
            fallthrough;

        statecase(cb_ctx->cb_state, POL_CB_READ_NV_POLICY)
            r = Esys_NV_Read_Finish(esys_ctx, &aux_data);
            try_again_or_error_goto(r, "NV read", cleanup);

            offset = 0;
            r = Tss2_MU_TPMT_HA_Unmarshal(&aux_data->buffer[0], aux_data->size,
                                          &offset, &nv_policy);
            Esys_Free(aux_data);
            goto_if_error(r, "Unmarshal policy", cleanup);

            cb_ctx->policy_digest.size = digest_size;
            memcpy(&cb_ctx->policy_digest.buffer[0], &nv_policy.digest, digest_size);
            fallthrough;

        statecase(cb_ctx->cb_state, POL_CB_SEARCH_POLICY)
            /* Search policy appropriate in object store */
            r = search_policy(fapi_ctx, compare_policy_digest, false,
                              &cb_ctx->policy_digest, &hash_alg,
                              &current_policy->policy_list);
            FAPI_SYNC(r, "Search policy", cleanup);

            if (!current_policy->policy_list) {
                goto_error(r, TSS2_FAPI_RC_POLICY_UNKNOWN, "Policy not found", cleanup);
            }
            /* Prepare policy execution */
            r = ifapi_policyutil_execute_prepare(fapi_ctx, current_policy->hash_alg,
                                                 &current_policy->policy_list->policy);
            return_if_error(r, "Prepare policy execution.");
            fallthrough;

        statecase(cb_ctx->cb_state, POL_CB_EXECUTE_SUB_POLICY)
            ESYS_TR session = current_policy->session;
            r = ifapi_policyutil_execute(fapi_ctx, &session);
            if (r == TSS2_FAPI_RC_TRY_AGAIN)
                return r;

            goto_if_error(r, "Execute policy.", cleanup);
            cb_ctx->cb_state = POL_CB_EXECUTE_INIT;
            break;

        statecasedefault_error(cb_ctx->state, r, cleanup);
    }
 cleanup:
    if (current_policy->policy_list) {
        ifapi_cleanup_policy_harness(&current_policy->policy_list->policy);
        SAFE_FREE(current_policy->policy_list);
    }
    SAFE_FREE(nv_path);
    return r;

}

/** Callback for getting the name of a key to be duplicated.
 *
 * @parm[out] name the name of the object to be duplicated.
 * @parm[in] userdata The user context to retrieve the key.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_FAPI_RC_BAD_REFERENCE: if the context is not passed or the
 *         object to be duplicated is not set.
 */
TSS2_RC
ifapi_get_duplicate_name(
    TPM2B_NAME *name,
    void *userdata)
{
    FAPI_CONTEXT *fapi_ctx = userdata;

    return_if_null(fapi_ctx, "Bad user data.", TSS2_FAPI_RC_BAD_REFERENCE);
    return_if_null(fapi_ctx->duplicate_key, "Object for duplication no set.",
                   TSS2_FAPI_RC_BAD_REFERENCE);
    *name = fapi_ctx->duplicate_key->misc.key.name;
    return TSS2_RC_SUCCESS;
}
