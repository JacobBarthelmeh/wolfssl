/* wolfcaam_seco.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_SECO_CAAM)

#include <hsm/hsm_api.h>
#include <seco_nvm.h>

#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/caam/wolfcaam.h>

#define MAX_SECO_TIMEOUT 1000

/* for devctl use */
int caamFd = -1;
wolfSSL_Mutex caamMutex;
static pthread_t tid;
static uint32_t nvm_status = 0;
static hsm_hdl_t hsm_session;

static void* hsm_storage_init(void* args)
{
    seco_nvm_manager(NVM_FLAGS_HSM, &nvm_status);
    (void)args;
    return NULL;
}


/* return 0 on success */
int wc_SECOInitInterface()
{
    int i;
    open_session_args_t session_args;
    hsm_err_t err;

    nvm_status = NVM_STATUS_UNDEF;
    if (wc_InitMutex(&caamMutex) != 0) {
        WOLFSSL_MSG("Could not init mutex");
        return -1;
    }

    (void)pthread_create(&tid, NULL, hsm_storage_init, NULL);

    /* wait for NVM to be ready for SECO */
    for (i = 0 ; i < MAX_SECO_TIMEOUT && nvm_status <= NVM_STATUS_STARTING;
        i++) {
        usleep(1000);
    }
    if (i == MAX_SECO_TIMEOUT) {
        WOLFSSL_MSG("Timed out waiting for SECO setup");
        return -1;
    }

    if (nvm_status == NVM_STATUS_STOPPED) {
        WOLFSSL_MSG("Error with SECO setup");
        return -1;
    }

    session_args.session_priority = 0;
    session_args.operating_mode   = 0;

    err = hsm_open_session(&session_args, &hsm_session);
    if (err != HSM_NO_ERROR) {
        WOLFSSL_MSG("Error with HSM session open");
        return -1;
    }
    WOLFSSL_MSG("SECO HSM setup done");

    return 0;
}


void wc_SECOFreeInterface()
{
    hsm_err_t err;

    err = hsm_close_session(hsm_session);
    if (err != HSM_NO_ERROR) {
        WOLFSSL_MSG("Error with HSM session close");
    }


    if (nvm_status != NVM_STATUS_STOPPED) {
        if (pthread_cancel(tid) != 0) {
            WOLFSSL_MSG("SECO HSM thread shutdown failed");
        }
    }

    seco_nvm_close_session();
    WOLFSSL_MSG("SECO HSM shutdown");

    wc_FreeMutex(&caamMutex);
}


/* returns error enum found from hsm calls, HSM_NO_ERROR on success */
static hsm_err_t wc_SECO_RNG(unsigned int args[4], CAAM_BUFFER *buf, int sz)
{
    hsm_hdl_t rng;
    hsm_err_t err;
    open_svc_rng_args_t svcArgs  = {0};
    op_get_random_args_t rngArgs = {0};

    err = hsm_open_rng_service(hsm_session, &svcArgs, &rng);

    if (err == HSM_NO_ERROR) {
        rngArgs.output      = (uint8_t*)buf[0].TheAddress;
        rngArgs.random_size = (uint32_t)buf[0].Length;
        err = hsm_get_random(rng, &rngArgs);
    #ifdef SECO_DEBUG
        {
            uint32_t z;
            printf("Pulled rng data from HSM :");
            for (z = 0; z < rngArgs.random_size; z++)
                printf("%02X", rngArgs.output[z]);
            printf("\n");
        }
    #endif
    }

    if (err == HSM_NO_ERROR) {
        err = hsm_close_rng_service(rng);
    }

    (void)args;
    (void)sz;
    return err;
}


static hsm_err_t wc_SECO_Hash(unsigned args[4], CAAM_BUFFER *buf, int sz,
    int type)
{
    hsm_hdl_t hash;
    hsm_err_t err = HSM_NO_ERROR;
    op_hash_one_go_args_t hashArgs   = {0};
    open_svc_hash_args_t sessionArgs = {0};

    if (args[0] != CAAM_ALG_FINAL) {
        WOLFSSL_MSG("Only expecting to call the HSM on final");
        err = HSM_GENERAL_ERROR;
    }

    if (err == HSM_NO_ERROR) {
        err = hsm_open_hash_service(hsm_session, &sessionArgs, &hash);
    }

    if (err == HSM_NO_ERROR) {
        switch (type) {
            case CAAM_SHA224:
                hashArgs.algo = HSM_HASH_ALGO_SHA_224;
                break;

            case CAAM_SHA256:
                hashArgs.algo = HSM_HASH_ALGO_SHA_256;
                break;

            case CAAM_SHA384:
                hashArgs.algo = HSM_HASH_ALGO_SHA_384;
                break;

            case CAAM_SHA512:
                hashArgs.algo = HSM_HASH_ALGO_SHA_512;
                break;
            //#define HSM_HASH_ALGO_SM3_256      ((hsm_hash_algo_t)(0x11u))
        }

        hashArgs.output = (uint8_t*)buf[0].TheAddress;
        hashArgs.output_size = buf[0].Length;
        hashArgs.input = (uint8_t*)buf[1].TheAddress;
        hashArgs.input_size = buf[1].Length;

        err = hsm_hash_one_go(hash, &hashArgs);
        if (err != HSM_NO_ERROR) {
            WOLFSSL_MSG("Error with HSM hash call");
        }

    #ifdef SECO_DEBUG
        {
            word32 z;
            printf("hash algo type = %d\n", hashArgs.algo);
            printf("\tlength of input data = %d\n", hashArgs.input_size);
            printf("\toutput : ");
            for (z = 0; z < hashArgs.output_size; z++)
                printf("%02X", hashArgs.output[z]);
            printf("\n");
        }
    #endif

        /* always try to close the hash handle */
        if (hsm_close_hash_service(hash) != HSM_NO_ERROR) {
            WOLFSSL_MSG("Error with HSM hash close");
            if (err == HSM_NO_ERROR) {
                err = HSM_GENERAL_ERROR;
            }
        }
    }
    (void)sz;
    return err;
}


/* trasnlates the HSM error to wolfSSL error and does debug print out */
static int wc_TranslateHSMError(int current, hsm_err_t err)
{
    int ret = -1;

    switch (err) {
        case HSM_NO_ERROR:
            ret = Success;
            break;

        case HSM_INVALID_MESSAGE:
            WOLFSSL_MSG("SECO HSM: Invalid/unknown msg");
            break;

        case HSM_INVALID_ADDRESS:
            WOLFSSL_MSG("SECO HSM: Invalid address");
            break;

        case HSM_UNKNOWN_ID:
            WOLFSSL_MSG("SECO HSM: unknown ID");
            break;

        case HSM_INVALID_PARAM:
            WOLFSSL_MSG("SECO HSM: invalid param");
            break;

        case HSM_NVM_ERROR:
            WOLFSSL_MSG("SECO HSM: generic nvm error");
            break;

        case HSM_OUT_OF_MEMORY:
            WOLFSSL_MSG("SECO HSM: out of memory");
            break;

        case HSM_UNKNOWN_HANDLE:
            WOLFSSL_MSG("SECO HSM: unknown handle");
            break;

        case HSM_UNKNOWN_KEY_STORE:
            WOLFSSL_MSG("SECO HSM: unknown key store");
            break;

        case HSM_KEY_STORE_AUTH:
            WOLFSSL_MSG("SECO HSM: key store auth error");
            break;

        case HSM_KEY_STORE_ERROR:
            WOLFSSL_MSG("SECO HSM: key store error");
            break;

        case HSM_ID_CONFLICT:
            WOLFSSL_MSG("SECO HSM: id conflict");
            break;

        case HSM_RNG_NOT_STARTED:
            WOLFSSL_MSG("SECO HSM: RNG not started");
            break;

        case HSM_CMD_NOT_SUPPORTED:
            WOLFSSL_MSG("SECO HSM: CMD not support");
            break;

        case HSM_INVALID_LIFECYCLE:
            WOLFSSL_MSG("SECO HSM: invalid lifecycle");
            break;

        case HSM_KEY_STORE_CONFLICT:
            WOLFSSL_MSG("SECO HSM: store conflict");
            break;

        case HSM_KEY_STORE_COUNTER:
            WOLFSSL_MSG("SECO HSM: key store counter error");
            break;

        case HSM_FEATURE_NOT_SUPPORTED:
            WOLFSSL_MSG("SECO HSM: feature not supported");
            break;

        case HSM_SELF_TEST_FAILURE:
            WOLFSSL_MSG("SECO HSM: self test failure");
            break;

        case HSM_NOT_READY_RATING:
            WOLFSSL_MSG("SECO HSM: not ready");
            break;

        case HSM_FEATURE_DISABLED:
            WOLFSSL_MSG("SECO HSM: feature is disabled error");
            break;

        case HSM_GENERAL_ERROR:
            WOLFSSL_MSG("SECO HSM: general error found");
            break;

        default:
            WOLFSSL_MSG("SECO HSM: unkown error value found");
    }

    if (current != 0) {
        WOLFSSL_MSG("In an error state before SECO HSM error");
        ret = current;
    }

    return ret;
}


/* Do a synchronous operations and block till done
 * returns 0 on success */
int SynchronousSendRequest(int type, unsigned int args[4], CAAM_BUFFER *buf,
        int sz)
{
    int ret;
    hsm_err_t err = HSM_NO_ERROR;
    CAAM_ADDRESS pubkey, privkey;

    if (args != NULL) {
//        SETIOV(&in[inIdx], args, sizeof(unsigned int) * 4);
    }
    else {
//        unsigned int localArgs[4] = {0};
//        SETIOV(&in[inIdx], localArgs, sizeof(unsigned int) * 4);
    }

    ret = wc_LockMutex(&caamMutex);
    if (ret == 0) {
    switch (type) {
    case CAAM_ENTROPY:
        err = wc_SECO_RNG(args, buf, sz);
        break;

    case CAAM_SHA224:
    case CAAM_SHA256:
    case CAAM_SHA384:
    case CAAM_SHA512:
        err = wc_SECO_Hash(args, buf, sz, type);
        break;

    case CAAM_GET_PART:
//        cmd = WC_CAAM_GET_PART;
        break;

    case CAAM_FREE_PART:
//        cmd = WC_CAAM_FREE_PART;
        break;

    case CAAM_FIND_PART:
//        cmd = WC_CAAM_FIND_PART;
        break;

    case CAAM_READ_PART:
//        cmd = WC_CAAM_READ_PART;
        break;

    case CAAM_WRITE_PART:
//        cmd = WC_CAAM_WRITE_PART;
        break;

    case CAAM_ECDSA_KEYPAIR:
//        cmd = WC_CAAM_ECDSA_KEYPAIR;
        break;

    case CAAM_ECDSA_VERIFY:
        /* public key */
        if (args[0] == 1) {
            pubkey = buf[0].TheAddress;
        }
        else {
        }

        /* msg */
        //SETIOV(&in[inIdx], buf[1].TheAddress, buf[1].Length);

        /* r */
        //SETIOV(&in[inIdx], buf[2].TheAddress, buf[2].Length);

        /* s */
        //SETIOV(&in[inIdx], buf[3].TheAddress, buf[3].Length);

//        cmd = WC_CAAM_ECDSA_VERIFY;
        break;

    case CAAM_ECDSA_SIGN:
        /* private key */
        if (args[0] == 1) {
            privkey = buf[0].TheAddress;
        }
        else {
            //SETIOV(&in[inIdx], buf[0].TheAddress, buf[0].Length);
        }

        /* msg */
        //SETIOV(&in[inIdx], buf[1].TheAddress, buf[1].Length);

        /* r out */
        //SETIOV(&out[outIdx], buf[2].TheAddress, buf[2].Length);

        /* s out */
        //SETIOV(&out[outIdx], buf[3].TheAddress, buf[3].Length);

//        cmd = WC_CAAM_ECDSA_SIGN;
        break;

    case CAAM_ECDSA_ECDH:
        /* when using memory in secure partition just send the address */
        if (args[1] == 1) {
            pubkey = buf[0].TheAddress;
        }
        else {
            //SETIOV(&in[inIdx], buf[0].TheAddress, buf[0].Length);
        }

        /* private key */
        if (args[0] == 1) {
            privkey = buf[1].TheAddress;
        }
        else {
            //SETIOV(&in[inIdx], buf[1].TheAddress, buf[1].Length);
        }

        /* shared secret */
        //SETIOV(&out[outIdx], buf[2].TheAddress, buf[2].Length);

//        cmd = WC_CAAM_ECDSA_ECDH;
        break;

    case CAAM_BLOB_ENCAP:
        //SETIOV(&in[inIdx], buf[0].TheAddress, buf[0].Length);

        if (args[0] == 1) {
            //SETIOV(&in[inIdx], buf[1].TheAddress, buf[1].Length + WC_CAAM_MAC_SZ);
        }
        else {
            //`SETIOV(&in[inIdx], buf[1].TheAddress, buf[1].Length);
        }

        //SETIOV(&out[outIdx], buf[2].TheAddress, buf[2].Length);
//        cmd = WC_CAAM_BLOB_ENCAP;
        break;

    case CAAM_BLOB_DECAP:
        //SETIOV(&in[inIdx], buf[0].TheAddress, buf[0].Length);

        //SETIOV(&in[inIdx], buf[1].TheAddress, buf[1].Length);

        if (args[0] == 1) {
            //SETIOV(&out[outIdx], buf[2].TheAddress,
            //        buf[2].Length + WC_CAAM_MAC_SZ);
        }
        else {
            //SETIOV(&out[outIdx], buf[2].TheAddress, buf[2].Length);
        }

//        cmd = WC_CAAM_BLOB_DECAP;
        break;

    case CAAM_CMAC:
//        {
//            int i;
//
//            if (args[2] == 1) {
//                SETIOV(&in[inIdx], buf[0].TheAddress, buf[0].Length + 16);
//                inIdx = inIdx + 1;
//            }
//            else {
//                SETIOV(&in[inIdx], buf[0].TheAddress, buf[0].Length);
//                inIdx = inIdx + 1;
//            }
//
//            SETIOV(&in[inIdx], buf[1].TheAddress, buf[1].Length);
//            inIdx = inIdx + 1;
//
//            /* get input buffers */
//            args[3] = 0;
//            for (i = 2; i < sz && i < MAX_IN_IOVS; i++) {
//                SETIOV(&in[inIdx], buf[i].TheAddress, buf[i].Length);
//                inIdx = inIdx + 1;
//                args[3] += buf[i].Length;
//            }
//
//            SETIOV(&out[outIdx], buf[1].TheAddress, buf[1].Length);
//            outIdx = outIdx + 1;
//        }
//        cmd = WC_CAAM_CMAC;
        break;

    case CAAM_FIFO_S:
//        SETIOV(&in[inIdx], buf[0].TheAddress, buf[0].Length);
//        inIdx = inIdx + 1;
//
//        SETIOV(&out[outIdx], buf[1].TheAddress, buf[1].Length + WC_CAAM_MAC_SZ);
//        outIdx = outIdx + 1;
//        cmd = WC_CAAM_FIFO_S;
        break;

    default:
        WOLFSSL_MSG("Unknown/unsupported type");
        ret = -1;
    }
        wc_UnLockMutex(&caamMutex);
    }

    (void)pubkey;
    (void)privkey;
    (void)sz;
    return wc_TranslateHSMError(ret, err);
}
#endif /* WOLFSSL_SECO_CAAM */

