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
static uint32_t nvm_status;
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


/* Do a synchronous operations and block till done
 * returns 0 on success */
int SynchronousSendRequest(int type, unsigned int args[4], CAAM_BUFFER *buf,
        int sz)
{
    int ret;
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
//        cmd = WC_TRNG_CMD;
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
    return Success;
}
#endif /* WOLFSSL_SECO_CAAM */

