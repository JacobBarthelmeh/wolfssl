/* afalg_aes.c
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
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
#include <wolfssl/wolfcrypt/error-crypt.h>

#if !defined(NO_AES) && defined(WOLFSSL_AFALG)

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/port/af_alg/wc_afalg.h>


#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

static const char WC_TYPE_SYMKEY[] = "skcipher";
static const char WC_NAME_AESCBC[] = "cbc(aes)";

static int wc_AesSetup(Aes* aes, const char* type, const char* name, int ivSz)
{
    aes->rdFd = wc_Afalg_CreateRead(aes->alFd, type, name);
    if (aes->rdFd < 0) {
        WOLFSSL_MSG("Unable to accept and get AF_ALG read socket");
        aes->rdFd = WC_SOCK_NOTSET;
        return aes->rdFd;
    }

    if (setsockopt(aes->alFd, SOL_ALG, ALG_SET_KEY, (byte*)aes->key, aes->keylen) != 0) {
        WOLFSSL_MSG("Unable to set AF_ALG key");
        aes->rdFd = WC_SOCK_NOTSET;
        return WC_AFALG_SOCK_E;
    }
    ForceZero((byte*)aes->key, sizeof(aes->key));

    /* set up CMSG headers */
    XMEMSET((byte*)&(aes->msg), 0, sizeof(struct msghdr));

    aes->msg.msg_control = (byte*)(aes->key); /* use existing key buffer for control buffer */
    aes->msg.msg_controllen = CMSG_SPACE(4);
    if (ivSz > 0) {
    	aes->msg.msg_controllen += CMSG_SPACE((sizeof(struct af_alg_iv) + 16));
    }

    if (wc_Afalg_SetOp(CMSG_FIRSTHDR(&(aes->msg)), aes->dir) < 0) {
        WOLFSSL_MSG("Error with setting AF_ALG operation");
        aes->rdFd = WC_SOCK_NOTSET;
        return -1;
    }

    return 0;
}


int wc_AesSetKey(Aes* aes, const byte* userKey, word32 keylen,
    const byte* iv, int dir)
{
#if defined(AES_MAX_KEY_SIZE)
    const word32 max_key_len = (AES_MAX_KEY_SIZE / 8);
#endif

    if (aes == NULL ||
            !((keylen == 16) || (keylen == 24) || (keylen == 32))) {
        return BAD_FUNC_ARG;
    }

#if defined(AES_MAX_KEY_SIZE)
    /* Check key length */
    if (keylen > max_key_len) {
        return BAD_FUNC_ARG;
    }
#endif
    aes->keylen = keylen;
    aes->rounds = keylen/4 + 6;

    aes->rdFd = WC_SOCK_NOTSET;
    aes->alFd = wc_Afalg_Socket();
    if (aes->alFd < 0) {
         WOLFSSL_MSG("Unable to open an AF_ALG socket");
         return WC_AFALG_SOCK_E;
    }

    /* save key until type is known i.e. CBC, ECB, ... */
    XMEMCPY((byte*)(aes->key), userKey, keylen);
    aes->dir = dir;

    return wc_AesSetIV(aes, iv);
}

#if defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER)
    /* AES-CTR and AES-DIRECT need to use this for key setup, no aesni yet */
    int wc_AesSetKeyDirect(Aes* aes, const byte* userKey, word32 keylen,
                        const byte* iv, int dir)
    {
	return wc_AesSetKey(aes, userKey, keylen, iv, dir);
	}
#endif


/* AES-CBC */
#ifdef HAVE_AES_CBC
    int wc_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
    {
	struct cmsghdr* cmsg;
	struct iovec    iov;
	int ret;

        if (aes == NULL || out == NULL || in == NULL) {
            return BAD_FUNC_ARG;
        }

	if (aes->rdFd == WC_SOCK_NOTSET) {
            if ((ret = wc_AesSetup(aes, WC_TYPE_SYMKEY, WC_NAME_AESCBC, AES_IV_SIZE)) != 0) {
		    WOLFSSL_MSG("Error with first time setup of AF_ALG socket");
		    return ret;
	    }
	}

	sz = sz - (sz % AES_BLOCK_SIZE);
	if ((sz / AES_BLOCK_SIZE) > 0) {
    	/* update IV */
    	cmsg = CMSG_FIRSTHDR(&(aes->msg));
    	ret = wc_Afalg_SetIv(CMSG_NXTHDR(&(aes->msg), cmsg), (byte*)(aes->reg), AES_IV_SIZE);
	if (ret < 0) {
		WOLFSSL_MSG("Error setting IV");
		return ret;
	}
    
    	/* set data to be encrypted */
    	iov.iov_base = (byte*)in;
    	iov.iov_len  = sz;

    	aes->msg.msg_iov    = &iov;
    	aes->msg.msg_iovlen = 1; /* # of iov structures */

    	ret = sendmsg(aes->rdFd, &(aes->msg), 0);
	if (ret < 0) {
		perror("send error");
		return ret;
	}
    	ret = read(aes->rdFd, out, sz);
	if (ret < 0) {
		perror("read error");
		return ret;
	}

    	/* set IV for next CBC call */
    	XMEMCPY(aes->reg, out + sz - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    	}

        return 0;
    }

    #ifdef HAVE_AES_DECRYPT
    int wc_AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
    {
	struct cmsghdr* cmsg;
	struct iovec    iov;
	int ret;


        if (aes == NULL || out == NULL || in == NULL
                                       || sz % AES_BLOCK_SIZE != 0) {
            return BAD_FUNC_ARG;
        }

	if (aes->rdFd == WC_SOCK_NOTSET) {
            if ((ret = wc_AesSetup(aes, WC_TYPE_SYMKEY, WC_NAME_AESCBC, AES_IV_SIZE)) != 0) {
		    return ret;
	    }
	}

	if ((sz / AES_BLOCK_SIZE) > 0) {
    	/* update IV */
    	cmsg = CMSG_FIRSTHDR(&(aes->msg));
    	ret = wc_Afalg_SetIv(CMSG_NXTHDR(&(aes->msg), cmsg), (byte*)(aes->reg), AES_IV_SIZE);
    
    	/* set data to be decrypted */
    	iov.iov_base = (byte*)in;
    	iov.iov_len  = sz;

    	aes->msg.msg_iov    = &iov;
    	aes->msg.msg_iovlen = 1; /* # of iov structures */

    	/* set IV for next CBC call */
    	XMEMCPY(aes->reg, in + sz - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

    	ret = sendmsg(aes->rdFd, &(aes->msg), 0);
	if (ret < 0) {
		return ret;
	}
    	ret = read(aes->rdFd, out, sz);
	if (ret < 0) {
		return ret;
	}

    	}

        return 0;
    }
    #endif

#endif /* HAVE_AES_CBC */


/* AES-CTR */
#if defined(WOLFSSL_AES_COUNTER)
        /* Increment AES counter */
        static WC_INLINE void IncrementAesCounter(byte* inOutCtr)
        {
            /* in network byte order so start at end and work back */
            int i;
            for (i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
                if (++inOutCtr[i])  /* we're done unless we overflow */
                    return;
            }
        }

        int wc_AesCtrEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
        {
            byte* tmp;

            if (aes == NULL || out == NULL || in == NULL) {
                return BAD_FUNC_ARG;
            }

            /* consume any unused bytes left in aes->tmp */
            tmp = (byte*)aes->tmp + AES_BLOCK_SIZE - aes->left;
            while (aes->left && sz) {
               *(out++) = *(in++) ^ *(tmp++);
               aes->left--;
               sz--;
            }

            /* do as many block size ops as possible */
            while (sz >= AES_BLOCK_SIZE) {
            #ifdef XTRANSFORM_AESCTRBLOCK
                XTRANSFORM_AESCTRBLOCK(aes, out, in);
            #else
                wc_AesEncrypt(aes, (byte*)aes->reg, out);
                xorbuf(out, in, AES_BLOCK_SIZE);
            #endif
                IncrementAesCounter((byte*)aes->reg);

                out += AES_BLOCK_SIZE;
                in  += AES_BLOCK_SIZE;
                sz  -= AES_BLOCK_SIZE;
                aes->left = 0;
            }

            /* handle non block size remaining and store unused byte count in left */
            if (sz) {
                wc_AesEncrypt(aes, (byte*)aes->reg, (byte*)aes->tmp);
                IncrementAesCounter((byte*)aes->reg);

                aes->left = AES_BLOCK_SIZE;
                tmp = (byte*)aes->tmp;

                while (sz--) {
                    *(out++) = *(in++) ^ *(tmp++);
                    aes->left--;
                }
            }

            return 0;
        }

#endif /* WOLFSSL_AES_COUNTER */


/*
 * The IV for AES GCM and CCM, stored in struct Aes's member reg, is comprised
 * of two parts in order:
 *   1. The fixed field which may be 0 or 4 bytes long. In TLS, this is set
 *      to the implicit IV.
 *   2. The explicit IV is generated by wolfCrypt. It needs to be managed
 *      by wolfCrypt to ensure the IV is unique for each call to encrypt.
 * The IV may be a 96-bit random value, or the 32-bit fixed value and a
 * 64-bit set of 0 or random data. The final 32-bits of reg is used as a
 * block counter during the encryption.
 */

#if (defined(HAVE_AESGCM) && !defined(WC_NO_RNG)) || defined(HAVE_AESCCM)
static WC_INLINE void IncCtr(byte* ctr, word32 ctrSz)
{
    int i;
    for (i = ctrSz-1; i >= 0; i--) {
        if (++ctr[i])
            break;
    }
}
#endif /* HAVE_AESGCM || HAVE_AESCCM */


#ifdef HAVE_AESGCM

static WC_INLINE void IncrementGcmCounter(byte* inOutCtr)
{
    int i;

    /* in network byte order so start at end and work back */
    for (i = AES_BLOCK_SIZE - 1; i >= AES_BLOCK_SIZE - CTR_SZ; i--) {
        if (++inOutCtr[i])  /* we're done unless we overflow */
            return;
    }
}


int wc_AesGcmSetKey(Aes* aes, const byte* key, word32 len)
{
    int  ret;
    byte iv[AES_BLOCK_SIZE];

    #ifdef WOLFSSL_IMX6_CAAM_BLOB
        byte   local[32];
        word32 localSz = 32;

        if (len == (16 + WC_CAAM_BLOB_SZ) ||
          len == (24 + WC_CAAM_BLOB_SZ) ||
          len == (32 + WC_CAAM_BLOB_SZ)) {
            if (wc_caamOpenBlob((byte*)key, len, local, &localSz) != 0) {
                 return BAD_FUNC_ARG;
            }

            /* set local values */
            key = local;
            len = localSz;
        }
    #endif

    if (!((len == 16) || (len == 24) || (len == 32)))
        return BAD_FUNC_ARG;

    XMEMSET(iv, 0, AES_BLOCK_SIZE);
    ret = wc_AesSetKey(aes, key, len, iv, AES_ENCRYPTION);

    #ifdef WOLFSSL_AESNI
        /* AES-NI code generates its own H value. */
        if (haveAESNI)
            return ret;
    #endif /* WOLFSSL_AESNI */

#if !defined(FREESCALE_LTC_AES_GCM)
    if (ret == 0) {
        wc_AesEncrypt(aes, iv, aes->H);
    #ifdef GCM_TABLE
        GenerateM0(aes);
    #endif /* GCM_TABLE */
    }
#endif /* FREESCALE_LTC_AES_GCM */

#if defined(WOLFSSL_XILINX_CRYPT)
    wc_AesGcmSetKey_ex(aes, key, len, XSECURE_CSU_AES_KEY_SRC_KUP);
#endif

    return ret;
}



#if !defined(WOLFSSL_XILINX_CRYPT)
#ifdef FREESCALE_LTC_AES_GCM
int wc_AesGcmEncrypt(Aes* aes, byte* out, const byte* in, word32 sz,
                   const byte* iv, word32 ivSz,
                   byte* authTag, word32 authTagSz,
                   const byte* authIn, word32 authInSz)
{
    status_t status;
    word32 keySize;

    /* argument checks */
    if (aes == NULL || authTagSz > AES_BLOCK_SIZE) {
        return BAD_FUNC_ARG;
    }

    if (authTagSz < WOLFSSL_MIN_AUTH_TAG_SZ) {
        WOLFSSL_MSG("GcmEncrypt authTagSz too small error");
        return BAD_FUNC_ARG;
    }

    status = wc_AesGetKeySize(aes, &keySize);
    if (status)
        return status;

    status = LTC_AES_EncryptTagGcm(LTC_BASE, in, out, sz, iv, ivSz,
        authIn, authInSz, (byte*)aes->key, keySize, authTag, authTagSz);

    return (status == kStatus_Success) ? 0 : AES_GCM_AUTH_E;
}
#else
#if defined(STM32_CRYPTO) && (defined(WOLFSSL_STM32F4) || \
                              defined(WOLFSSL_STM32F7) || \
                              defined(WOLFSSL_STM32L4))

static WC_INLINE int wc_AesGcmEncrypt_STM32(Aes* aes, byte* out, const byte* in,
                                         word32 sz, const byte* iv, word32 ivSz,
                                         byte* authTag, word32 authTagSz,
                                         const byte* authIn, word32 authInSz)
{
    int ret;
    word32 keySize;
    byte initialCounter[AES_BLOCK_SIZE];
    #ifdef WOLFSSL_STM32_CUBEMX
        CRYP_HandleTypeDef hcryp;
    #else
        byte keyCopy[AES_BLOCK_SIZE * 2];
    #endif /* WOLFSSL_STM32_CUBEMX */
    int status = 0;
    byte* authInPadded = NULL;
    byte tag[AES_BLOCK_SIZE];
    int authPadSz;

    ret = wc_AesGetKeySize(aes, &keySize);
    if (ret != 0)
        return ret;

    XMEMSET(initialCounter, 0, AES_BLOCK_SIZE);
    XMEMCPY(initialCounter, iv, ivSz);
    initialCounter[AES_BLOCK_SIZE - 1] = STM32_GCM_IV_START;

    /* pad authIn if it is not a block multiple */
    if ((authInSz % AES_BLOCK_SIZE) != 0) {
        authPadSz = ((authInSz / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
        /* Need to pad the AAD to a full block with zeros. */
        authInPadded = XMALLOC(authPadSz, aes->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (authInPadded == NULL) {
            return MEMORY_E;
        }
        XMEMSET(authInPadded, 0, authPadSz);
        XMEMCPY(authInPadded, authIn, authInSz);
    } else {
        authPadSz = authInSz;
        authInPadded = (byte*)authIn;
    }


#ifdef WOLFSSL_STM32_CUBEMX
    XMEMSET(&hcryp, 0, sizeof(CRYP_HandleTypeDef));
    switch (keySize) {
        case 16: /* 128-bit key */
            hcryp.Init.KeySize = CRYP_KEYSIZE_128B;
            break;
#ifdef CRYP_KEYSIZE_192B
        case 24: /* 192-bit key */
            hcryp.Init.KeySize = CRYP_KEYSIZE_192B;
            break;
#endif
    	case 32: /* 256-bit key */
            hcryp.Init.KeySize = CRYP_KEYSIZE_256B;
            break;
        default:
            break;
    }
    hcryp.Instance = CRYP;
    hcryp.Init.DataType = CRYP_DATATYPE_8B;
    hcryp.Init.pKey = (byte*)aes->key;
    hcryp.Init.pInitVect = initialCounter;
    hcryp.Init.Header = authInPadded;
    hcryp.Init.HeaderSize = authInSz;

#ifdef WOLFSSL_STM32L4
    /* Set the CRYP parameters */
    hcryp.Init.ChainingMode  = CRYP_CHAINMODE_AES_GCM_GMAC;
    hcryp.Init.OperatingMode = CRYP_ALGOMODE_ENCRYPT;
    hcryp.Init.GCMCMACPhase  = CRYP_INIT_PHASE;
    HAL_CRYP_Init(&hcryp);

    /* GCM init phase */
    status = HAL_CRYPEx_AES_Auth(&hcryp, NULL, 0, NULL, STM32_HAL_TIMEOUT);
    if (status == HAL_OK) {
        /* GCM header phase */
        hcryp.Init.GCMCMACPhase  = CRYP_HEADER_PHASE;
        status = HAL_CRYPEx_AES_Auth(&hcryp, NULL, 0, NULL, STM32_HAL_TIMEOUT);
        if (status == HAL_OK) {
            /* GCM payload phase */
            hcryp.Init.GCMCMACPhase  = CRYP_PAYLOAD_PHASE;
            status = HAL_CRYPEx_AES_Auth(&hcryp, (byte*)in, sz, out, STM32_HAL_TIMEOUT);
            if (status == HAL_OK) {
                /* GCM final phase */
                hcryp.Init.GCMCMACPhase  = CRYP_FINAL_PHASE;
                status = HAL_CRYPEx_AES_Auth(&hcryp, NULL, sz, tag, STM32_HAL_TIMEOUT);
            }
        }
    }
#else
    HAL_CRYP_Init(&hcryp);

    status = HAL_CRYPEx_AESGCM_Encrypt(&hcryp, (byte*)in, sz,
                                       out, STM32_HAL_TIMEOUT);
    /* Compute the authTag */
    if (status == HAL_OK) {
        status = HAL_CRYPEx_AESGCM_Finish(&hcryp, sz, tag, STM32_HAL_TIMEOUT);
    }
#endif

    if (status != HAL_OK)
        ret = AES_GCM_AUTH_E;
    HAL_CRYP_DeInit(&hcryp);
#else
    ByteReverseWords((word32*)keyCopy, (word32*)aes->key, keySize);
    status = CRYP_AES_GCM(MODE_ENCRYPT, (uint8_t*)initialCounter,
                         (uint8_t*)keyCopy,     keySize * 8,
                         (uint8_t*)in,          sz,
                         (uint8_t*)authInPadded,authInSz,
                         (uint8_t*)out,         tag);
    if (status != SUCCESS)
        ret = AES_GCM_AUTH_E;
#endif /* WOLFSSL_STM32_CUBEMX */

    /* authTag may be shorter than AES_BLOCK_SZ, store separately */
    if (ret == 0)
    	XMEMCPY(authTag, tag, authTagSz);

    /* We only allocate extra memory if authInPadded is not a multiple of AES_BLOCK_SZ */
    if (authInPadded != NULL && authInSz != authPadSz) {
        XFREE(authInPadded, aes->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
}
#endif /* STM32_CRYPTO */

#ifdef WOLFSSL_AESNI
int AES_GCM_encrypt_C(Aes* aes, byte* out, const byte* in, word32 sz,
                      const byte* iv, word32 ivSz,
                      byte* authTag, word32 authTagSz,
                      const byte* authIn, word32 authInSz);
#else
static
#endif
int AES_GCM_encrypt_C(Aes* aes, byte* out, const byte* in, word32 sz,
                      const byte* iv, word32 ivSz,
                      byte* authTag, word32 authTagSz,
                      const byte* authIn, word32 authInSz)
{
    int ret = 0;
    word32 blocks = sz / AES_BLOCK_SIZE;
    word32 partial = sz % AES_BLOCK_SIZE;
    const byte* p = in;
    byte* c = out;
    byte counter[AES_BLOCK_SIZE];
    byte initialCounter[AES_BLOCK_SIZE];
    byte *ctr;
    byte scratch[AES_BLOCK_SIZE];

    ctr = counter;
    XMEMSET(initialCounter, 0, AES_BLOCK_SIZE);
    if (ivSz == GCM_NONCE_MID_SZ) {
        XMEMCPY(initialCounter, iv, ivSz);
        initialCounter[AES_BLOCK_SIZE - 1] = 1;
    }
    else {
        GHASH(aes, NULL, 0, iv, ivSz, initialCounter, AES_BLOCK_SIZE);
    }
    XMEMCPY(ctr, initialCounter, AES_BLOCK_SIZE);

#ifdef WOLFSSL_PIC32MZ_CRYPT
    if (blocks) {
        /* use intitial IV for PIC32 HW, but don't use it below */
        XMEMCPY(aes->reg, ctr, AES_BLOCK_SIZE);

        ret = wc_Pic32AesCrypt(
            aes->key, aes->keylen, aes->reg, AES_BLOCK_SIZE,
            out, in, (blocks * AES_BLOCK_SIZE),
            PIC32_ENCRYPTION, PIC32_ALGO_AES, PIC32_CRYPTOALGO_AES_GCM);
        if (ret != 0)
            return ret;
    }
    /* process remainder using partial handling */
#endif

#if defined(HAVE_AES_ECB) && !defined(WOLFSSL_PIC32MZ_CRYPT)
    /* some hardware acceleration can gain performance from doing AES encryption
     * of the whole buffer at once */
    if (c != p) { /* can not handle inline encryption */
        while (blocks--) {
            IncrementGcmCounter(ctr);
            XMEMCPY(c, ctr, AES_BLOCK_SIZE);
            c += AES_BLOCK_SIZE;
        }

        /* reset number of blocks and then do encryption */
        blocks = sz / AES_BLOCK_SIZE;
        wc_AesEcbEncrypt(aes, out, out, AES_BLOCK_SIZE * blocks);
        xorbuf(out, p, AES_BLOCK_SIZE * blocks);
        p += AES_BLOCK_SIZE * blocks;
    }
    else
#endif /* HAVE_AES_ECB */

    while (blocks--) {
        IncrementGcmCounter(ctr);
    #ifndef WOLFSSL_PIC32MZ_CRYPT
        wc_AesEncrypt(aes, ctr, scratch);
        xorbuf(scratch, p, AES_BLOCK_SIZE);
        XMEMCPY(c, scratch, AES_BLOCK_SIZE);
    #endif
        p += AES_BLOCK_SIZE;
        c += AES_BLOCK_SIZE;
    }

    if (partial != 0) {
        IncrementGcmCounter(ctr);
        wc_AesEncrypt(aes, ctr, scratch);
        xorbuf(scratch, p, partial);
        XMEMCPY(c, scratch, partial);
    }

    GHASH(aes, authIn, authInSz, out, sz, authTag, authTagSz);
    wc_AesEncrypt(aes, initialCounter, scratch);
    xorbuf(authTag, scratch, authTagSz);

    return ret;
}

int wc_AesGcmEncrypt(Aes* aes, byte* out, const byte* in, word32 sz,
                   const byte* iv, word32 ivSz,
                   byte* authTag, word32 authTagSz,
                   const byte* authIn, word32 authInSz)
{
    /* argument checks */
    if (aes == NULL || authTagSz > AES_BLOCK_SIZE) {
        return BAD_FUNC_ARG;
    }

    if (authTagSz < WOLFSSL_MIN_AUTH_TAG_SZ) {
        WOLFSSL_MSG("GcmEncrypt authTagSz too small error");
        return BAD_FUNC_ARG;
    }

#if defined(STM32_CRYPTO) && (defined(WOLFSSL_STM32F4) || \
                              defined(WOLFSSL_STM32F7) || \
                              defined(WOLFSSL_STM32L4))

    /* additional argument checks - STM32 HW only supports 12 byte IV */
    if (ivSz != GCM_NONCE_MID_SZ) {
        return BAD_FUNC_ARG;
    }

    /* STM32 HW AES-GCM requires / assumes inputs are a multiple of block size.
     * We can avoid this by zero padding (authIn) AAD, but zero-padded plaintext
     * will be encrypted and output incorrectly, causing a bad authTag.
     * We will use HW accelerated AES-GCM if plain%AES_BLOCK_SZ==0.
     * Otherwise, we will use accelerated AES_CTR for encrypt, and then
     * perform GHASH in software.
     * See NIST SP 800-38D */

    /* Plain text is a multiple of block size, so use HW-Accelerated AES_GCM */
    if (sz % AES_BLOCK_SIZE == 0) {
        return wc_AesGcmEncrypt_STM32(aes, out, in, sz, iv, ivSz,
                                      authTag, authTagSz, authIn, authInSz);
    }
#endif

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_AES)
    /* if async and byte count above threshold */
    /* only 12-byte IV is supported in HW */
    if (aes->asyncDev.marker == WOLFSSL_ASYNC_MARKER_AES &&
                    sz >= WC_ASYNC_THRESH_AES_GCM && ivSz == GCM_NONCE_MID_SZ) {
    #if defined(HAVE_CAVIUM)
        #ifdef HAVE_CAVIUM_V
        if (authInSz == 20) { /* Nitrox V GCM is only working with 20 byte AAD */
            return NitroxAesGcmEncrypt(aes, out, in, sz,
                (const byte*)aes->asyncKey, aes->keylen, iv, ivSz,
                authTag, authTagSz, authIn, authInSz);
        }
        #endif
    #elif defined(HAVE_INTEL_QA)
        return IntelQaSymAesGcmEncrypt(&aes->asyncDev, out, in, sz,
            (const byte*)aes->asyncKey, aes->keylen, iv, ivSz,
            authTag, authTagSz, authIn, authInSz);
    #else /* WOLFSSL_ASYNC_CRYPT_TEST */
        if (wc_AsyncTestInit(&aes->asyncDev, ASYNC_TEST_AES_GCM_ENCRYPT)) {
            WC_ASYNC_TEST* testDev = &aes->asyncDev.test;
            testDev->aes.aes = aes;
            testDev->aes.out = out;
            testDev->aes.in = in;
            testDev->aes.sz = sz;
            testDev->aes.iv = iv;
            testDev->aes.ivSz = ivSz;
            testDev->aes.authTag = authTag;
            testDev->aes.authTagSz = authTagSz;
            testDev->aes.authIn = authIn;
            testDev->aes.authInSz = authInSz;
            return WC_PENDING_E;
        }
    #endif
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    /* Software AES-GCM */

#ifdef WOLFSSL_AESNI
    #ifdef HAVE_INTEL_AVX2
    if (IS_INTEL_AVX2(intel_flags)) {
        AES_GCM_encrypt_avx2(in, out, authIn, iv, authTag, sz, authInSz, ivSz,
                                 authTagSz, (const byte*)aes->key, aes->rounds);
        return 0;
    }
    else
    #endif
    #ifdef HAVE_INTEL_AVX1
    if (IS_INTEL_AVX1(intel_flags)) {
        AES_GCM_encrypt_avx1(in, out, authIn, iv, authTag, sz, authInSz, ivSz,
                                 authTagSz, (const byte*)aes->key, aes->rounds);
        return 0;
    }
    else
    #endif
    if (haveAESNI) {
        AES_GCM_encrypt(in, out, authIn, iv, authTag, sz, authInSz, ivSz,
                                 authTagSz, (const byte*)aes->key, aes->rounds);
        return 0;
    }
    else
#endif
    {
        return AES_GCM_encrypt_C(aes, out, in, sz, iv, ivSz, authTag, authTagSz,
                                                              authIn, authInSz);
    }
}
#endif


#if defined(HAVE_AES_DECRYPT) || defined(HAVE_AESGCM_DECRYPT)
#ifdef FREESCALE_LTC_AES_GCM
int  wc_AesGcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
                   const byte* iv, word32 ivSz,
                   const byte* authTag, word32 authTagSz,
                   const byte* authIn, word32 authInSz)
{
    int ret;
    word32 keySize;
    status_t status;

    /* argument checks */
    if (aes == NULL || out == NULL || in == NULL || iv == NULL ||
        authTag == NULL || authTagSz > AES_BLOCK_SIZE) {
        return BAD_FUNC_ARG;
    }

    ret = wc_AesGetKeySize(aes, &keySize);
    if (ret != 0) {
        return ret;
    }

    status = LTC_AES_DecryptTagGcm(LTC_BASE, in, out, sz, iv, ivSz,
        authIn, authInSz, (byte*)aes->key, keySize, authTag, authTagSz);

    return (status == kStatus_Success) ? 0 : AES_GCM_AUTH_E;
}
#elif defined(STM32_CRYPTO) && (defined(WOLFSSL_STM32F4) || \
                                defined(WOLFSSL_STM32F7) || \
                                defined(WOLFSSL_STM32L4))
int  wc_AesGcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
                   const byte* iv, word32 ivSz,
                   const byte* authTag, word32 authTagSz,
                   const byte* authIn, word32 authInSz)
{
    int ret;
    word32 keySize;
    #ifdef WOLFSSL_STM32_CUBEMX
        CRYP_HandleTypeDef hcryp;
    #else
        byte keyCopy[AES_BLOCK_SIZE * 2];
    #endif /* WOLFSSL_STM32_CUBEMX */
    int  status;
    int  inPadSz, authPadSz;
    byte tag[AES_BLOCK_SIZE];
    byte *inPadded = NULL;
    byte *authInPadded = NULL;
    byte initialCounter[AES_BLOCK_SIZE];

    /* argument checks */
    if (aes == NULL || out == NULL || in == NULL || iv == NULL ||
        authTag == NULL || authTagSz > AES_BLOCK_SIZE) {
        return BAD_FUNC_ARG;
    }

    ret = wc_AesGetKeySize(aes, &keySize);
    if (ret != 0) {
        return ret;
    }

    /* additional argument checks - STM32 HW only supports 12 byte IV */
    if (ivSz != GCM_NONCE_MID_SZ) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(initialCounter, 0, AES_BLOCK_SIZE);
    XMEMCPY(initialCounter, iv, ivSz);
    initialCounter[AES_BLOCK_SIZE - 1] = STM32_GCM_IV_START;

    /* Need to pad the AAD and input cipher text to a full block size since
     * CRYP_AES_GCM will assume these are a multiple of AES_BLOCK_SIZE.
     * It is okay to pad with zeros because GCM does this before GHASH already.
     * See NIST SP 800-38D */

    if ((sz % AES_BLOCK_SIZE) > 0) {
        inPadSz = ((sz / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
        inPadded = XMALLOC(inPadSz, aes->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (inPadded == NULL) {
            return MEMORY_E;
        }
        XMEMSET(inPadded, 0, inPadSz);
        XMEMCPY(inPadded, in, sz);
    } else {
        inPadSz = sz;
        inPadded = (byte*)in;
    }

    if ((authInSz % AES_BLOCK_SIZE) > 0) {
        authPadSz = ((authInSz / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
        authInPadded = XMALLOC(authPadSz, aes->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (authInPadded == NULL) {
            if (inPadded != NULL && inPadSz != sz)
                XFREE(inPadded , aes->heap, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }
        XMEMSET(authInPadded, 0, authPadSz);
        XMEMCPY(authInPadded, authIn, authInSz);
    } else {
        authPadSz = authInSz;
        authInPadded = (byte*)authIn;
    }

#ifdef WOLFSSL_STM32_CUBEMX
    XMEMSET(&hcryp, 0, sizeof(CRYP_HandleTypeDef));
    switch(keySize) {
        case 16: /* 128-bit key */
            hcryp.Init.KeySize = CRYP_KEYSIZE_128B;
            break;
#ifdef CRYP_KEYSIZE_192B
        case 24: /* 192-bit key */
            hcryp.Init.KeySize = CRYP_KEYSIZE_192B;
            break;
#endif
        case 32: /* 256-bit key */
            hcryp.Init.KeySize = CRYP_KEYSIZE_256B;
            break;
        default:
            break;
    }
    hcryp.Instance = CRYP;
    hcryp.Init.DataType = CRYP_DATATYPE_8B;
    hcryp.Init.pKey = (byte*)aes->key;
    hcryp.Init.pInitVect = initialCounter;
    hcryp.Init.Header = authInPadded;
    hcryp.Init.HeaderSize = authInSz;

#ifdef WOLFSSL_STM32L4
    /* Set the CRYP parameters */
    hcryp.Init.ChainingMode  = CRYP_CHAINMODE_AES_GCM_GMAC;
    hcryp.Init.OperatingMode = CRYP_ALGOMODE_DECRYPT;
    hcryp.Init.GCMCMACPhase  = CRYP_INIT_PHASE;
    HAL_CRYP_Init(&hcryp);

    /* GCM init phase */
    status = HAL_CRYPEx_AES_Auth(&hcryp, NULL, 0, NULL, STM32_HAL_TIMEOUT);
    if (status == HAL_OK) {
        /* GCM header phase */
        hcryp.Init.GCMCMACPhase  = CRYP_HEADER_PHASE;
        status = HAL_CRYPEx_AES_Auth(&hcryp, NULL, 0, NULL, STM32_HAL_TIMEOUT);
        if (status == HAL_OK) {
            /* GCM payload phase */
            hcryp.Init.GCMCMACPhase  = CRYP_PAYLOAD_PHASE;
            status = HAL_CRYPEx_AES_Auth(&hcryp, (byte*)inPadded, sz, inPadded,
                STM32_HAL_TIMEOUT);
            if (status == HAL_OK) {
                /* GCM final phase */
                hcryp.Init.GCMCMACPhase  = CRYP_FINAL_PHASE;
                status = HAL_CRYPEx_AES_Auth(&hcryp, NULL, sz, tag,
                    STM32_HAL_TIMEOUT);
            }
        }
    }
#else
    HAL_CRYP_Init(&hcryp);
    /* Use inPadded for output buffer instead of
    * out so that we don't overflow our size. */
    status = HAL_CRYPEx_AESGCM_Decrypt(&hcryp, (byte*)inPadded,
                                    sz, inPadded, STM32_HAL_TIMEOUT);
    /* Compute the authTag */
    if (status == HAL_OK) {
        status = HAL_CRYPEx_AESGCM_Finish(&hcryp, sz, tag, STM32_HAL_TIMEOUT);
    }
#endif

    if (status != HAL_OK)
        ret = AES_GCM_AUTH_E;

    HAL_CRYP_DeInit(&hcryp);
#else
    ByteReverseWords((word32*)keyCopy, (word32*)aes->key, keySize);

    /* Input size and auth size need to be the actual sizes, even though
     * they are not block aligned, because this length (in bits) is used
     * in the final GHASH. Use inPadded for output buffer instead of
     * out so that we don't overflow our size.                         */
    status = CRYP_AES_GCM(MODE_DECRYPT, (uint8_t*)initialCounter,
                         (uint8_t*)keyCopy,     keySize * 8,
                         (uint8_t*)inPadded,    sz,
                         (uint8_t*)authInPadded,authInSz,
                         (uint8_t*)inPadded,    tag);
    if (status != SUCCESS)
        ret = AES_GCM_AUTH_E;
#endif /* WOLFSSL_STM32_CUBEMX */

    if (ret == 0 && ConstantCompare(authTag, tag, authTagSz) == 0) {
        /* Only keep the decrypted data if authTag success. */
        XMEMCPY(out, inPadded, sz);
        ret = 0; /* success */
    }

    /* only allocate padding buffers if the inputs are not a multiple of block sz */
    if (inPadded != NULL && inPadSz != sz)
        XFREE(inPadded , aes->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (authInPadded != NULL && authPadSz != authInSz)
        XFREE(authInPadded, aes->heap, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}
#else
#ifdef WOLFSSL_AESNI
int AES_GCM_decrypt_C(Aes* aes, byte* out, const byte* in, word32 sz,
                      const byte* iv, word32 ivSz,
                      const byte* authTag, word32 authTagSz,
                      const byte* authIn, word32 authInSz);
#else
static
#endif
int AES_GCM_decrypt_C(Aes* aes, byte* out, const byte* in, word32 sz,
                      const byte* iv, word32 ivSz,
                      const byte* authTag, word32 authTagSz,
                      const byte* authIn, word32 authInSz)
{
    int ret = 0;
    word32 blocks = sz / AES_BLOCK_SIZE;
    word32 partial = sz % AES_BLOCK_SIZE;
    const byte* c = in;
    byte* p = out;
    byte counter[AES_BLOCK_SIZE];
    byte initialCounter[AES_BLOCK_SIZE];
    byte *ctr;
    byte scratch[AES_BLOCK_SIZE];
    byte Tprime[AES_BLOCK_SIZE];
    byte EKY0[AES_BLOCK_SIZE];
    ctr = counter;

    XMEMSET(initialCounter, 0, AES_BLOCK_SIZE);
    if (ivSz == GCM_NONCE_MID_SZ) {
        XMEMCPY(initialCounter, iv, ivSz);
        initialCounter[AES_BLOCK_SIZE - 1] = 1;
    }
    else {
        GHASH(aes, NULL, 0, iv, ivSz, initialCounter, AES_BLOCK_SIZE);
    }
    XMEMCPY(ctr, initialCounter, AES_BLOCK_SIZE);

    /* Calc the authTag again using the received auth data and the cipher text */
    GHASH(aes, authIn, authInSz, in, sz, Tprime, sizeof(Tprime));
    wc_AesEncrypt(aes, ctr, EKY0);
    xorbuf(Tprime, EKY0, sizeof(Tprime));

    if (ConstantCompare(authTag, Tprime, authTagSz) != 0) {
        return AES_GCM_AUTH_E;
    }

#ifdef WOLFSSL_PIC32MZ_CRYPT
    if (blocks) {
        /* use intitial IV for PIC32 HW, but don't use it below */
        XMEMCPY(aes->reg, ctr, AES_BLOCK_SIZE);

        ret = wc_Pic32AesCrypt(
            aes->key, aes->keylen, aes->reg, AES_BLOCK_SIZE,
            out, in, (blocks * AES_BLOCK_SIZE),
            PIC32_DECRYPTION, PIC32_ALGO_AES, PIC32_CRYPTOALGO_AES_GCM);
        if (ret != 0)
            return ret;
    }
    /* process remainder using partial handling */
#endif

#if defined(HAVE_AES_ECB) && !defined(WOLFSSL_PIC32MZ_CRYPT)
    /* some hardware acceleration can gain performance from doing AES encryption
     * of the whole buffer at once */
    if (c != p) { /* can not handle inline decryption */
        while (blocks--) {
            IncrementGcmCounter(ctr);
            XMEMCPY(p, ctr, AES_BLOCK_SIZE);
            p += AES_BLOCK_SIZE;
        }

        /* reset number of blocks and then do encryption */
        blocks = sz / AES_BLOCK_SIZE;
        wc_AesEcbEncrypt(aes, out, out, AES_BLOCK_SIZE * blocks);
        xorbuf(out, c, AES_BLOCK_SIZE * blocks);
        c += AES_BLOCK_SIZE * blocks;
    }
    else
#endif /* HAVE_AES_ECB */
    while (blocks--) {
        IncrementGcmCounter(ctr);
    #ifndef WOLFSSL_PIC32MZ_CRYPT
        wc_AesEncrypt(aes, ctr, scratch);
        xorbuf(scratch, c, AES_BLOCK_SIZE);
        XMEMCPY(p, scratch, AES_BLOCK_SIZE);
    #endif
        p += AES_BLOCK_SIZE;
        c += AES_BLOCK_SIZE;
    }

    if (partial != 0) {
        IncrementGcmCounter(ctr);
        wc_AesEncrypt(aes, ctr, scratch);
        xorbuf(scratch, c, partial);
        XMEMCPY(p, scratch, partial);
    }

    return ret;
}

int wc_AesGcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
                     const byte* iv, word32 ivSz,
                     const byte* authTag, word32 authTagSz,
                     const byte* authIn, word32 authInSz)
{
#ifdef WOLFSSL_AESNI
    int res;
#endif

    /* argument checks */
    /* If the sz is non-zero, both in and out must be set. If sz is 0,
     * in and out are don't cares, as this is is the GMAC case. */
    if (aes == NULL || iv == NULL || (sz != 0 && (in == NULL || out == NULL)) ||
        authTag == NULL || authTagSz > AES_BLOCK_SIZE || authTagSz == 0) {

        return BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_AES)
    /* if async and byte count above threshold */
    /* only 12-byte IV is supported in HW */
    if (aes->asyncDev.marker == WOLFSSL_ASYNC_MARKER_AES &&
                    sz >= WC_ASYNC_THRESH_AES_GCM && ivSz == GCM_NONCE_MID_SZ) {
    #if defined(HAVE_CAVIUM)
        #ifdef HAVE_CAVIUM_V
        if (authInSz == 20) { /* Nitrox V GCM is only working with 20 byte AAD */
            return NitroxAesGcmDecrypt(aes, out, in, sz,
                (const byte*)aes->asyncKey, aes->keylen, iv, ivSz,
                authTag, authTagSz, authIn, authInSz);
        }
        #endif
    #elif defined(HAVE_INTEL_QA)
        return IntelQaSymAesGcmDecrypt(&aes->asyncDev, out, in, sz,
            (const byte*)aes->asyncKey, aes->keylen, iv, ivSz,
            authTag, authTagSz, authIn, authInSz);
    #else /* WOLFSSL_ASYNC_CRYPT_TEST */
        if (wc_AsyncTestInit(&aes->asyncDev, ASYNC_TEST_AES_GCM_DECRYPT)) {
            WC_ASYNC_TEST* testDev = &aes->asyncDev.test;
            testDev->aes.aes = aes;
            testDev->aes.out = out;
            testDev->aes.in = in;
            testDev->aes.sz = sz;
            testDev->aes.iv = iv;
            testDev->aes.ivSz = ivSz;
            testDev->aes.authTag = (byte*)authTag;
            testDev->aes.authTagSz = authTagSz;
            testDev->aes.authIn = authIn;
            testDev->aes.authInSz = authInSz;
            return WC_PENDING_E;
        }
    #endif
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    /* software AES GCM */

#ifdef WOLFSSL_AESNI
    #ifdef HAVE_INTEL_AVX2
    if (IS_INTEL_AVX2(intel_flags)) {
        AES_GCM_decrypt_avx2(in, out, authIn, iv, authTag, sz, authInSz, ivSz,
                                 authTagSz, (byte*)aes->key, aes->rounds, &res);
        if (res == 0)
            return AES_GCM_AUTH_E;
        return 0;
    }
    else
    #endif
    #ifdef HAVE_INTEL_AVX1
    if (IS_INTEL_AVX1(intel_flags)) {
        AES_GCM_decrypt_avx1(in, out, authIn, iv, authTag, sz, authInSz, ivSz,
                                 authTagSz, (byte*)aes->key, aes->rounds, &res);
        if (res == 0)
            return AES_GCM_AUTH_E;
        return 0;
    }
    else
    #endif
    if (haveAESNI) {
        AES_GCM_decrypt(in, out, authIn, iv, authTag, sz, authInSz, ivSz,
                                 authTagSz, (byte*)aes->key, aes->rounds, &res);
        if (res == 0)
            return AES_GCM_AUTH_E;
        return 0;
    }
    else
#endif
    {
        return AES_GCM_decrypt_C(aes, out, in, sz, iv, ivSz, authTag, authTagSz,
                                                              authIn, authInSz);
    }
}
#endif
#endif /* HAVE_AES_DECRYPT || HAVE_AESGCM_DECRYPT */
#endif /* (WOLFSSL_XILINX_CRYPT) */


/* Common to all, abstract functions that build off of lower level AESGCM
 * functions */
#ifndef WC_NO_RNG

int wc_AesGcmSetExtIV(Aes* aes, const byte* iv, word32 ivSz)
{
    int ret = 0;

    if (aes == NULL || iv == NULL ||
        (ivSz != GCM_NONCE_MIN_SZ && ivSz != GCM_NONCE_MID_SZ &&
         ivSz != GCM_NONCE_MAX_SZ)) {

        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        XMEMCPY((byte*)aes->reg, iv, ivSz);

        /* If the IV is 96, allow for a 2^64 invocation counter.
         * For any other size for the nonce, limit the invocation
         * counter to 32-bits. (SP 800-38D 8.3) */
        aes->invokeCtr[0] = 0;
        aes->invokeCtr[1] = (ivSz == GCM_NONCE_MID_SZ) ? 0 : 0xFFFFFFFF;
        aes->nonceSz = ivSz;
    }

    return ret;
}


int wc_AesGcmSetIV(Aes* aes, word32 ivSz,
                   const byte* ivFixed, word32 ivFixedSz,
                   WC_RNG* rng)
{
    int ret = 0;

    if (aes == NULL || rng == NULL ||
        (ivSz != GCM_NONCE_MIN_SZ && ivSz != GCM_NONCE_MID_SZ &&
         ivSz != GCM_NONCE_MAX_SZ) ||
        (ivFixed == NULL && ivFixedSz != 0) ||
        (ivFixed != NULL && ivFixedSz != AES_IV_FIXED_SZ)) {

        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        byte* iv = (byte*)aes->reg;

        if (ivFixedSz)
            XMEMCPY(iv, ivFixed, ivFixedSz);

        ret = wc_RNG_GenerateBlock(rng, iv + ivFixedSz, ivSz - ivFixedSz);
    }

    if (ret == 0) {
        /* If the IV is 96, allow for a 2^64 invocation counter.
         * For any other size for the nonce, limit the invocation
         * counter to 32-bits. (SP 800-38D 8.3) */
        aes->invokeCtr[0] = 0;
        aes->invokeCtr[1] = (ivSz == GCM_NONCE_MID_SZ) ? 0 : 0xFFFFFFFF;
        aes->nonceSz = ivSz;
    }

    return ret;
}


int wc_AesGcmEncrypt_ex(Aes* aes, byte* out, const byte* in, word32 sz,
                        byte* ivOut, word32 ivOutSz,
                        byte* authTag, word32 authTagSz,
                        const byte* authIn, word32 authInSz)
{
    int ret = 0;

    if (aes == NULL || (sz != 0 && (in == NULL || out == NULL)) ||
        ivOut == NULL || ivOutSz != aes->nonceSz ||
        (authIn == NULL && authInSz != 0)) {

        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        aes->invokeCtr[0]++;
        if (aes->invokeCtr[0] == 0) {
            aes->invokeCtr[1]++;
            if (aes->invokeCtr[1] == 0)
                ret = AES_GCM_OVERFLOW_E;
        }
    }

    if (ret == 0) {
        XMEMCPY(ivOut, aes->reg, ivOutSz);
        ret = wc_AesGcmEncrypt(aes, out, in, sz,
                               (byte*)aes->reg, ivOutSz,
                               authTag, authTagSz,
                               authIn, authInSz);
        IncCtr((byte*)aes->reg, ivOutSz);
    }

    return ret;
}

int wc_Gmac(const byte* key, word32 keySz, byte* iv, word32 ivSz,
            const byte* authIn, word32 authInSz,
            byte* authTag, word32 authTagSz, WC_RNG* rng)
{
    Aes aes;
    int ret = 0;

    if (key == NULL || iv == NULL || (authIn == NULL && authInSz != 0) ||
        authTag == NULL || authTagSz == 0 || rng == NULL) {

        ret = BAD_FUNC_ARG;
    }

    if (ret == 0)
        ret = wc_AesGcmSetKey(&aes, key, keySz);
    if (ret == 0)
        ret = wc_AesGcmSetIV(&aes, ivSz, NULL, 0, rng);
    if (ret == 0)
        ret = wc_AesGcmEncrypt_ex(&aes, NULL, NULL, 0, iv, ivSz,
                                  authTag, authTagSz, authIn, authInSz);
    ForceZero(&aes, sizeof(aes));

    return ret;
}

int wc_GmacVerify(const byte* key, word32 keySz,
                  const byte* iv, word32 ivSz,
                  const byte* authIn, word32 authInSz,
                  const byte* authTag, word32 authTagSz)
{
    Aes aes;
    int ret = 0;

    if (key == NULL || iv == NULL || (authIn == NULL && authInSz != 0) ||
        authTag == NULL || authTagSz == 0 || authTagSz > AES_BLOCK_SIZE) {

        ret = BAD_FUNC_ARG;
    }

    if (ret == 0)
        ret = wc_AesGcmSetKey(&aes, key, keySz);
    if (ret == 0)
        ret = wc_AesGcmDecrypt(&aes, NULL, NULL, 0, iv, ivSz,
                                  authTag, authTagSz, authIn, authInSz);
    ForceZero(&aes, sizeof(aes));

    return ret;
}

#endif /* WC_NO_RNG */


WOLFSSL_API int wc_GmacSetKey(Gmac* gmac, const byte* key, word32 len)
{
    if (gmac == NULL || key == NULL) {
        return BAD_FUNC_ARG;
    }
    return wc_AesGcmSetKey(&gmac->aes, key, len);
}


WOLFSSL_API int wc_GmacUpdate(Gmac* gmac, const byte* iv, word32 ivSz,
                              const byte* authIn, word32 authInSz,
                              byte* authTag, word32 authTagSz)
{
    return wc_AesGcmEncrypt(&gmac->aes, NULL, NULL, 0, iv, ivSz,
                                         authTag, authTagSz, authIn, authInSz);
}

#endif /* HAVE_AESGCM */


#ifdef HAVE_AESCCM

int wc_AesCcmSetKey(Aes* aes, const byte* key, word32 keySz)
{
    if (!((keySz == 16) || (keySz == 24) || (keySz == 32)))
        return BAD_FUNC_ARG;

    return wc_AesSetKey(aes, key, keySz, NULL, AES_ENCRYPTION);
}

#ifdef WOLFSSL_ARMASM
    /* implementation located in wolfcrypt/src/port/arm/armv8-aes.c */

#elif defined(HAVE_COLDFIRE_SEC)
    #error "Coldfire SEC doesn't currently support AES-CCM mode"

#elif defined(WOLFSSL_IMX6_CAAM) && !defined(NO_IMX6_CAAM_AES)
    /* implemented in wolfcrypt/src/port/caam_aes.c */

#elif defined(FREESCALE_LTC)

/* return 0 on success */
int wc_AesCcmEncrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
                   const byte* nonce, word32 nonceSz,
                   byte* authTag, word32 authTagSz,
                   const byte* authIn, word32 authInSz)
{
    byte *key;
    uint32_t keySize;
    status_t status;

    /* sanity check on arguments */
    if (aes == NULL || out == NULL || in == NULL || nonce == NULL
            || authTag == NULL || nonceSz < 7 || nonceSz > 13)
        return BAD_FUNC_ARG;

    key = (byte*)aes->key;

    status = wc_AesGetKeySize(aes, &keySize);
    if (status != 0) {
        return status;
    }

    status = LTC_AES_EncryptTagCcm(LTC_BASE, in, out, inSz,
        nonce, nonceSz, authIn, authInSz, key, keySize, authTag, authTagSz);

    return (kStatus_Success == status) ? 0 : BAD_FUNC_ARG;
}

#ifdef HAVE_AES_DECRYPT
int  wc_AesCcmDecrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
                   const byte* nonce, word32 nonceSz,
                   const byte* authTag, word32 authTagSz,
                   const byte* authIn, word32 authInSz)
{
    byte *key;
    uint32_t keySize;
    status_t status;

    /* sanity check on arguments */
    if (aes == NULL || out == NULL || in == NULL || nonce == NULL
            || authTag == NULL || nonceSz < 7 || nonceSz > 13)
        return BAD_FUNC_ARG;

    key = (byte*)aes->key;

    status = wc_AesGetKeySize(aes, &keySize);
    if (status != 0) {
        return status;
    }

    status = LTC_AES_DecryptTagCcm(LTC_BASE, in, out, inSz,
        nonce, nonceSz, authIn, authInSz, key, keySize, authTag, authTagSz);

    if (status == kStatus_Success) {
        return 0;
    }
    else {
        XMEMSET(out, 0, inSz);
        return AES_CCM_AUTH_E;
    }
}
#endif /* HAVE_AES_DECRYPT */


/* software AES CCM */
#else

static void roll_x(Aes* aes, const byte* in, word32 inSz, byte* out)
{
    /* process the bulk of the data */
    while (inSz >= AES_BLOCK_SIZE) {
        xorbuf(out, in, AES_BLOCK_SIZE);
        in += AES_BLOCK_SIZE;
        inSz -= AES_BLOCK_SIZE;

        wc_AesEncrypt(aes, out, out);
    }

    /* process remainder of the data */
    if (inSz > 0) {
        xorbuf(out, in, inSz);
        wc_AesEncrypt(aes, out, out);
    }
}

static void roll_auth(Aes* aes, const byte* in, word32 inSz, byte* out)
{
    word32 authLenSz;
    word32 remainder;

    /* encode the length in */
    if (inSz <= 0xFEFF) {
        authLenSz = 2;
        out[0] ^= ((inSz & 0xFF00) >> 8);
        out[1] ^=  (inSz & 0x00FF);
    }
    else if (inSz <= 0xFFFFFFFF) {
        authLenSz = 6;
        out[0] ^= 0xFF; out[1] ^= 0xFE;
        out[2] ^= ((inSz & 0xFF000000) >> 24);
        out[3] ^= ((inSz & 0x00FF0000) >> 16);
        out[4] ^= ((inSz & 0x0000FF00) >>  8);
        out[5] ^=  (inSz & 0x000000FF);
    }
    /* Note, the protocol handles auth data up to 2^64, but we are
     * using 32-bit sizes right now, so the bigger data isn't handled
     * else if (inSz <= 0xFFFFFFFFFFFFFFFF) {} */
    else
        return;

    /* start fill out the rest of the first block */
    remainder = AES_BLOCK_SIZE - authLenSz;
    if (inSz >= remainder) {
        /* plenty of bulk data to fill the remainder of this block */
        xorbuf(out + authLenSz, in, remainder);
        inSz -= remainder;
        in += remainder;
    }
    else {
        /* not enough bulk data, copy what is available, and pad zero */
        xorbuf(out + authLenSz, in, inSz);
        inSz = 0;
    }
    wc_AesEncrypt(aes, out, out);

    if (inSz > 0)
        roll_x(aes, in, inSz, out);
}


static WC_INLINE void AesCcmCtrInc(byte* B, word32 lenSz)
{
    word32 i;

    for (i = 0; i < lenSz; i++) {
        if (++B[AES_BLOCK_SIZE - 1 - i] != 0) return;
    }
}

/* return 0 on success */
int wc_AesCcmEncrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
                   const byte* nonce, word32 nonceSz,
                   byte* authTag, word32 authTagSz,
                   const byte* authIn, word32 authInSz)
{
    byte A[AES_BLOCK_SIZE];
    byte B[AES_BLOCK_SIZE];
    byte lenSz;
    word32 i;
    byte mask = 0xFF;
    const word32 wordSz = (word32)sizeof(word32);

    /* sanity check on arguments */
    if (aes == NULL || out == NULL || in == NULL || nonce == NULL
            || authTag == NULL || nonceSz < 7 || nonceSz > 13 ||
            authTagSz > AES_BLOCK_SIZE)
        return BAD_FUNC_ARG;

    XMEMCPY(B+1, nonce, nonceSz);
    lenSz = AES_BLOCK_SIZE - 1 - (byte)nonceSz;
    B[0] = (authInSz > 0 ? 64 : 0)
         + (8 * (((byte)authTagSz - 2) / 2))
         + (lenSz - 1);
    for (i = 0; i < lenSz; i++) {
        if (mask && i >= wordSz)
            mask = 0x00;
        B[AES_BLOCK_SIZE - 1 - i] = (inSz >> ((8 * i) & mask)) & mask;
    }

    wc_AesEncrypt(aes, B, A);

    if (authInSz > 0)
        roll_auth(aes, authIn, authInSz, A);
    if (inSz > 0)
        roll_x(aes, in, inSz, A);
    XMEMCPY(authTag, A, authTagSz);

    B[0] = lenSz - 1;
    for (i = 0; i < lenSz; i++)
        B[AES_BLOCK_SIZE - 1 - i] = 0;
    wc_AesEncrypt(aes, B, A);
    xorbuf(authTag, A, authTagSz);

    B[15] = 1;
    while (inSz >= AES_BLOCK_SIZE) {
        wc_AesEncrypt(aes, B, A);
        xorbuf(A, in, AES_BLOCK_SIZE);
        XMEMCPY(out, A, AES_BLOCK_SIZE);

        AesCcmCtrInc(B, lenSz);
        inSz -= AES_BLOCK_SIZE;
        in += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
    }
    if (inSz > 0) {
        wc_AesEncrypt(aes, B, A);
        xorbuf(A, in, inSz);
        XMEMCPY(out, A, inSz);
    }

    ForceZero(A, AES_BLOCK_SIZE);
    ForceZero(B, AES_BLOCK_SIZE);

    return 0;
}

#ifdef HAVE_AES_DECRYPT
int  wc_AesCcmDecrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
                   const byte* nonce, word32 nonceSz,
                   const byte* authTag, word32 authTagSz,
                   const byte* authIn, word32 authInSz)
{
    byte A[AES_BLOCK_SIZE];
    byte B[AES_BLOCK_SIZE];
    byte* o;
    byte lenSz;
    word32 i, oSz;
    int result = 0;
    byte mask = 0xFF;
    const word32 wordSz = (word32)sizeof(word32);

    /* sanity check on arguments */
    if (aes == NULL || out == NULL || in == NULL || nonce == NULL
            || authTag == NULL || nonceSz < 7 || nonceSz > 13 ||
            authTagSz > AES_BLOCK_SIZE)
        return BAD_FUNC_ARG;

    o = out;
    oSz = inSz;
    XMEMCPY(B+1, nonce, nonceSz);
    lenSz = AES_BLOCK_SIZE - 1 - (byte)nonceSz;

    B[0] = lenSz - 1;
    for (i = 0; i < lenSz; i++)
        B[AES_BLOCK_SIZE - 1 - i] = 0;
    B[15] = 1;

    while (oSz >= AES_BLOCK_SIZE) {
        wc_AesEncrypt(aes, B, A);
        xorbuf(A, in, AES_BLOCK_SIZE);
        XMEMCPY(o, A, AES_BLOCK_SIZE);

        AesCcmCtrInc(B, lenSz);
        oSz -= AES_BLOCK_SIZE;
        in += AES_BLOCK_SIZE;
        o += AES_BLOCK_SIZE;
    }
    if (inSz > 0) {
        wc_AesEncrypt(aes, B, A);
        xorbuf(A, in, oSz);
        XMEMCPY(o, A, oSz);
    }

    for (i = 0; i < lenSz; i++)
        B[AES_BLOCK_SIZE - 1 - i] = 0;
    wc_AesEncrypt(aes, B, A);

    o = out;
    oSz = inSz;

    B[0] = (authInSz > 0 ? 64 : 0)
         + (8 * (((byte)authTagSz - 2) / 2))
         + (lenSz - 1);
    for (i = 0; i < lenSz; i++) {
        if (mask && i >= wordSz)
            mask = 0x00;
        B[AES_BLOCK_SIZE - 1 - i] = (inSz >> ((8 * i) & mask)) & mask;
    }

    wc_AesEncrypt(aes, B, A);

    if (authInSz > 0)
        roll_auth(aes, authIn, authInSz, A);
    if (inSz > 0)
        roll_x(aes, o, oSz, A);

    B[0] = lenSz - 1;
    for (i = 0; i < lenSz; i++)
        B[AES_BLOCK_SIZE - 1 - i] = 0;
    wc_AesEncrypt(aes, B, B);
    xorbuf(A, B, authTagSz);

    if (ConstantCompare(A, authTag, authTagSz) != 0) {
        /* If the authTag check fails, don't keep the decrypted data.
         * Unfortunately, you need the decrypted data to calculate the
         * check value. */
        XMEMSET(out, 0, inSz);
        result = AES_CCM_AUTH_E;
    }

    ForceZero(A, AES_BLOCK_SIZE);
    ForceZero(B, AES_BLOCK_SIZE);
    o = NULL;

    return result;
}

#endif /* HAVE_AES_DECRYPT */
#endif /* software AES CCM */

/* abstract functions that call lower level AESCCM functions */
#ifndef WC_NO_RNG

int wc_AesCcmSetNonce(Aes* aes, const byte* nonce, word32 nonceSz)
{
    int ret = 0;

    if (aes == NULL || nonce == NULL ||
        nonceSz < CCM_NONCE_MIN_SZ || nonceSz > CCM_NONCE_MAX_SZ) {

        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        XMEMCPY(aes->reg, nonce, nonceSz);
        aes->nonceSz = nonceSz;

        /* Invocation counter should be 2^61 */
        aes->invokeCtr[0] = 0;
        aes->invokeCtr[1] = 0xE0000000;
    }

    return ret;
}


int wc_AesCcmEncrypt_ex(Aes* aes, byte* out, const byte* in, word32 sz,
                        byte* ivOut, word32 ivOutSz,
                        byte* authTag, word32 authTagSz,
                        const byte* authIn, word32 authInSz)
{
    int ret = 0;

    if (aes == NULL || out == NULL ||
        (in == NULL && sz != 0) ||
        ivOut == NULL ||
        (authIn == NULL && authInSz != 0) ||
        (ivOutSz != aes->nonceSz)) {

        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        aes->invokeCtr[0]++;
        if (aes->invokeCtr[0] == 0) {
            aes->invokeCtr[1]++;
            if (aes->invokeCtr[1] == 0)
                ret = AES_CCM_OVERFLOW_E;
        }
    }

    if (ret == 0) {
        ret = wc_AesCcmEncrypt(aes, out, in, sz,
                               (byte*)aes->reg, aes->nonceSz,
                               authTag, authTagSz,
                               authIn, authInSz);
        XMEMCPY(ivOut, aes->reg, aes->nonceSz);
        IncCtr((byte*)aes->reg, aes->nonceSz);
    }

    return ret;
}

#endif /* WC_NO_RNG */

#endif /* HAVE_AESCCM */


#ifdef HAVE_AES_ECB
/* software implementation */
int wc_AesEcbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    word32 blocks = sz / AES_BLOCK_SIZE;

    if ((in == NULL) || (out == NULL) || (aes == NULL))
      return BAD_FUNC_ARG;
    while (blocks>0) {
      wc_AesEncryptDirect(aes, out, in);
      out += AES_BLOCK_SIZE;
      in  += AES_BLOCK_SIZE;
      sz  -= AES_BLOCK_SIZE;
      blocks--;
    }
    return 0;
}


int wc_AesEcbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    word32 blocks = sz / AES_BLOCK_SIZE;

    if ((in == NULL) || (out == NULL) || (aes == NULL))
      return BAD_FUNC_ARG;
    while (blocks>0) {
      wc_AesDecryptDirect(aes, out, in);
      out += AES_BLOCK_SIZE;
      in  += AES_BLOCK_SIZE;
      sz  -= AES_BLOCK_SIZE;
      blocks--;
    }
    return 0;
}
#endif /* HAVE_AES_ECB */

#ifdef WOLFSSL_AES_CFB
/* CFB 128
 *
 * aes structure holding key to use for encryption
 * out buffer to hold result of encryption (must be at least as large as input
 *     buffer)
 * in  buffer to encrypt
 * sz  size of input buffer
 *
 * returns 0 on success and negative error values on failure
 */
int wc_AesCfbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    byte*  tmp = NULL;
    byte*  reg = NULL;

    WOLFSSL_ENTER("wc_AesCfbEncrypt");

    if (aes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    if (aes->left && sz) {
        reg = (byte*)aes->reg + AES_BLOCK_SIZE - aes->left;
    }

    /* consume any unused bytes left in aes->tmp */
    tmp = (byte*)aes->tmp + AES_BLOCK_SIZE - aes->left;
    while (aes->left && sz) {
        *(out++) = *(reg++) = *(in++) ^ *(tmp++);
        aes->left--;
        sz--;
    }

    while (sz >= AES_BLOCK_SIZE) {
        wc_AesEncryptDirect(aes, out, (byte*)aes->reg);
        xorbuf(out, in, AES_BLOCK_SIZE);
        XMEMCPY(aes->reg, out, AES_BLOCK_SIZE);
        out += AES_BLOCK_SIZE;
        in  += AES_BLOCK_SIZE;
        sz  -= AES_BLOCK_SIZE;
        aes->left = 0;
    }

    /* encrypt left over data */
    if (sz) {
        wc_AesEncryptDirect(aes, (byte*)aes->tmp, (byte*)aes->reg);
        aes->left = AES_BLOCK_SIZE;
        tmp = (byte*)aes->tmp;
        reg = (byte*)aes->reg;

        while (sz--) {
            *(out++) = *(reg++) = *(in++) ^ *(tmp++);
            aes->left--;
        }
    }

    return 0;
}


#ifdef HAVE_AES_DECRYPT
/* CFB 128
 *
 * aes structure holding key to use for decryption
 * out buffer to hold result of decryption (must be at least as large as input
 *     buffer)
 * in  buffer to decrypt
 * sz  size of input buffer
 *
 * returns 0 on success and negative error values on failure
 */
int wc_AesCfbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    byte*  tmp;

    WOLFSSL_ENTER("wc_AesCfbDecrypt");

    if (aes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    /* check if more input needs copied over to aes->reg */
    if (aes->left && sz) {
        int size = min(aes->left, sz);
        XMEMCPY((byte*)aes->reg + AES_BLOCK_SIZE - aes->left, in, size);
    }

    /* consume any unused bytes left in aes->tmp */
    tmp = (byte*)aes->tmp + AES_BLOCK_SIZE - aes->left;
    while (aes->left && sz) {
        *(out++) = *(in++) ^ *(tmp++);
        aes->left--;
        sz--;
    }

    while (sz > AES_BLOCK_SIZE) {
        wc_AesEncryptDirect(aes, out, (byte*)aes->reg);
        xorbuf(out, in, AES_BLOCK_SIZE);
        XMEMCPY(aes->reg, in, AES_BLOCK_SIZE);
        out += AES_BLOCK_SIZE;
        in  += AES_BLOCK_SIZE;
        sz  -= AES_BLOCK_SIZE;
        aes->left = 0;
    }

    /* decrypt left over data */
    if (sz) {
        wc_AesEncryptDirect(aes, (byte*)aes->tmp, (byte*)aes->reg);
        XMEMCPY(aes->reg, in, sz);
        aes->left = AES_BLOCK_SIZE;
        tmp = (byte*)aes->tmp;

        while (sz--) {
            *(out++) = *(in++) ^ *(tmp++);
            aes->left--;
        }
    }

    return 0;
}
#endif /* HAVE_AES_DECRYPT */
#endif /* WOLFSSL_AES_CFB */


#ifdef HAVE_AES_KEYWRAP

/* Initialize key wrap counter with value */
static WC_INLINE void InitKeyWrapCounter(byte* inOutCtr, word32 value)
{
    int i;
    word32 bytes;

    bytes = sizeof(word32);
    for (i = 0; i < (int)sizeof(word32); i++) {
        inOutCtr[i+sizeof(word32)] = (value >> ((bytes - 1) * 8)) & 0xFF;
        bytes--;
    }
}

/* Increment key wrap counter */
static WC_INLINE void IncrementKeyWrapCounter(byte* inOutCtr)
{
    int i;

    /* in network byte order so start at end and work back */
    for (i = KEYWRAP_BLOCK_SIZE - 1; i >= 0; i--) {
        if (++inOutCtr[i])  /* we're done unless we overflow */
            return;
    }
}

/* Decrement key wrap counter */
static WC_INLINE void DecrementKeyWrapCounter(byte* inOutCtr)
{
    int i;

    for (i = KEYWRAP_BLOCK_SIZE - 1; i >= 0; i--) {
        if (--inOutCtr[i] != 0xFF)  /* we're done unless we underflow */
            return;
    }
}

/* perform AES key wrap (RFC3394), return out sz on success, negative on err */
int wc_AesKeyWrap(const byte* key, word32 keySz, const byte* in, word32 inSz,
                  byte* out, word32 outSz, const byte* iv)
{
    Aes aes;
    byte* r;
    word32 i;
    int ret, j;

    byte t[KEYWRAP_BLOCK_SIZE];
    byte tmp[AES_BLOCK_SIZE];

    /* n must be at least 2, output size is n + 8 bytes */
    if (key == NULL || in  == NULL || inSz < 2 ||
        out == NULL || outSz < (inSz + KEYWRAP_BLOCK_SIZE))
        return BAD_FUNC_ARG;

    /* input must be multiple of 64-bits */
    if (inSz % KEYWRAP_BLOCK_SIZE != 0)
        return BAD_FUNC_ARG;

    /* user IV is optional */
    if (iv == NULL) {
        XMEMSET(tmp, 0xA6, KEYWRAP_BLOCK_SIZE);
    } else {
        XMEMCPY(tmp, iv, KEYWRAP_BLOCK_SIZE);
    }

    r = out + 8;
    XMEMCPY(r, in, inSz);
    XMEMSET(t, 0, sizeof(t));

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;

    ret = wc_AesSetKey(&aes, key, keySz, NULL, AES_ENCRYPTION);
    if (ret != 0)
        return ret;

    for (j = 0; j <= 5; j++) {
        for (i = 1; i <= inSz / KEYWRAP_BLOCK_SIZE; i++) {

            /* load R[i] */
            XMEMCPY(tmp + KEYWRAP_BLOCK_SIZE, r, KEYWRAP_BLOCK_SIZE);

            wc_AesEncryptDirect(&aes, tmp, tmp);

            /* calculate new A */
            IncrementKeyWrapCounter(t);
            xorbuf(tmp, t, KEYWRAP_BLOCK_SIZE);

            /* save R[i] */
            XMEMCPY(r, tmp + KEYWRAP_BLOCK_SIZE, KEYWRAP_BLOCK_SIZE);
            r += KEYWRAP_BLOCK_SIZE;
        }
        r = out + KEYWRAP_BLOCK_SIZE;
    }

    /* C[0] = A */
    XMEMCPY(out, tmp, KEYWRAP_BLOCK_SIZE);

    wc_AesFree(&aes);

    return inSz + KEYWRAP_BLOCK_SIZE;
}

int wc_AesKeyUnWrap(const byte* key, word32 keySz, const byte* in, word32 inSz,
                    byte* out, word32 outSz, const byte* iv)
{
    Aes aes;
    byte* r;
    word32 i, n;
    int ret, j;

    byte t[KEYWRAP_BLOCK_SIZE];
    byte tmp[AES_BLOCK_SIZE];

    const byte* expIv;
    const byte defaultIV[] = {
        0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6
    };

    (void)iv;

    if (key == NULL || in == NULL || inSz < 3 ||
        out == NULL || outSz < (inSz - KEYWRAP_BLOCK_SIZE))
        return BAD_FUNC_ARG;

    /* input must be multiple of 64-bits */
    if (inSz % KEYWRAP_BLOCK_SIZE != 0)
        return BAD_FUNC_ARG;

    /* user IV optional */
    if (iv != NULL) {
        expIv = iv;
    } else {
        expIv = defaultIV;
    }

    /* A = C[0], R[i] = C[i] */
    XMEMCPY(tmp, in, KEYWRAP_BLOCK_SIZE);
    XMEMCPY(out, in + KEYWRAP_BLOCK_SIZE, inSz - KEYWRAP_BLOCK_SIZE);
    XMEMSET(t, 0, sizeof(t));

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;

    ret = wc_AesSetKey(&aes, key, keySz, NULL, AES_DECRYPTION);
    if (ret != 0)
        return ret;

    /* initialize counter to 6n */
    n = (inSz - 1) / KEYWRAP_BLOCK_SIZE;
    InitKeyWrapCounter(t, 6 * n);

    for (j = 5; j >= 0; j--) {
        for (i = n; i >= 1; i--) {

            /* calculate A */
            xorbuf(tmp, t, KEYWRAP_BLOCK_SIZE);
            DecrementKeyWrapCounter(t);

            /* load R[i], starting at end of R */
            r = out + ((i - 1) * KEYWRAP_BLOCK_SIZE);
            XMEMCPY(tmp + KEYWRAP_BLOCK_SIZE, r, KEYWRAP_BLOCK_SIZE);
            wc_AesDecryptDirect(&aes, tmp, tmp);

            /* save R[i] */
            XMEMCPY(r, tmp + KEYWRAP_BLOCK_SIZE, KEYWRAP_BLOCK_SIZE);
        }
    }

    wc_AesFree(&aes);

    /* verify IV */
    if (XMEMCMP(tmp, expIv, KEYWRAP_BLOCK_SIZE) != 0)
        return BAD_KEYWRAP_IV_E;

    return inSz - KEYWRAP_BLOCK_SIZE;
}

#endif /* HAVE_AES_KEYWRAP */

#ifdef WOLFSSL_AES_XTS

/* Galios Field to use */
#define GF_XTS 0x87

/* This is to help with setting keys to correct encrypt or decrypt type.
 *
 * tweak AES key for tweak in XTS
 * aes   AES key for encrypt/decrypt process
 * key   buffer holding aes key | tweak key
 * len   length of key buffer in bytes. Should be twice that of key size. i.e.
 *       32 for a 16 byte key.
 * dir   direction, either AES_ENCRYPTION or AES_DECRYPTION
 * heap  heap hint to use for memory. Can be NULL
 * devId id to use with async crypto. Can be 0
 *
 * Note: is up to user to call wc_AesFree on tweak and aes key when done.
 *
 * return 0 on success
 */
int wc_AesXtsSetKey(XtsAes* aes, const byte* key, word32 len, int dir,
        void* heap, int devId)
{
    word32 keySz;
    int    ret = 0;

    if (aes == NULL || key == NULL) {
        return BAD_FUNC_ARG;
    }

    if ((ret = wc_AesInit(&aes->tweak, heap, devId)) != 0) {
        return ret;
    }
    if ((ret = wc_AesInit(&aes->aes, heap, devId)) != 0) {
        return ret;
    }

    keySz = len/2;
    if (keySz != 16 && keySz != 32) {
        WOLFSSL_MSG("Unsupported key size");
        return WC_KEY_SIZE_E;
    }

    if ((ret = wc_AesSetKey(&aes->aes, key, keySz, NULL, dir)) == 0) {
        ret = wc_AesSetKey(&aes->tweak, key + keySz, keySz, NULL,
                AES_ENCRYPTION);
        if (ret != 0) {
            wc_AesFree(&aes->aes);
        }
    }

    return ret;
}


/* This is used to free up resources used by Aes structs
 *
 * aes AES keys to free
 *
 * return 0 on success
 */
int wc_AesXtsFree(XtsAes* aes)
{
    if (aes != NULL) {
        wc_AesFree(&aes->aes);
        wc_AesFree(&aes->tweak);
    }

    return 0;
}


/* Same process as wc_AesXtsEncrypt but uses a word64 type as the tweak value
 * instead of a byte array. This just converts the word64 to a byte array and
 * calls wc_AesXtsEncrypt.
 *
 * aes    AES keys to use for block encrypt/decrypt
 * out    output buffer to hold cipher text
 * in     input plain text buffer to encrypt
 * sz     size of both out and in buffers
 * sector value to use for tweak
 *
 * returns 0 on success
 */
int wc_AesXtsEncryptSector(XtsAes* aes, byte* out, const byte* in,
        word32 sz, word64 sector)
{
    byte* pt;
    byte  i[AES_BLOCK_SIZE];

    XMEMSET(i, 0, AES_BLOCK_SIZE);
#ifdef BIG_ENDIAN_ORDER
    sector = ByteReverseWord64(sector);
#endif
    pt = (byte*)&sector;
    XMEMCPY(i, pt, sizeof(word64));

    return wc_AesXtsEncrypt(aes, out, in, sz, (const byte*)i, AES_BLOCK_SIZE);
}


/* Same process as wc_AesXtsDecrypt but uses a word64 type as the tweak value
 * instead of a byte array. This just converts the word64 to a byte array.
 *
 * aes    AES keys to use for block encrypt/decrypt
 * out    output buffer to hold plain text
 * in     input cipher text buffer to encrypt
 * sz     size of both out and in buffers
 * sector value to use for tweak
 *
 * returns 0 on success
 */
int wc_AesXtsDecryptSector(XtsAes* aes, byte* out, const byte* in, word32 sz,
        word64 sector)
{
    byte* pt;
    byte  i[AES_BLOCK_SIZE];

    XMEMSET(i, 0, AES_BLOCK_SIZE);
#ifdef BIG_ENDIAN_ORDER
    sector = ByteReverseWord64(sector);
#endif
    pt = (byte*)&sector;
    XMEMCPY(i, pt, sizeof(word64));

    return wc_AesXtsDecrypt(aes, out, in, sz, (const byte*)i, AES_BLOCK_SIZE);
}

#ifdef HAVE_AES_ECB
/* helper function for encrypting / decrypting full buffer at once */
static int _AesXtsHelper(Aes* aes, byte* out, const byte* in, word32 sz, int dir)
{
    word32 outSz   = sz;
    word32 totalSz = (sz / AES_BLOCK_SIZE) * AES_BLOCK_SIZE; /* total bytes */
    byte*  pt      = out;

    outSz -= AES_BLOCK_SIZE;

    while (outSz > 0) {
        word32 j;
        byte carry = 0;

        /* multiply by shift left and propogate carry */
        for (j = 0; j < AES_BLOCK_SIZE && outSz > 0; j++, outSz--) {
            byte tmpC;

            tmpC   = (pt[j] >> 7) & 0x01;
            pt[j+AES_BLOCK_SIZE] = ((pt[j] << 1) + carry) & 0xFF;
            carry  = tmpC;
        }
        if (carry) {
            pt[AES_BLOCK_SIZE] ^= GF_XTS;
        }

        pt += AES_BLOCK_SIZE;
    }

    xorbuf(out, in, totalSz);
    if (dir == AES_ENCRYPTION) {
        return wc_AesEcbEncrypt(aes, out, out, totalSz);
    }
    else {
        return wc_AesEcbDecrypt(aes, out, out, totalSz);
    }
}
#endif /* HAVE_AES_ECB */


/* AES with XTS mode. (XTS) XEX encryption with Tweak and cipher text Stealing.
 *
 * xaes  AES keys to use for block encrypt/decrypt
 * out   output buffer to hold cipher text
 * in    input plain text buffer to encrypt
 * sz    size of both out and in buffers
 * i     value to use for tweak
 * iSz   size of i buffer, should always be AES_BLOCK_SIZE but having this input
 *       adds a sanity check on how the user calls the function.
 *
 * returns 0 on success
 */
int wc_AesXtsEncrypt(XtsAes* xaes, byte* out, const byte* in, word32 sz,
        const byte* i, word32 iSz)
{
    int ret = 0;
    word32 blocks = (sz / AES_BLOCK_SIZE);
    Aes *aes, *tweak;

    if (xaes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    aes   = &xaes->aes;
    tweak = &xaes->tweak;

    if (iSz < AES_BLOCK_SIZE) {
        return BAD_FUNC_ARG;
    }

    if (blocks > 0) {
        byte tmp[AES_BLOCK_SIZE];

        XMEMSET(tmp, 0, AES_BLOCK_SIZE); /* set to 0's in case of improper AES
                                          * key setup passed to encrypt direct*/

        wc_AesEncryptDirect(tweak, tmp, i);

    #ifdef HAVE_AES_ECB
        /* encrypt all of buffer at once when possible */
        if (in != out) { /* can not handle inline */
            XMEMCPY(out, tmp, AES_BLOCK_SIZE);
            if ((ret = _AesXtsHelper(aes, out, in, sz, AES_ENCRYPTION)) != 0) {
                return ret;
            }
        }
    #endif

        while (blocks > 0) {
            word32 j;
            byte carry = 0;
            byte buf[AES_BLOCK_SIZE];

    #ifdef HAVE_AES_ECB
            if (in == out) { /* check for if inline */
    #endif
            XMEMCPY(buf, in, AES_BLOCK_SIZE);
            xorbuf(buf, tmp, AES_BLOCK_SIZE);
            wc_AesEncryptDirect(aes, out, buf);
    #ifdef HAVE_AES_ECB
            }
    #endif
            xorbuf(out, tmp, AES_BLOCK_SIZE);

            /* multiply by shift left and propogate carry */
            for (j = 0; j < AES_BLOCK_SIZE; j++) {
                byte tmpC;

                tmpC   = (tmp[j] >> 7) & 0x01;
                tmp[j] = ((tmp[j] << 1) + carry) & 0xFF;
                carry  = tmpC;
            }
            if (carry) {
                tmp[0] ^= GF_XTS;
            }

            in  += AES_BLOCK_SIZE;
            out += AES_BLOCK_SIZE;
            sz  -= AES_BLOCK_SIZE;
            blocks--;
        }

        /* stealing operation of XTS to handle left overs */
        if (sz > 0) {
            byte buf[AES_BLOCK_SIZE];

            XMEMCPY(buf, out - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            if (sz >= AES_BLOCK_SIZE) { /* extra sanity check before copy */
                return BUFFER_E;
            }
            XMEMCPY(out, buf, sz);
            XMEMCPY(buf, in, sz);

            xorbuf(buf, tmp, AES_BLOCK_SIZE);
            wc_AesEncryptDirect(aes, out - AES_BLOCK_SIZE, buf);
            xorbuf(out - AES_BLOCK_SIZE, tmp, AES_BLOCK_SIZE);
        }
    }
    else {
        WOLFSSL_MSG("Plain text input too small for encryption");
        return BAD_FUNC_ARG;
    }

    return ret;
}


/* Same process as encryption but Aes key is AES_DECRYPTION type.
 *
 * xaes  AES keys to use for block encrypt/decrypt
 * out   output buffer to hold plain text
 * in    input cipher text buffer to decrypt
 * sz    size of both out and in buffers
 * i     value to use for tweak
 * iSz   size of i buffer, should always be AES_BLOCK_SIZE but having this input
 *       adds a sanity check on how the user calls the function.
 *
 * returns 0 on success
 */
int wc_AesXtsDecrypt(XtsAes* xaes, byte* out, const byte* in, word32 sz,
        const byte* i, word32 iSz)
{
    int ret = 0;
    word32 blocks = (sz / AES_BLOCK_SIZE);
    Aes *aes, *tweak;

    if (xaes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    aes   = &xaes->aes;
    tweak = &xaes->tweak;

    if (iSz < AES_BLOCK_SIZE) {
        return BAD_FUNC_ARG;
    }

    if (blocks > 0) {
        word32 j;
        byte carry = 0;
        byte tmp[AES_BLOCK_SIZE];
        byte stl = (sz % AES_BLOCK_SIZE);

        XMEMSET(tmp, 0, AES_BLOCK_SIZE); /* set to 0's in case of improper AES
                                          * key setup passed to decrypt direct*/

        wc_AesEncryptDirect(tweak, tmp, i);

        /* if Stealing then break out of loop one block early to handle special
         * case */
        if (stl > 0) {
            blocks--;
        }

    #ifdef HAVE_AES_ECB
        /* decrypt all of buffer at once when possible */
        if (in != out) { /* can not handle inline */
            XMEMCPY(out, tmp, AES_BLOCK_SIZE);
            if ((ret = _AesXtsHelper(aes, out, in, sz, AES_DECRYPTION)) != 0) {
                return ret;
            }
        }
    #endif

        while (blocks > 0) {
            byte buf[AES_BLOCK_SIZE];

    #ifdef HAVE_AES_ECB
            if (in == out) { /* check for if inline */
    #endif
            XMEMCPY(buf, in, AES_BLOCK_SIZE);
            xorbuf(buf, tmp, AES_BLOCK_SIZE);
            wc_AesDecryptDirect(aes, out, buf);
    #ifdef HAVE_AES_ECB
            }
    #endif
            xorbuf(out, tmp, AES_BLOCK_SIZE);

            /* multiply by shift left and propogate carry */
            for (j = 0; j < AES_BLOCK_SIZE; j++) {
                byte tmpC;

                tmpC   = (tmp[j] >> 7) & 0x01;
                tmp[j] = ((tmp[j] << 1) + carry) & 0xFF;
                carry  = tmpC;
            }
            if (carry) {
                tmp[0] ^= GF_XTS;
            }
            carry = 0;

            in  += AES_BLOCK_SIZE;
            out += AES_BLOCK_SIZE;
            sz  -= AES_BLOCK_SIZE;
            blocks--;
        }

        /* stealing operation of XTS to handle left overs */
        if (sz > 0) {
            byte buf[AES_BLOCK_SIZE];
            byte tmp2[AES_BLOCK_SIZE];

            /* multiply by shift left and propogate carry */
            for (j = 0; j < AES_BLOCK_SIZE; j++) {
                byte tmpC;

                tmpC   = (tmp[j] >> 7) & 0x01;
                tmp2[j] = ((tmp[j] << 1) + carry) & 0xFF;
                carry  = tmpC;
            }
            if (carry) {
                tmp2[0] ^= GF_XTS;
            }

            XMEMCPY(buf, in, AES_BLOCK_SIZE);
            xorbuf(buf, tmp2, AES_BLOCK_SIZE);
            wc_AesDecryptDirect(aes, out, buf);
            xorbuf(out, tmp2, AES_BLOCK_SIZE);

            /* tmp2 holds partial | last */
            XMEMCPY(tmp2, out, AES_BLOCK_SIZE);
            in  += AES_BLOCK_SIZE;
            out += AES_BLOCK_SIZE;
            sz  -= AES_BLOCK_SIZE;

            /* Make buffer with end of cipher text | last */
            XMEMCPY(buf, tmp2, AES_BLOCK_SIZE);
            if (sz >= AES_BLOCK_SIZE) { /* extra sanity check before copy */
                return BUFFER_E;
            }
            XMEMCPY(buf, in,   sz);
            XMEMCPY(out, tmp2, sz);

            xorbuf(buf, tmp, AES_BLOCK_SIZE);
            wc_AesDecryptDirect(aes, tmp2, buf);
            xorbuf(tmp2, tmp, AES_BLOCK_SIZE);
            XMEMCPY(out - AES_BLOCK_SIZE, tmp2, AES_BLOCK_SIZE);
        }
    }
    else {
        WOLFSSL_MSG("Plain text input too small for encryption");
        return BAD_FUNC_ARG;
    }

    return ret;
}

#endif /* WOLFSSL_AES_XTS */

#endif /* !NO_AES */

