/* sm2.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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

#ifdef HAVE_ECC_SM2

#include <wolfssl/wolfcrypt/sm2.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifndef NO_HASH_WRAPPER
/* takes in a hex string and converts it to binary then hash's in
 * returns 0 on success
 */
static int ecc_sm2_digest_hashin(wc_HashAlg* hash, enum wc_HashType hashType,
        const char* hexIn, int hexSz, void* heap)
{
    byte   *tmp;
    word32 tmpSz;
    int err = 0;

    tmpSz = hexSz;
    tmp = (byte*)XMALLOC(tmpSz, heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (tmp == NULL)
        err = MEMORY_E;
    if (err == 0)
        err = Base16_Decode((const byte*)hexIn, hexSz, tmp, &tmpSz);
    if (err == 0)
        err = wc_HashUpdate(hash, hashType, tmp, tmpSz);
    XFREE(tmp, heap, DYNAMIC_TYPE_TMP_BUFFER);

    (void)heap;
    return err;
}


/* Creating SM2 hash on sign/verify using input hashType
 *
 *   ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
 *   Hash Out = Hash(ZA || M)
 *
 * id is the IDA to be hashed in
 * msg is the message to be signed
 * hashType is the hash type to use
 * out stores the final digest output
 * key is a SM2 ECC key that has already been setup
 *
 * returns 0 on success
 */
int wc_ecc_sm2_create_digest(const byte *id, word16 idSz,
        const byte* msg, int msgSz, enum wc_HashType hashType,
        byte* out, int outSz, ecc_key* key)
{
    int err = 0, hashSz;
    byte ENTLA[2] = {0}; /* RFC draft states ID size is always 2 bytes */
    word16 sz = 0;
    const ecc_set_type* dp;
    byte *xA = NULL, *yA = NULL;
    word32 xAsz, yAsz;
    wc_HashAlg hash;

    if (key == NULL || out == NULL || msg == NULL || id == NULL) {
        return BAD_FUNC_ARG;
    }

    hashSz = wc_HashGetDigestSize(hashType);
    if (hashSz < 0 || hashSz > outSz)
        err = BUFFER_E;

    if (err == 0) {
        dp  = (key->dp != NULL)? key->dp:
            wc_ecc_get_curve_params(wc_ecc_get_curve_idx(ECC_SM2P256V1));
        sz = idSz * WOLFSSL_BIT_SIZE; /* Use size in bits */
        ENTLA[0] = sz >> WOLFSSL_BIT_SIZE;
        ENTLA[1] = sz & 0xFF;
    }

    if (err == 0) {
        xAsz = yAsz = wc_ecc_size(key);
        xA = (byte*)XMALLOC(xAsz  + 1, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        yA = (byte*)XMALLOC(yAsz  + 1, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (xA == NULL || yA == NULL)
            err = MEMORY_E;
    }

#ifdef DEBUG_ECC_SM2
    {
        int i;
        byte* pt = (byte*)(&ENTLA);
        printf("ENTLA = ");
        for (i = 0; i < 2; i++)
            printf("%02X", pt[i]);
        printf("\n");
    }
#endif

    if (err == 0)
        err = wc_ecc_export_public_raw(key, xA, &xAsz, yA, &yAsz);
    if (err == 0)
        err = wc_HashInit_ex(&hash, hashType, key->heap, 0);
    if (err == 0)
        err = wc_HashUpdate(&hash, hashType, (byte*)&ENTLA, 2);
    if (err == 0)
        err = wc_HashUpdate(&hash, hashType, id, idSz);

    if (err == 0) {
        err = ecc_sm2_digest_hashin(&hash, hashType, dp->Af,
                (int)XSTRLEN(dp->Af), key->heap);
    }
    if (err == 0) {
        err = ecc_sm2_digest_hashin(&hash, hashType, dp->Bf,
                (int)XSTRLEN(dp->Bf), key->heap);
    }
    if (err == 0) {
        err = ecc_sm2_digest_hashin(&hash, hashType, dp->Gx,
                (int)XSTRLEN(dp->Gx), key->heap);
    }
    if (err == 0) {
        err = ecc_sm2_digest_hashin(&hash, hashType, dp->Gy,
                (int)XSTRLEN(dp->Gy), key->heap);
    }
    if (err == 0)
        err = wc_HashUpdate(&hash, hashType, xA, xAsz);
    XFREE(xA, key->heap, DYNAMIC_TYPE_TMP_BUFFER);

    if (err == 0)
        err = wc_HashUpdate(&hash, hashType, yA, yAsz);
    XFREE(yA, key->heap, DYNAMIC_TYPE_TMP_BUFFER);

    if (err == 0)
        err = wc_HashFinal(&hash, hashType, out);
#ifdef DEBUG_ECC_SM2
    {
        int i;
        printf("ZA = ");
        for (i = 0; i < hashSz; i++)
            printf("%02X", out[i]);
        printf("\n");
    }
#endif

    /* hash in msg ( ZA || M) */
    if (err == 0)
        err = wc_HashInit_ex(&hash, hashType, NULL, 0);
    if (err == 0)
        err = wc_HashUpdate(&hash, hashType, out, hashSz);
    if (err == 0)
        err = wc_HashUpdate(&hash, hashType, msg, msgSz);
    if (err == 0)
        err = wc_HashFinal(&hash, hashType, out);
#ifdef DEBUG_ECC_SM2
    {
        int i;
        printf("Hv(ZA || M) = ");
        for (i = 0; i < hashSz; i++)
            printf("%02X", out[i]);
        printf("\n");
    }
#endif

    (void)wc_HashFree(&hash, hashType);
    return err;
}
#endif /* NO_HASH_WRAPPER */


#ifdef HAVE_ECC_VERIFY
/* verify a digest of hash(ZA || M) using SM2
 *
 * res gets set to 1 on successful verify and 0 on failure
 *
 * return 0 on success (note this is even when successfully finding verify is
 * incorrect)
 */
int wc_ecc_sm2_verify_hash_ex(mp_int *r, mp_int *s, const byte *hash,
        word32 hashSz, int *res, ecc_key *key)
{
    int err = MP_OKAY;
    const ecc_set_type* dp;
    ecc_point *PO = NULL, *G = NULL;
    mp_int t, e, prime, Af, order;

    if (key == NULL || res == NULL || r == NULL || s == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }
    *res = 0;

#if defined(WOLFSSL_DSP) && !defined(WOLFSSL_DSP_BUILD)
  if (key->handle != -1) {
      return dsp_ecc_verify(key->handle, hash, hashSz, key, r, s, res,
              key->heap);
  }
  if (wolfSSL_GetHandleCbSet() == 1) {
      return dsp_ecc_verify(key->handle, hash, hashSz, key, r, s, res,
              key->heap);
  }
#endif

    err = mp_init_multi(&e, &t, &prime, &Af, &order, NULL);
    if (err == MP_OKAY) {
        dp  = (key->dp != NULL)? key->dp:
            wc_ecc_get_curve_params(wc_ecc_get_curve_idx(ECC_SM2P256V1));
    }

    /* B5: calculate t = (r' + s') modn -- if t is 0 then failed */
    if (err == MP_OKAY)
        err = mp_read_radix(&order, dp->order, MP_RADIX_HEX);
    if (err == MP_OKAY)
        err = mp_addmod (r, s, &order, &t);
    if (err == MP_OKAY) {
        if (mp_iszero(&t) == MP_YES)
            err = MP_VAL;
    }
#ifdef DEBUG_ECC_SM2
    mp_dump("t = ", &t, 0);
#endif

    /* B6: calculate the point (x1', y1')=[s']G + [t]PA */
    if (err == MP_OKAY) {
        PO = wc_ecc_new_point_h(key->heap);
        G  = wc_ecc_new_point_h(key->heap);
        if (PO == NULL || G == NULL)
            err = MEMORY_E;
    }

    if (err == MP_OKAY)
        err = mp_read_radix(G->x, dp->Gx, MP_RADIX_HEX);
    if (err == MP_OKAY)
        err = mp_read_radix(G->y, dp->Gy, MP_RADIX_HEX);
    if (err == MP_OKAY)
        err = mp_set(G->z, 1);
    if (err == MP_OKAY)
        err = mp_read_radix(&Af, dp->Af, MP_RADIX_HEX);
    if (err == MP_OKAY)
        err = mp_read_radix(&prime, dp->prime, MP_RADIX_HEX);
    if (err == MP_OKAY)
        err = ecc_mul2add(G, s, &(key->pubkey), &t, PO, &Af, &prime,
                key->heap);
#ifdef DEBUG_ECC_SM2
    printf("\n");
    mp_dump("G->x = ", G->x, 0);
    mp_dump("G->y = ", G->y, 0);
    printf("\n");
    mp_dump("PO->x = ", PO->x, 0);
    mp_dump("PO->y = ", PO->y, 0);
    printf("\n\n");
#endif


    /* B7: calculate R=(e'+x1') modn, if R=r then passed */
    if (err == MP_OKAY)
        err = mp_read_unsigned_bin(&e, hash, hashSz);
    if (err == MP_OKAY)
        err = mp_addmod(&e, PO->x, &order, &t);
    if (err == MP_OKAY && mp_cmp(&t, r) == MP_EQ)
        *res = 1;

    wc_ecc_del_point_h(PO, key->heap);
    wc_ecc_del_point_h(G, key->heap);

    mp_free(&e);
    mp_free(&t);
    mp_free(&prime);
    mp_free(&Af);
    mp_free(&order);

    return err;
}


#ifndef NO_ASN
/* verify a digest of hash(ZA || M) using SM2 and encoded signature
 *
 * res gets set to 1 on successful verify and 0 on failure
 *
 * return 0 on success (note this is even when successfully finding verify is
 * incorrect)
 */
int wc_ecc_sm2_verify_hash(const byte* sig, word32 siglen, const byte* hash,
                    word32 hashlen, int* stat, ecc_key* key)
{
    int err;
    mp_int r, s;

    if (sig == NULL || hash == NULL || stat == NULL || key == NULL)
        return BAD_FUNC_ARG;

    err = DecodeECC_DSA_Sig(sig, siglen, &r, &s);
    if (err == 0)
        err = wc_ecc_sm2_verify_hash_ex(&r, &s, hash, hashlen, stat, key);

    mp_free(&r);
    mp_free(&s);
    return err;
}
#endif /* NO_ASN */
#endif /* HAVE_ECC_VERIFY */

#endif /* HAVE_ECC_SM2 */
