/* afalg_hash.c
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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

#if defined(WOLFSSL_AFALG_HASH)

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/port/af_alg/wc_afalg.h>

static const char WC_TYPE_HASH[] = "hash";

#if !defined(NO_SHA256)
#include <wolfssl/wolfcrypt/sha256.h>

static const char WC_NAME_SHA256[] = "sha256";


/* create AF_ALG sockets for SHA256 operation */
int wc_InitSha256_ex(wc_Sha256* sha, void* heap, int devId)
{
	(void)devId; /* no async for now */
	XMEMSET(sha, 0, sizeof(wc_Sha256));
	sha->heap = heap;

	sha->alFd = wc_Afalg_Socket();
	if (sha->alFd < 0) {
		return WC_AFALG_SOCK_E;
	}

	sha->rdFd = wc_Afalg_CreateRead(sha->alFd, WC_TYPE_HASH, WC_NAME_SHA256);
	if (sha->rdFd < 0) {
		return WC_AFALG_SOCK_E;
	}

	return 0;
}


int wc_Sha256Update(wc_Sha256* sha, const byte* in, word32 sz)
{
	int ret;

	if ((ret = send(sha->rdFd, in, sz, MSG_MORE)) < 0) {
		perror("error");
		return ret;
	}
	return 0;	
}


int wc_Sha256FinalRaw(wc_Sha256* sha, byte* raw)
{
	(void)sha;
	(void)raw;
	return 0;
}


int wc_Sha256Final(wc_Sha256* sha, byte* hash)
{
	int ret;

	if ((ret = send(sha->rdFd, NULL, 0, 0)) < 0) {
		return ret;
	}

	if ((ret = read(sha->rdFd, hash, WC_SHA256_DIGEST_SIZE)) !=
			WC_SHA256_DIGEST_SIZE) {
		return ret;
	}

	return wc_InitSha256_ex(sha, sha->heap, 0);
}


int wc_Sha256GetHash(wc_Sha256* sha, byte* hash)
{
	int ret;

	if ((ret = read(sha->rdFd, hash, WC_SHA256_DIGEST_SIZE)) !=
			WC_SHA256_DIGEST_SIZE) {
		return ret;
	}

	{
		int i;
		printf("hash get = ");
		for (i = 0; i < 32; i++) printf("%02X", hash[i]);
		printf("\n");
	}

	printf("ret of send = %ld\n", send(sha->rdFd, hash, WC_SHA256_DIGEST_SIZE, 0));
	return 0;
}

int wc_Sha256Copy(wc_Sha256* src, wc_Sha256* dst)
{
	printf("copying sha256\n");
//	wc_InitSha256_ex(dst, src->heap, 0);
//	dst->rdFd = accept(src->rdFd, NULL, 0);
//	dst->alFd = accept(src->alFd, NULL, 0);
//	
//	printf("dst rdfd = %d, src fd = %d\n", dst->rdFd, src->rdFd);
//	printf("dst alfd = %d, src fd = %d\n", dst->alFd, src->alFd);
//
//	if (dst->rdFd == -1 || dst->alFd == -1) {
//		perror("error getting copy");
//		return -1;
//	}

	return 0;
}

#endif /* !NO_SHA256 */




#endif /* WOLFSSL_AFALG */
