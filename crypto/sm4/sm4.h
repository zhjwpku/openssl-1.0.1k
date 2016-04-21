/* crypto/SM4/SM4.h */
/* ====================================================================
 * Copyright (c) 2014 - 2015 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 */

#ifndef HEADER_SM4_H
#define HEADER_SM4_H

#define SM4_KEY_LENGTH		16
#define SM4_BLOCK_SIZE		16
#define SM4_NUM_ROUNDS		32

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include "openssl/modes.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint32_t rk[SM4_NUM_ROUNDS];
} SM4_KEY;

void SM4_set_encrypt_key(SM4_KEY *key, const unsigned char *user_key);
void SM4_set_decrypt_key(SM4_KEY *key, const unsigned char *user_key);
void SM4_encrypt(const unsigned char *in, unsigned char *out, SM4_KEY *key);

void SM4_ecb_encrypt(const unsigned char *in, unsigned char *out,
					 SM4_KEY *key, int enc);
void SM4_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len,
					 SM4_KEY *key, unsigned char *ivec, int encrypt);
void SM4_cfb128_encrypt(const unsigned char *in, unsigned char *out,
						 size_t length, SM4_KEY *key,
                         unsigned char *ivec, int *num, int encrypt);
void SM4_ofb128_encrypt(const unsigned char *in, unsigned char *out,
                         size_t length, const SM4_KEY *key,
                         unsigned char ivec[SM4_BLOCK_SIZE],int *num);

#define SM4_decrypt(in,out,key)  SM4_encrypt(in,out,key)

#ifdef __cplusplus
}
#endif
#endif

