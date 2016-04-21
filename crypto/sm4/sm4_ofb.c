/* crypto/sm4/sm4_ofb.c */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sm4.h"

#ifndef MODES_DEBUG
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif
#include <assert.h>

void SM4_ofb128_encrypt(const unsigned char *in, unsigned char *out,
			size_t length, const SM4_KEY *key,
			unsigned char ivec[SM4_BLOCK_SIZE],
			int *num)
{
	CRYPTO_ofb128_encrypt(in,out,length,key,ivec,num,(block128_f)SM4_encrypt);
}
