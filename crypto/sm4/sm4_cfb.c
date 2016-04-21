/* crypto/sm4/sm4_cfb.c */

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

/* The input and output encrypted as though 128bit cfb mode is being
 * used.  The extra state information to record how much of the
 * 128bit block we have used is contained in *num;
 */

void SM4_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                        size_t length, SM4_KEY *key,
                        unsigned char *ivec, int *num, int encrypt) {
        CRYPTO_cfb128_encrypt(in,out,length,key,ivec,num,encrypt,(block128_f)SM4_encrypt);
}
