/* crypto/sm4/sm4_ecb.c */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sm4.h"
#include <assert.h>

void SM4_ecb_encrypt(const unsigned char *in, unsigned char *out, SM4_KEY *key, int encrypt) {
        assert(in && out && key);
	if(encrypt)
		SM4_encrypt(in, out, key);
	else
		SM4_decrypt(in, out, key);
}
