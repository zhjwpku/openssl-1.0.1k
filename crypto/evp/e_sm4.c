/* crypto/evp/e_sm4.c */
#include <stdio.h>
#include "cryptlib.h"

#include <openssl/evp.h>
#include <openssl/objects.h>
#include "evp_locl.h"
#include <openssl/sm4.h>

static int sm4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
						const unsigned char *iv,int enc);

typedef struct {
	SM4_KEY ks;
} EVP_SM4_KEY;


IMPLEMENT_BLOCK_CIPHER(sm4, ks, SM4, EVP_SM4_KEY, NID_sm4,
		       16, 16, 16, 128, 0, sm4_init_key, NULL, NULL, NULL, NULL)

static int sm4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			 const unsigned char *iv, int enc)
{
	int mode = EVP_CIPHER_CTX_mode(ctx);

	if(mode == EVP_CIPH_OFB_MODE || mode == EVP_CIPH_CFB_MODE)
		enc = 1;

	if (enc)
		SM4_set_encrypt_key(ctx->cipher_data, key);
	else
		SM4_set_decrypt_key(ctx->cipher_data, key);
	return 1;
}
