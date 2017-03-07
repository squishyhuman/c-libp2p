#include <string.h>
#include <stdlib.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/aes.h"

/**
 * functions for aes encryption
 */

/**
 * Generate a new AES key
 * @param key where to store the 32 byte key
 * @returns true(1) on success
 */
int libp2p_crypto_aes_key_generate(char* key) {
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	mbedtls_entropy_init(&entropy);

	char* pers = "aes generate key";

	mbedtls_ctr_drbg_init(&ctr_drbg);

	if (mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
									  (const unsigned char *) pers,
									  strlen( pers )) != 0)
		return 0;

	if (mbedtls_ctr_drbg_random(&ctr_drbg, key, 32) != 0)
		return 0;

	return 1;
}

/**
 * Encrypt a block of text
 * @param key the aes key (32 bytes)
 * @param iv the random part of encryption (16 bytes)
 * @param input the text to encrypt
 * @param input_size the length of the array
 * @param output where the output will be placed
 * @param output_size the length of the memory allocated for output
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_aes_encrypt(char* key, char* iv, char* input, size_t input_size, unsigned char** output, size_t* output_size) {
	int new_size = 0;
	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	mbedtls_aes_setkey_enc(&ctx, key, 256);
	// turn input into a multiple of 16
	new_size = input_size;
	if (new_size % 16 != 0) {
		new_size += new_size % 16;
	}
	char* padded_input = malloc(new_size);
	memcpy(padded_input, input, input_size);
	if (new_size != input_size)
		memset(&padded_input[input_size], 0, new_size - input_size);
	// make room for the output
	*output = malloc(new_size);
	*output_size = new_size;
	int retVal = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, new_size, iv, padded_input, *output);
	free(padded_input);
	if (retVal != 0)
		free(output);
	return retVal == 0;
}

/**
 * Decrypt a block of text
 * @param key the aes key (32 bytes)
 * @param iv the random part of encryption (16 bytes)
 * @param input the text to encrypt
 * @param input_size the length of the array
 * @param output where the output will be placed
 * @param output_size the length of the memory allocated for output
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_aes_decrypt(char* key, char* iv, char* input, size_t input_size, unsigned char** output, size_t* output_size) {
	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	mbedtls_aes_setkey_dec(&ctx, key, 256);
	// make room for the output
	*output = malloc(input_size);
	*output_size = input_size;
	if (mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, input_size, iv, input, *output) != 0)
		return 0;
	return 1;
}
