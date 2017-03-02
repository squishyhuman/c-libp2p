#include "mbedtls/aes.h"

/**
 * Encrypt a block of text
 * @param key the aes key
 * @param iv the random part of encryption
 * @param input the text to encrypt
 * @param input_size the length of the array
 * @param output where the output will be placed
 * @param output_size the length of the memory allocated for output
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_aes_encrypt(char* key, char* iv, char* input, size_t input_size, unsigned char* output, size_t* output_size) {
	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	mbedtls_aes_setkey_enc(&ctx, key, 256);
	mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, 24, iv, input, output);
	//TODO Implement this method
	return 0;
}
