#include "mbedtls/sha256.h"

/***
 * hash a string using SHA256
 * @param input the input string
 * @param input_length the length of the input string
 * @param output where to place the results, should be 32 bytes
 * @returns 1
 */
int libp2p_crypto_hashing_sha256(const unsigned char* input, size_t input_length, unsigned char* output) {
	mbedtls_sha256(input, input_length, output, 0);
	return 32;
}


/**
 * Initialize a sha256 hmac process
 * @param ctx the context
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_hashing_sha256_init(mbedtls_sha256_context* ctx) {
	mbedtls_sha256_init(ctx);
	return 1;
}

/**
 * Update a sha256 hmac process
 * @param ctx the context
 * @param input the data to add
 * @param input_size the size of input
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_hashing_sha256_update(mbedtls_sha256_context* ctx, const unsigned char* input, size_t input_size) {
	mbedtls_sha256_update(ctx, input, input_size);
	return 1;
}

/**
 * finalize a sha256 hmac process
 * @param ctx the context
 * @param hash where to put the results (for SHA256, should be 32 bytes long)
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_hashing_sha256_finish(mbedtls_sha256_context* ctx, unsigned char* hash) {
	mbedtls_sha256_finish(ctx, hash);
	return 1;
}

/**
 * Clean up allocated memory
 * @param ctx the context
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_hashing_sha256_free(mbedtls_sha256_context* ctx) {
	mbedtls_sha256_free(ctx);
	return 1;
}
