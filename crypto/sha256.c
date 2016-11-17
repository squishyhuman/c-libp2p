#include "mbedtls/sha256.h"

/***
 * hash a string using SHA256
 * @param input the input string
 * @param input_length the length of the input string
 * @param output where to place the results
 * @returns 1
 */
int libp2p_crypto_hashing_sha256(const unsigned char* input, size_t input_length, unsigned char output[32]) {
	mbedtls_sha256(input, input_length, output, 0);
	return 1;
}
