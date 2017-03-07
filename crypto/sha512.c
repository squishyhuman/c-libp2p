#include "mbedtls/sha512.h"

/***
 * hash a string using SHA512
 * @param input the input string
 * @param input_length the length of the input string
 * @param output where to place the results
 * @returns 1
 */
int libp2p_crypto_hashing_sha512(const unsigned char* input, size_t input_length, unsigned char* output) {
	mbedtls_sha512(input, input_length, output, 0);
	return 64;
}
