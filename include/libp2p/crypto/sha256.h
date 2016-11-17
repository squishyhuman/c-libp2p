#ifndef __CRYPTO_HASHING_SHA256_H__
#define __CRYPTO_HASHING_SHA256_H__

/***
 * hash a string using SHA256
 * @param input the input string
 * @param input_length the length of the input string
 * @param output where to place the results
 * @returns 1
 */
int libp2p_crypto_hashing_sha256(const unsigned char* input, size_t input_length, unsigned char output[32]);

#endif
