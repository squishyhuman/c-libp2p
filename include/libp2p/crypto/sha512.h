#pragma once

/***
 * hash a string using SHA512
 * @param input the input string
 * @param input_length the length of the input string
 * @param output where to place the results, should be 64 bytes
 * @returns number of bytes written, or 0
 */
int libp2p_crypto_hashing_sha512(const unsigned char* input, size_t input_length, unsigned char* output);

