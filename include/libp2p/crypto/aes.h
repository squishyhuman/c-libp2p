#pragma once

/**
 * Encrypt a block of text
 * @param input the text to encrypt
 * @param input_size the length of the array
 * @param output where the output will be placed
 * @param output_size the length of the memory allocated for output
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_aes_encrypt(char* input, size_t input_size, unsigned char* output, size_t& output_size);
