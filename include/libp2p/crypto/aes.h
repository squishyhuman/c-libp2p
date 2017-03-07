#pragma once

/**
 * Generate a new AES key
 * @param key where to store the 32 byte key
 * @returns true(1) on success
 */
int libp2p_crypto_aes_key_generate(char* key);

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
int libp2p_crypto_aes_encrypt(char* key, char* iv, char* input, size_t input_size, unsigned char** output, size_t* output_size);

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
int libp2p_crypto_aes_decrypt(char* key, char* iv, char* input, size_t input_size, unsigned char** output, size_t* output_size);
