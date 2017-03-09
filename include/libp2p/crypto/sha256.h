#pragma once

#include "mbedtls/sha256.h"

/***
 * hash a string using SHA256
 * @param input the input string
 * @param input_length the length of the input string
 * @param output where to place the results
 * @returns 1
 */
int libp2p_crypto_hashing_sha256(const unsigned char* input, size_t input_length, unsigned char* output);

/**
 * Initialize a sha256 hmac process
 * @param ctx the context
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_hashing_sha256_init(mbedtls_sha256_context* ctx);

/**
 * Update a sha256 hmac process
 * @param ctx the context
 * @param input the data to add
 * @param input_size the size of input
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_hashing_sha256_update(mbedtls_sha256_context* ctx, const unsigned char* input, size_t input_size);

/**
 * finalize a sha256 hmac process
 * @param ctx the context
 * @param hash where to put the results (for SHA256, should be 32 bytes long)
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_hashing_sha256_finish(mbedtls_sha256_context* ctx, unsigned char* hash);

/**
 * Clean up allocated memory
 * @param ctx the context
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_hashing_sha256_free(mbedtls_sha256_context* ctx);
