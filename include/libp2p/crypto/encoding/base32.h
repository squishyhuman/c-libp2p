#ifndef __LIBP2P_CRYPTO_ENCODING_BASE32_H__
#define __LIBP2P_CRYPTO_ENCODING_BASE32_H__

#include <string.h>

/**
 * Encode in Base32 format
 * @param incoming the incoming bytes
 * @param incoming_length the length of the incoming bytes
 * @param results where to put the results
 * @param results_length the size of the buffer, and returns the actual length used
 * @returns true(1) on success
 */
int libp2p_crypto_encoding_base32_encode(const unsigned char* incoming, size_t incoming_length,
		unsigned char* results, size_t* results_length);

/**
 * Calculate the size of the buffer necessary to encode
 * @param incoming_length the length of the incoming value
 * @returns the size of the buffer necessary to hold the encoded bytes
 */
size_t libp2p_crypto_encoding_base32_encode_size(size_t incoming_length);

/**
 * Decode from Base16 format
 * @param incoming the incoming base16 encoded string
 * @param incoming_length the length of the incoming string (no need to include null)
 * @param results where to put the results
 * @param results_length the size of the buffer, and returns the actual length used
 * @returns true(1) on success
 */
int libp2p_crypto_encoding_base32_decode(const unsigned char* incoming, size_t incoming_length,
		unsigned char* results, size_t* results_length);

/**
 * Calculate the size of the buffer necessary to decode
 * @param incoming_length the length of the incoming value
 * @returns the size of the buffer necessary to hold the decoded bytes
 */
size_t libp2p_crypto_encoding_base32_decode_size(size_t incoming_length);

#endif
