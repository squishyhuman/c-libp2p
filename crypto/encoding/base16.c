#include <string.h>
#include <stdio.h>

#include "libp2p/crypto/encoding/base16.h"

/**
 * Encode in Base16 format
 * @param incoming the incoming bytes
 * @param incoming_length the length of the incoming bytes
 * @param results where to put the results
 * @param results_length the size of the buffer, and returns the actual length used
 * @returns true(1) on success
 */
int libp2p_crypto_encoding_base16_encode(const unsigned char* incoming, size_t incoming_length, unsigned char* results, size_t* results_length) {
	// the size will be 2x the size of incoming, so check that
	if (*results_length < incoming_length * 2)
		return 0;

	// clear out the results variable
	memset(results, 0, *results_length);

	*results_length = 0;
	for(int i = 0; i < incoming_length; i++) {
		unsigned char buf[3];
		sprintf((char*)buf, "%02x", incoming[i]);
		results[i * 2] = buf[0];
		results[i * 2 + 1] = buf[1];
		*results_length += 2;
	}

	return 1;
}

/**
 * Calculate the size of the buffer necessary to encode
 * @param incoming_length the length of the incoming value
 * @returns the size of the buffer necessary to hold the encoded bytes
 */
int libp2p_crypto_encoding_base16_encode_size(size_t incoming_length) {
	return incoming_length * 2;
}

/**
 * Decode from Base16 format
 * @param incoming the incoming base16 encoded string
 * @param incoming_length the length of the incoming string (no need to include null)
 * @param results where to put the results
 * @param results_length the size of the buffer, and returns the actual length used
 * @returns true(1) on success
 */
int libp2p_crypto_encoding_base16_decode(const unsigned char* incoming, size_t incoming_length, unsigned char* results, size_t* results_length) {

	// buffer too small
	if (*results_length < incoming_length / 2)
		return 0;

	memset(results, 0, *results_length);

	char* pos = (char*)incoming;

	for(int i = 0; i < incoming_length / 2; i++) {
		sscanf(pos, "%2hhx", &results[i]);
		pos += 2;
	}
	return 1;
}

/**
 * Calculate the size of the buffer necessary to decode
 * @param incoming_length the length of the incoming value
 * @returns the size of the buffer necessary to hold the decoded bytes
 */
int libp2p_crypto_encoding_base16_decode_size(size_t incoming_length) {
	return incoming_length / 2;
}

