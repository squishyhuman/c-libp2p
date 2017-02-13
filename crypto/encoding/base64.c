#include <stdio.h>
#include <math.h>

#include "mbedtls/base64.h"

/**
 * encode using base64
 * @param input_data the data to be encoded
 * @param input_length the length of the input data
 * @param output_data where the data is to be stored
 * @param max_output_length the max size of the output_data
 * @param bytes_written the number of bytes written to output_data
 * @returns true(1) on success, otherwise false
 */
int libp2p_crypto_encoding_base64_encode(const unsigned char* input_data, size_t input_length, unsigned char* output_data, size_t max_output_length, size_t* bytes_written) {
	int retVal = mbedtls_base64_encode(output_data, max_output_length, bytes_written, input_data, input_length);
	return retVal == 0;
}

/**
 * decode something that was encoded as base64
 * @param input_data the data to decode
 * @param input_length the length of the input data
 * @param output_data the buffer to store the output
 * @param max_output_length the length of the output buffer
 * @param bytes_written the number of bytes written to output_data
 * @returns true(1) on success, otherwise 0
 */
int libp2p_crypto_encoding_base64_decode(const unsigned char* input_data, size_t input_length, unsigned char* output_data, size_t max_output_length, size_t* bytes_written) {
	int retVal = mbedtls_base64_decode(output_data, max_output_length, bytes_written, input_data, input_length);
	return retVal == 0;
}

/**
 * calculate the max length in bytes of an encoding of n source bytes
 * @param encoded_size the size of the encoded string
 * @returns the maximum size in bytes had the string been decoded
 */
size_t libp2p_crypto_encoding_base64_decode_size(size_t encoded_size) {
	size_t radix = 64;
	double bits_per_digit = log2(radix); // each char represents about 6 bits

	return ceil(encoded_size * bits_per_digit / 8);
}

/**
 * calculate the max length in bytes of a decoding of n source bytes
 * @param decoded_size the size of the incoming string to be encoded
 * @returns the maximum size in bytes had the string been encoded
 */
size_t libp2p_crypto_encoding_base64_encode_size(size_t decoded_size) {
	/*
	size_t radix = 64;
	double bits_per_digit = log2(radix);

	return ceil( (8 / bits_per_digit * decoded_size) + 1);
	*/
	return (decoded_size / 3  + (decoded_size % 3 != 0)) * 4 + 1;
}

