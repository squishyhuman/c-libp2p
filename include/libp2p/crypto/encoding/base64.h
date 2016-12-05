#ifndef base64_h
#define base64_h

#include <stdio.h>

/**
 * encode using base64
 * @param input_data the data to be encoded
 * @param input_length the length of the input data
 * @param output_data where the data is to be stored
 * @param max_output_length the max size of the output_data
 * @param bytes_written the number of bytes written to output_data
 * @returns true(1) on success, otherwise false
 */
int libp2p_crypto_encoding_base64_encode(const unsigned char* input_data, size_t input_length, unsigned char* output_data, size_t max_output_length, size_t* bytes_written);

/**
 * calculate the max length in bytes of an encoding of n source bytes
 * @param encoded_size the size of the encoded string
 * @returns the maximum size in bytes had the string been decoded
 */
size_t libp2p_crypto_encoding_base64_encode_size(size_t input_length);

/**
 * decode something that was encoded as base64
 * @param input_data the data to decode
 * @param input_length the length of the input data
 * @param output_data the buffer to store the output
 * @param max_output_length the length of the output buffer
 * @param bytes_written the number of bytes written to output_data
 * @returns a pointer to the decoded data
 */
int libp2p_crypto_encoding_base64_decode(const unsigned char* input_data, size_t input_length, unsigned char* output_data, size_t max_output_length, size_t* bytes_written);

/**
 * calculate the max length in bytes of a decoding of n source bytes
 * @param decoded_size the size of the incoming string to be encoded
 * @returns the maximum size in bytes had the string been encoded
 */
size_t libp2p_crypto_encoding_base64_decode_size(size_t input_length);

#endif /* base64_h */
