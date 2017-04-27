#ifndef test_base58_h
#define test_base58_h

#include "libp2p/crypto/encoding/base58.h"

/***
 * tests the base58 encoding and decoding
 */
int test_base58_encode_decode() {
	
	unsigned char original[3] = { 0x41, 0x42 ,0x00 };
	
	size_t buffer_size = 10;
	unsigned char buffer[buffer_size];
	unsigned char* ptr = buffer;
	
	int retVal = libp2p_crypto_encoding_base58_encode(original, 3, &ptr, &buffer_size);
	if (retVal == 0)
		return 0;
	
	size_t result_size = 3;
	unsigned char result[result_size];
	unsigned char* ptr2 = result;
	memset(result, 0, result_size);
	
	retVal = libp2p_crypto_encoding_base58_decode(ptr, buffer_size, &ptr2, &result_size);
	if (retVal == 0)
		return 0;
	
	for (int i = 0; i < 3; i++)
		if (original[i] != result[i])
			return 0;
	
	return 1;
}

int test_base58_size() {
	unsigned char* unencoded = (unsigned char*)"Hello, World!"; // 13 chars + 1 null
	size_t string_length = strlen((char*)unencoded) + 1;
	
	size_t encoded_length = libp2p_crypto_encoding_base58_encode_size(string_length);

	if (encoded_length != 20) {
		fprintf(stderr, "Encoded length incorrect. Should have been 20 and is %lu\n", encoded_length);
		return 0;
	}

	size_t encoded_max_length = 100;
	unsigned char encoded[encoded_max_length];
	unsigned char* ptr = encoded;
	
	// now encode it
	libp2p_crypto_encoding_base58_encode(unencoded, string_length-1, &ptr, &encoded_max_length);
	
	size_t decoded_length = libp2p_crypto_encoding_base58_decode_size(encoded_max_length);
	
	if (decoded_length != string_length) {
		fprintf(stderr, "String length and decoded length are different. Decoded length = %lu and string length is %lu\n", decoded_length, string_length);
		return 0;
	}
	
	return 1;
}

int test_base58_max_size() {
	unsigned char hash[5] = {'S', 'D', 'Y', 'h', 'd' };
	
	size_t results = libp2p_crypto_encoding_base58_decode_size(5);
	if (results != 4)
		return 0;
	
	return 1;
}

int test_base58_peer_address() {
	char* x_data = "QmPZ9gcCEpqKTo6aq61g2nXGUhM4iCL3ewB6LDXZCtioEB";
	size_t x_data_length = strlen(x_data);
	size_t result_buffer_length = libp2p_crypto_encoding_base58_decode_size(x_data_length);
	unsigned char result_buffer[result_buffer_length];
	unsigned char* ptr_to_result = result_buffer;
	memset(result_buffer, 0, result_buffer_length);
	// now get the decoded address
	int return_value = libp2p_crypto_encoding_base58_decode((unsigned char*)x_data, x_data_length, &ptr_to_result, &result_buffer_length);
	if (return_value == 0)
		return 0;
	// add 2 bytes to the front for the varint
	unsigned char final_result[result_buffer_length + 2];
	// TODO: put the 2 bytes of your varint here, and erase the memset line below.
	memset(final_result, 0, 2);
	memcpy(&(final_result[2]), result_buffer, result_buffer_length);
	// throw everything in a hex string so we can debug the results
	for(int i = 0; i < result_buffer_length + 2; i++) {
		// get the char so we can see it in the debugger
		unsigned char c = final_result[i];
		printf("%02x", c);
	}
	printf("\n");
	return 1;
}

#endif /* test_base58_h */
