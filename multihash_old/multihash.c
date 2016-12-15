#include "../include/libp2p/multihash_old/multihash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libp2p/crypto/encoding/base58.h"


char* libp2p_multihash_get_fn_name(char fn_code) {
	switch(fn_code) {
		case (0x11):
			return "sha1";
		case(0x12):
			return "sha2-256";
		case(0x13):
			return "sha2-512";
		case(0x14):
			return "sha3-512";
		case(0x15):
			return "sha3-384";
		case(0x16):
			return "sha3-256";
		case(0x17):
			return "sha3-224";
		case(0x18):
			return "shake-128";
		case(0x19):
			return "shake-256";
		case(0x20):
			return "blake2b";
		case(0x21):
			return "blake2s";
	}
	return 0x00;
}

/**
 * helper function to convert a char string to a byte
 * @param s the string (only grabs the first character)
 * @returns the value of the char
 */
unsigned char from_hex_to_char(const char* s) {
	// make sure there is a null in position 3
	char buff[3];
	buff[0] = s[0];
	buff[1] = s[1];
	buff[2] = 0;
	char* ptr = &buff[2];
	return strtoul(buff, &ptr, 16);
}

/***
 * convert a MultiHash into a byte array
 * @param hash the MultiHash to convert
 * @param results the resultant byte array
 * @param max_length the maximum length of the byte array
 * @returns true(1) on success
 */
int from_multihash_to_byte_array(struct MultiHash* hash, unsigned char* results, size_t max_length) {
	// what size is needed?
	int required_size = hash->size + 2;
	
	if (required_size < max_length)
		return 0;
	
	results[0] = hash->fn_code;
	results[1] = hash->size;
	
	// now copy in the data
	for(int i = 0; i < hash->size; i++)
		results[i+2] = hash->data[i];

	return 1;
}

/***
 * public methods
 **/

/***
 * retrieve the size element of the multihash object that is embedded in the base58 string
 * @param b58_string the base58 encoded string
 * @returns the size element of the MultiHash object
 */
size_t libp2p_multihash_b58_size(unsigned char* b58_string) {
	size_t byte_length = libp2p_crypto_encoding_base58_decode_max_size(b58_string);
	unsigned char bytes[byte_length];
	unsigned char* ptr = bytes;
	
	int retVal = libp2p_crypto_encoding_base58_decode(b58_string, strlen((char*)b58_string), &ptr, &byte_length);
	if (retVal == 0)
		return 0;
	
	return ptr[1];
}

/**
 * turns a multihash into a string of hex
 */
int libp2p_multihash_hex_string(struct MultiHash* hash, char* string, int max_length) {
	// calculate the size of the struct
	size_t struct_size = sizeof(char) * (hash->size + 2);
	
	// make sure we have enough space (2 bytes for each byte, plus terminating null
	if (max_length < (struct_size * 2))
		return 0;

	// put in the hex values
	char temp[3];
	sprintf(temp, "%02x", hash->fn_code);
	string[0] = temp[0];
	string[1] = temp[1];
	sprintf(temp, "%02x", hash->size);
	string[2] = temp[0];
	string[3] = temp[1];
	for(int i = 0; i < struct_size - 2; i++) {
		sprintf(temp, "%02x", hash->data[i]);
		string[(i*2) + 4] = temp[0];
		string[(i*2) + 5] = temp[1];
	}
	return 1;
}

/**
 * decodes a hex string into a multihash
 */
int libp2p_multihash_from_hex_string(char* string, int length, struct MultiHash* hash) {
	hash->fn_code = from_hex_to_char(&string[0]);
	hash->size = from_hex_to_char(&string[2]);
	for(int i = 0; i < hash->size; i++) {
		int pos = (i * 2) + 4;
		if (pos > length - 1)
			return 0;
		hash->data[i] = from_hex_to_char(&string[(i*2) + 4]);
	}
	return 1;
}

/**
 * turns a multihash into a b58 string
 * @param hash the Multihash to encode
 * @param binary_buffer the buffer to fill
 * @param max_length the size of the buffer
 * @returns true(1) on success
*/
int libp2p_multihash_to_b58(struct MultiHash* hash, unsigned char* binary_buffer, size_t max_length) {
	int bytes_length = hash->size + 2;
	unsigned char bytes[bytes_length];
	unsigned char* ptr = bytes;
	
	int retVal = from_multihash_to_byte_array(hash, bytes, bytes_length);
	if (retVal == 0)
		return 0;

	// finally encode the array into base64
	return libp2p_crypto_encoding_base58_encode(ptr, bytes_length, &binary_buffer, &max_length);
}

/**
 * turns a base58 encoded string into a MultiHash
 * @param b58_string the base58 encoded string
 * @param b58_string_length the length of the encoded string
 * @param hash the MultiHash to fill
 * @returns true(1) on success
 */
int libp2p_b58_to_multihash(unsigned char* b58_string, size_t b58_string_length, struct MultiHash* hash) {
	size_t buffer_size = libp2p_crypto_encoding_base58_decode_max_size(b58_string);
	unsigned char buffer[buffer_size];
	unsigned char* b = buffer;
	
	libp2p_crypto_encoding_base58_decode(b58_string, b58_string_length, &b, &buffer_size);

	// now build the hash
	hash->fn_code = b[0];
	hash->size = b[1];
	memcpy(hash->data, &b[2], hash->size);
	return 0;	
}
