#ifndef test_multihash_h
#define test_multihash_h

#include "../../include/libp2p/multihash_old/multihash.h"
#include "libp2p/crypto/encoding/base58.h"

int test_multihash_encode() {
	struct MultiHash hash;
	hash.fn_code = MULTIHASH_SHA1;
	hash.size = 2;
	unsigned char data[] = "A";
	hash.data = data;
	// 8 bytes plus terminating null to make it easier to debug
	// note: function does not clear the buffer, so we have to
	char buffer[9];
	char* b = buffer;
	memset(b, 0, 9);
	int retVal = libp2p_multihash_hex_string(&hash, b, 9);
	if (retVal == 0)
		return 0;
	
	if (b[0] != '1' && b[1] != '1')
		return 0;
	if (b[2] != '0' && b[3] != '2')
		return 0;
	if (b[4] != '4' && b[5] != '1')
		return 0;
	if (b[6] != '0' && b[7] != '0')
		return 0;
	return 1;
}

int test_multihash_decode() {
	char in[9] = "11024100";
	char* string = in;
	struct MultiHash hash;
	
	int retVal = libp2p_multihash_from_hex_string(string, 8, &hash);
	if (retVal == 0)
		return 0;
	
	if (hash.fn_code != 0x11)
		return 0;
	if (hash.size != 2)
		return 0;
	if (hash.data[0] != 0x41 || hash.data[1] != 0x00)
		return 0;
	return 1;
}

int test_multihash_base58_decode() {
	unsigned char original[5] = { 'S', 'D', 'Y', 'h', 'd' };
	
	size_t buffer_len = 4;
	unsigned char buffer[buffer_len];
	unsigned char* ptr = buffer;
	
	int retVal = libp2p_crypto_encoding_base58_decode(original, 5, &ptr, &buffer_len);
	if (retVal == 0)
		return 0;
	if (buffer[0] != 0x11)
		return 0;
	if (buffer[1] != 0x02)
		return 0;
	
	return 1;
}

int test_multihash_size() {
	unsigned char hash[6] = {'S', 'D', 'Y', 'h', 'd' ,0 };
	unsigned char* ptr = hash;
	size_t sz = libp2p_multihash_b58_size(ptr);
	
	return sz == 2;
}

int test_multihash_base58_encode_decode() {
	// build the original MultiHash
	struct MultiHash original;
	original.fn_code = MULTIHASH_SHA1;
	original.size = 2;
	unsigned char data[] = "A";
	original.data = data;
	
	// have a buffer to store the base58 encoding
	size_t buffer_size = 65535;
	unsigned char buffer[buffer_size];
	unsigned char* b = buffer;
	
	// encode it
	libp2p_multihash_to_b58(&original, b, buffer_size);
	
	// build a place to store the new MultiHash
	struct MultiHash results;
	results.size = 2;
	unsigned char results_data[2];
	results.data = results_data;
	
	// decode it
	libp2p_b58_to_multihash(b, strlen((char*)b), &results);
	
	// compare
	if (original.fn_code != results.fn_code)
		return 0;
	if (original.size != results.size)
		return 0;
	if (original.data[0] != results.data[0])
		return 0;
	if (original.data[1] != results.data[1])
		return 0;
	return 1;
}

#endif /* test_multihash_h */
