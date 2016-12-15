/**
 * An implementation of the multihash protocol in C
 */

#ifndef __LIBP2P_MULTIHASH_H
#define __LIBP2P_MULTIHASH_H

#define MULTIHASH_SHA1	0x11
#define MULTIHASH_SHA2_256 0x12
#define MULTIHASH_SHA2_512 0x13
#define MULTIHASH_SHA3_512 0x14
#define MULTIHASH_SHA3_384 0x15
#define MULTIHASH_SHA3_256 0x16
#define MULTIHASH_SHA3_224 0x17
#define MULTIHASH_SHAKE_128 0x18
#define MULTIHASH_SHAKE_256 0x19
#define MULTIHASH_BLAKE2B 0x20
#define MULTIHASH_BLAKE2S 0x21

struct MultiHash {
	char fn_code;
	char size;
	unsigned char* data;
};

char* libp2p_multihash_get_fn_name(char fn_code);

/**
 * encodes the multihash into a hex string
 */
int libp2p_multihash_hex_string(struct MultiHash* hash, char* string, int max_length);

/**
 * decodes a hex string into a multihash
 */
int libp2p_multihash_from_hex_string(char* string, int length, struct MultiHash* hash);

/**
 * turns a multihash into a b58 string
 * @param hash the Multihash to encode
 * @param binary_buffer the buffer to fill
 * @param max_length the size of the buffer
 * @returns true(1) on success
 */
int libp2p_multihash_to_b58(struct MultiHash* hash, unsigned char* binary_buffer, size_t max_length);

/**
 * turns a base58 encoded string into a MultiHash
 * @param b58_string the base58 encoded string
 * @param b58_string_length the length of the encoded string
 * @param hash the MultiHash to fill
 * @returns true(1) on success
 */
int libp2p_b58_to_multihash(unsigned char* b58_string, size_t b58_string_length, struct MultiHash* hash);

/**
 * retrieve the size required for the multihash that is embedded in the base58 encoded string
 */
size_t libp2p_multihash_b58_size(unsigned char* b58_string);

#endif /* multihash_h */
