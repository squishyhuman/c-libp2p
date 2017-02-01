#pragma once

struct Propose {
	unsigned char* rand;
	size_t rand_size;
	unsigned char* public_key;
	size_t public_key_size;
	char* exchanges;
	size_t exchanges_size;
	char* ciphers;
	size_t ciphers_size;
	char* hashes;
	size_t hashes_size;
};

/**
 * retrieves the approximate size of an encoded version of the passed in struct
 * @param in the struct to look at
 * @reutrns the size of buffer needed
 */
size_t libp2p_secio_propose_protobuf_encode_size(struct Propose* in);

/**
 * Encode the struct Propose in protobuf format
 * @param in the struct to be encoded
 * @param buffer where to put the results
 * @param max_buffer_length the max to write
 * @param bytes_written how many bytes were written to the buffer
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_secio_propose_protobuf_encode(struct Propose* in, unsigned char* buffer, size_t max_buffer_length, size_t* bytes_written);

/**
 * Turns a protobuf array into a Propose struct
 * @param buffer the protobuf array
 * @param max_buffer_length the length of the buffer
 * @param out a pointer to the new struct Propose NOTE: this method allocates memory
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_secio_propose_protobuf_decode(unsigned char* buffer, size_t max_buffer_length, struct Propose** out);
