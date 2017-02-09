#pragma once

struct Exchange {
	unsigned char* epubkey;
	size_t epubkey_size;
	unsigned char* signature;
	size_t signature_size;
};

struct Exchange* libp2p_secio_exchange_new();
void libp2p_secio_exchange_free(struct Exchange* in);

/**
 * retrieves the approximate size of an encoded version of the passed in struct
 * @param in the struct to look at
 * @reutrns the size of buffer needed
 */
size_t libp2p_secio_exchange_protobuf_encode_size(struct Exchange* in);

/**
 * Encode the struct Exchange in protobuf format
 * @param in the struct to be encoded
 * @param buffer where to put the results
 * @param max_buffer_length the max to write
 * @param bytes_written how many bytes were written to the buffer
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_secio_exchange_protobuf_encode(struct Exchange* in, unsigned char* buffer, size_t max_buffer_length, size_t* bytes_written);

/**
 * Turns a protobuf array into an Exchange struct
 * @param buffer the protobuf array
 * @param max_buffer_length the length of the buffer
 * @param out a pointer to the new struct Exchange NOTE: this method allocates memory
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_secio_exchange_protobuf_decode(unsigned char* buffer, size_t max_buffer_length, struct Exchange** out);
