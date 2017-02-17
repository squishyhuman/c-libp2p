#pragma once

/***
 * A very simple vector implementation for unsigned chars
 */

/**
 * The struct
 */
struct Libp2pVector {
	unsigned char* buffer;
	size_t buffer_size;
};

/**
 * Create and destroy
 */
struct Libp2pVector* libp2p_utils_vector_new();
void libp2p_utils_vector_free(struct Libp2pVector* vector);

/**
 * Add bytes to vector
 */
int libp2p_utils_vector_add(struct Libp2pVector* vector, unsigned char* in_bytes, size_t in_size);

/**
 * serialize the vector into a byte array that has a 4 byte prefix of the size
 * @param vector the vector to serialize
 * @param out a pointer to the byte array that will be filled
 * @param out_size the number of bytes written
 * @returns true(1) on success, otherwise false
 */
int libp2p_utils_vector_serialize(struct Libp2pVector* vector, unsigned char** out, size_t* out_size);

/**
 * turn a byte array into a Libp2pVector
 * @param in the bytes that were previously serialized
 * @param out the new Libp2pVector
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_utils_vector_unserialize(unsigned char* in, struct Libp2pVector** out);
