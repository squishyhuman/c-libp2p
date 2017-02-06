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
