#include <stdlib.h>
#include <string.h>

#include "libp2p/utils/vector.h"

/**
 * Allocate memory for a new Libp2pVector
 * @returns a new Libp2pVector or NULL if it couldn't do it
 */
struct Libp2pVector* libp2p_utils_vector_new() {
	struct Libp2pVector* out = (struct Libp2pVector*)malloc(sizeof(struct Libp2pVector));
	if (out != NULL) {
		out->buffer = NULL;
		out->buffer_size = 0;
	}
	return out;
}

void libp2p_utils_vector_free(struct Libp2pVector* vector) {
	if (vector != NULL) {
		if (vector->buffer != NULL)
			free(vector->buffer);
		vector->buffer_size = 0;
		free(vector);
		vector = NULL;
	}
}

/**
 * Add bytes to vector
 */
int libp2p_utils_vector_add(struct Libp2pVector* vector, unsigned char* in_bytes, size_t in_size) {
	if (in_size > 0) {
		if (vector->buffer == NULL) {
			vector->buffer = (unsigned char*)malloc(in_size);
			if (vector->buffer == NULL)
				return 0;
			memcpy(vector->buffer, in_bytes, in_size);
		} else {
			vector->buffer = (unsigned char*)realloc(vector->buffer, in_size + vector->buffer_size);
			if (vector->buffer == NULL)
				return 0;
			memcpy(&vector->buffer[vector->buffer_size], in_bytes, in_size);
			vector->buffer_size += in_size;
		}
	}
	return 1;
}

int libp2p_utils_vector_serialize(struct Libp2pVector* vector, unsigned char** out, size_t* out_size) {
	// the first 4 bytes are the size, followed by the the byte array
	*out_size = vector->buffer_size + 4;
	*out = (unsigned char*)malloc(*out_size);
	if (*out == NULL)
		return 0;
	unsigned char* ptr = *out;
	ptr[0] = (vector->buffer_size >> 24) & 0xFF;
	ptr[1] = (vector->buffer_size >> 16) & 0xFF;
	ptr[2] = (vector->buffer_size >> 8) & 0xFF;
	ptr[3] = vector->buffer_size & 0xFF;
	memcpy(&ptr[4], vector->buffer, vector->buffer_size);
	return 1;
}

int libp2p_utils_vector_unserialize(unsigned char* in, struct Libp2pVector** out) {
	*out = (struct Libp2pVector*)malloc(sizeof(struct Libp2pVector));
	if (*out == NULL)
		return 0;
	struct Libp2pVector* ptr = *out;
	ptr->buffer_size = in[0] | (in[1] << 8) | (in[2] << 16) | (in[3] << 24);
	ptr->buffer = (unsigned char*)malloc(ptr->buffer_size);
	if (ptr->buffer == NULL) {
		free (*out);
		return 0;
	}
	memcpy(ptr->buffer, &in[4], ptr->buffer_size);
	return 1;
}
