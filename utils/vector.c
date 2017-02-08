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
