#include <stdlib.h>

#include "libp2p/secio/char_vector.h"

struct UnsignedCharVector* char_vector_new() {
	struct UnsignedCharVector* vector = (struct UnsignedCharVector*)malloc(sizeof(struct UnsignedCharVector));
	vector->buffer = NULL;
	vector->buffer_size = 0;
	return vector;
}

void char_vector_free(struct UnsignedCharVector* vector) {
	if (vector != NULL) {
		if (vector->buffer != NULL)
			free(vector->buffer);
		vector->buffer = NULL;
		vector->buffer_size = 0;
		free(vector);
		vector = NULL;
	}
}

int char_vector_add(struct UnsignedCharVector* vector, unsigned char* in_bytes, size_t in_size) {
	// make new memory
	if (vector->buffer == NULL) {
		vector->buffer = (unsigned char*)malloc(in_size);
		if (vector->buffer == NULL)
			return 0;
		vector->buffer_size = in_size;
	} else {
		vector->buffer = (unsigned char*)realloc(vector->buffer_size + in_size);
		if (vector->buffer == NULL)
			return 0;
		memcpy(&vector->buffer[vector->buffer_size], in_bytes, in_size);
		vector->buffer_size = in_size + vector->buffer_size;
	}
	return 1;
}
