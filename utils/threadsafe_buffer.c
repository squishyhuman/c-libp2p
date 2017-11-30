/**
 * A thredsafe buffer
 */

#include <stdlib.h>

#include "libp2p/utils/threadsafe_buffer.h"
#include "libp2p/utils/logger.h"

/***
 * Allocate a new context
 * @returns a newly allocated context, or NULL on error (out of memory?)
 */
struct ThreadsafeBufferContext* threadsafe_buffer_context_new() {
	struct ThreadsafeBufferContext* context = (struct ThreadsafeBufferContext*) malloc(sizeof(struct ThreadsafeBufferContext));
	if (context != NULL) {
		context->buffer_size = 0;
		context->buffer = NULL;
		pthread_mutex_init(&context->lock, NULL);
	}
	return context;
}

/***
 * Free resources of a buffer context
 * @param context the context
 */
void threadsafe_buffer_context_free(struct ThreadsafeBufferContext* context) {
	if (context != NULL) {
		if (context->buffer != NULL)
			free(context->buffer);
		free(context);
	}
}

/***
 * Read from the buffer without destroying its contents or moving its read pointer
 * @param context the context
 * @param results where to put the results
 * @param results_size the size of the results
 * @returns number of bytes read
 */
size_t threadsafe_buffer_peek(struct ThreadsafeBufferContext* context, uint8_t* results, size_t results_size) {
	size_t bytes_read = 0;
	if (context == NULL)
		return 0;
	pthread_mutex_lock(&context->lock);
	// do the read
	if (context->buffer != NULL && context->buffer_size > 0) {
		bytes_read = results_size < context->buffer_size ? results_size : context->buffer_size;
		memcpy(results, context->buffer, bytes_read);
	}
	pthread_mutex_unlock(&context->lock);
	return bytes_read;
}

/***
 * Read from the buffer.
 * NOTE: If results_size is more than what is left in the buffer, this will read everything.
 * @param context the context
 * @param results where to put the results
 * @param results_size the size of the buffer
 * @returns number of bytes read
 */
size_t threadsafe_buffer_read(struct ThreadsafeBufferContext* context, uint8_t* results, size_t results_size) {
	size_t bytes_read = 0;
	if (context == NULL)
		return 0;
	pthread_mutex_lock(&context->lock);
	// do the read
	if (context->buffer != NULL && context->buffer_size > 0) {
		bytes_read = results_size < context->buffer_size ? results_size : context->buffer_size;
		libp2p_logger_debug("threadsafe_buffer", "read: We want to read %d bytes, and have %d in the buffer. Therefore, we will read %d.\n", results_size, context->buffer_size, bytes_read);
		memcpy(results, context->buffer, bytes_read);
	}
	// adjust the size
	if (bytes_read > 0) {
		if (context->buffer_size - bytes_read > 0) {
			// more remains
			size_t new_buffer_size = context->buffer_size - bytes_read;
			uint8_t* new_buffer = (uint8_t*) malloc(new_buffer_size);
			memcpy(new_buffer, &context->buffer[bytes_read], new_buffer_size);
			free(context->buffer);
			context->buffer = new_buffer;
			context->buffer_size = new_buffer_size;
		} else {
			// everything has been read
			free(context->buffer);
			context->buffer = NULL;
			context->buffer_size = 0;
		}
	}
	pthread_mutex_unlock(&context->lock);
	return bytes_read;
}

/****
 * Add bytes to the end of the buffer
 * @param context the context
 * @param bytes the bytes to add
 * @param bytes_size the size of bytes
 * @returns the size added to the buffer (0 on error)
 */
size_t threadsafe_buffer_write(struct ThreadsafeBufferContext* context, const uint8_t* bytes, size_t bytes_size) {
	if (context == NULL)
		return 0;
	if (bytes_size == 0)
		return 0;
	size_t bytes_copied = 0;
	pthread_mutex_lock(&context->lock);
	// allocate memory
	uint8_t* new_buffer = (uint8_t*) realloc(context->buffer, context->buffer_size + bytes_size);
	if (new_buffer != NULL) {
		// copy data
		memcpy(&new_buffer[context->buffer_size], bytes, bytes_size);
		context->buffer_size += bytes_size;
		context->buffer = new_buffer;
		bytes_copied = bytes_size;
		libp2p_logger_debug("threadsafe_buffer", "write: Added %d bytes. Buffer now contains %d bytes.\n", bytes_size, context->buffer_size);
	}
	pthread_mutex_unlock(&context->lock);
	return bytes_copied;
}
