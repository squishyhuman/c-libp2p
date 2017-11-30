#pragma once

/**
 * A thredsafe buffer
 */

#include <string.h>
#include <pthread.h>
#include <stdint.h>

/***
 * Holds the information about the buffer
 */
struct ThreadsafeBufferContext {
	size_t buffer_size;
	uint8_t* buffer;
	pthread_mutex_t lock;
};

/***
 * Allocate a new context
 * @returns a newly allocated context, or NULL on error (out of memory?)
 */
struct ThreadsafeBufferContext* threadsafe_buffer_context_new();

/***
 * Free resources of a buffer context
 * @param context the context
 */
void threadsafe_buffer_context_free(struct ThreadsafeBufferContext* context);

/***
 * Read from the buffer without destroying its contents or moving its read pointer
 * @param context the context
 * @param results where to put the results
 * @param results_size the size of the results
 * @returns number of bytes read
 */
size_t threadsafe_buffer_peek(struct ThreadsafeBufferContext* context, uint8_t* results, size_t results_size);

/***
 * Read from the buffer.
 * NOTE: If results_size is more than what is left in the buffer, this will read everything.
 * @param context the context
 * @param results where to put the results
 * @param results_size the size of the buffer
 * @returns number of bytes read
 */
size_t threadsafe_buffer_read(struct ThreadsafeBufferContext* context, uint8_t* results, size_t results_size);

/****
 * Add bytes to the end of the buffer
 * @param context the context
 * @param bytes the bytes to add
 * @param bytes_size the size of bytes
 * @returns the size added to the buffer (0 on error)
 */
size_t threadsafe_buffer_write(struct ThreadsafeBufferContext* context, const uint8_t* bytes, size_t bytes_size);
