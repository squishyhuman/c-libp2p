#pragma once

#include <pthread.h>

/**
 * Encapsulates a message that (was/will be) sent
 * across a stream
 */
struct StreamMessage {
	uint8_t* data;
	size_t data_size;
	int error_number;
};

/***
 * Create a new StreamMessage struct
 * @returns a StreamMessage struct
 */
struct StreamMessage* libp2p_stream_message_new();

/**
 * free resources of a StreamMessage struct
 * @param msg the StreamMessage to free
 */
void libp2p_stream_message_free(struct StreamMessage* msg);


/**
 * An interface in front of various streams
 */
struct Stream {
	/**
	 * A generic socket descriptor
	 */
	void* socket_descriptor;
	pthread_mutex_t socket_mutex;
	struct MultiAddress *address;

	/**
	 * Reads from the stream
	 * @param stream the stream context (usually a SessionContext pointer)
	 * @param message where to put the incoming message (will be allocated)
	 * @param timeout_secs number of seconds before a timeout
	 * @returns true(1) on success, false(0) otherwise
	 */
	int (*read)(void* stream_context, struct StreamMessage** message, int timeout_secs);

	/**
	 * Writes to a stream
	 * @param stream the stream context (usually a SessionContext pointer)
	 * @param buffer what to write
	 * @param how much to write
	 * @returns true(1) on success, false(0) otherwise
	 */
	int (*write)(void* stream_context, const unsigned char* buffer, size_t buffer_size);

	/**
	 * Closes a stream
	 *
	 * NOTE: This is also responsible for deallocating the Stream struct
	 * @param stream the stream context
	 * @returns true(1) on success, otherwise false(0)
	 */
	int (*close)(void* stream_context);

	/***
	 * Checks to see if something is waiting on the stream
	 *
	 * @param stream the stream context
	 * @returns true(1) if something is waiting, false(0) otherwise
	 */
	int (*peek)(void* stream_context);
};

/***
 * Attempt to lock a stream for personal use. Does not block.
 * @param stream the stream to lock
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_stream_try_lock(struct Stream* stream);

/***
 * Attempt to lock a stream for personal use. Blocks until the lock is acquired
 * @param stream the stream to lock
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_stream_lock(struct Stream* stream);

/***
 * Attempt to unlock the mutex for this stream
 * @param stream the stream to unlock
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_stream_unlock(struct Stream* stream);
