#pragma once

#include <pthread.h>
#include <stdint.h>

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
 * This is a context struct for a basic IP connection
 */
struct ConnectionContext {
	int socket_descriptor;
	struct SessionContext* session_context;
};


/**
 * An interface in front of various streams
 */
struct Stream {
	/**
	 * A generic socket descriptor
	 */
	struct MultiAddress* address; // helps identify who is on the other end
	pthread_mutex_t* socket_mutex; // only 1 transmission at a time
	struct Stream* parent_stream; // what stream wraps this stream
	/**
	 * A generic place to store implementation-specific context items
	 */
	void* stream_context;

	/**
	 * Reads from the stream
	 * @param stream the stream context (usually a SessionContext pointer)
	 * @param message where to put the incoming message (will be allocated)
	 * @param timeout_secs number of seconds before a timeout
	 * @returns true(1) on success, false(0) otherwise
	 */
	int (*read)(void* stream_context, struct StreamMessage** message, int timeout_secs);

	/**
	 * Reads a certain amount of bytes directly from the stream
	 * @param stream_context the context
	 * @param buffer where to put the results
	 * @param buffer_size the number of bytes to read
	 * @param timeout_secs number of seconds before a timeout
	 * @returns number of bytes read, or -1 on error
	 */
	int (*read_raw)(void* stream_context, uint8_t* buffer, int buffer_size, int timeout_secs);

	/**
	 * Writes to a stream
	 * @param stream the stream context (usually a SessionContext pointer)
	 * @param buffer what to write
	 * @returns true(1) on success, false(0) otherwise
	 */
	int (*write)(void* stream_context, struct StreamMessage* buffer);

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

struct Stream* libp2p_stream_new();

void libp2p_stream_free(struct Stream* stream);

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
