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

/***
 * Make a copy of a message
 * @param original the original message
 * @returns a StreamMessage that is a copy of the original
 */
struct StreamMessage* libp2p_stream_message_copy(const struct StreamMessage* original);

/**
 * This is a context struct for a basic IP connection
 */
struct ConnectionContext {
	int socket_descriptor;
	unsigned long long last_comm_epoch;
	struct SessionContext* session_context;
};

/**
 * The different types of protocols
 */
enum stream_type {
	STREAM_TYPE_UNKNOWN = 0x0,
	STREAM_TYPE_MULTISTREAM = 0x1,
	STREAM_TYPE_SECIO = 0x2,
	STREAM_TYPE_KADEMLIA = 0x3,
	STREAM_TYPE_IDENTIFY = 0x4,
	STREAM_TYPE_YAMUX = 0x5,
	STREAM_TYPE_JOURNAL = 0x6,
	STREAM_TYPE_RAW = 0x7
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
	int channel; // the channel (for multiplexing streams)
	enum stream_type stream_type;

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
	 * @param stream the stream
	 * @returns true(1) on success, otherwise false(0)
	 */
	int (*close)(struct Stream* stream);

	/***
	 * Checks to see if something is waiting on the stream
	 *
	 * @param stream the stream context
	 * @returns true(1) if something is waiting, false(0) if not, -1 on error
	 */
	int (*peek)(void* stream_context);

	/**
	 * Handle a stream upgrade
	 * @param stream the current stream
	 * @param new_stream the newly created stream
	 */
	int (*handle_upgrade)(struct Stream* stream, struct Stream* new_stream);

	/***
	 * Negotiate this protocol using the parent stream
	 * @param parent_stream the connection to use
	 * @returns a new Stream, or NULL on error
	 */
	struct Stream* (*negotiate)(struct Stream* parent_stream);

	/****
	 * A message has been received, and needs to be handled
	 * @param message the message received
	 * @param stream where the message came from
	 * @param protocol_context the context for the protocol
	 * @returns < 0 on error, 0 if no further processing needs to be done, or 1 for success
	 */
	int (*handle_message)(const struct StreamMessage* message, struct Stream* stream, void* protocol_context);
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
