#pragma once

/**
 * An interface in front of various streams
 */
struct Stream {
	/**
	 * A generic socket descriptor
	 */
	void* socket_descriptor;
	struct MultiAddress *address;

	/**
	 * Reads from the stream
	 * @param stream the stream context (usually a SessionContext pointer)
	 * @param buffer where to put the results
	 * @param bytes_read how many bytes were read
	 * @returns true(1) on success, false(0) otherwise
	 */
	int (*read)(void* stream_context, unsigned char** buffer, size_t* bytes_read);

	/**
	 * Writes to a stream
	 * @param stream the stream context
	 * @param buffer what to write
	 * @param how much to write
	 * @returns true(1) on success, false(0) otherwise
	 */
	int (*write)(void* stream_context, const unsigned char* buffer, size_t buffer_size);

	/**
	 * Closes a stream
	 * @param stream the stream context
	 * @returns true(1) on success, otherwise false(0)
	 */
	int (*close)(void* stream_context);
};
