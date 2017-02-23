#pragma once

/**
 * An interface in front of various streams
 */
struct Stream {
	/**
	 * A generic socket descriptor
	 */
	void* socket_descriptor;

	/**
	 * Reads from the stream
	 * @param stream the stream
	 * @param buffer where to put the results
	 * @param bytes_read how many bytes were read
	 * @returns true(1) on success, false(0) otherwise
	 */
	int (*read)(struct Stream* stream, unsigned char** buffer, size_t* bytes_read);

	/**
	 * Writes to a stream
	 * @param stream the stream
	 * @param buffer what to write
	 * @param how much to write
	 * @returns true(1) on success, false(0) otherwise
	 */
	int (*write)(struct Stream* stream, const unsigned char* buffer, size_t buffer_size);

	/**
	 * Closes a stream
	 * @param stream the stream
	 * @returns true(1) on success, otherwise false(0)
	 */
	int (*close)(struct Stream* stream);
};
