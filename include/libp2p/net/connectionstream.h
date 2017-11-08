#pragma once

#include "libp2p/net/stream.h"
#include "libp2p/conn/session.h"

/***
 * Create a new stream based on a network connection
 * @param fd the handle to the network connection
 * @param ip the IP address of the connection
 * @param port the port of the connection
 * @returns a Stream
 */
struct Stream* libp2p_net_connection_new(int fd, char* ip, int port, struct SessionContext* session_context);

/**
 * Attempt to upgrade the parent_stream to use the new stream by default
 * @param parent_stream the parent stream
 * @param new_stream the new stream
 * @returns true(1) on success, false(0) if not
 */
int libp2p_net_connection_upgrade(struct Stream* parent_stream, struct Stream* new_stream);

/**
 * Given a stream, find the SessionContext
 * NOTE: This is done by navigating to the root context, which should
 * be a ConnectionContext, then grabbing the SessionContext there.
 * @param stream the stream to use
 * @returns the SessionContext for this stream
 */
struct SessionContext* libp2p_net_connection_get_session_context(struct Stream* stream);

/***
 * These are put here to allow implementations of struct Stream
 * to use them. They should not be called by external code
 */


/**
 * Close a network connection
 * @param stream_context the ConnectionContext
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_net_connection_close(void* stream_context);

/***
 * Check and see if there is anything waiting on this network connection
 * @param stream_context the ConnectionContext
 * @returns number of bytes waiting, or -1 on error
 */
int libp2p_net_connection_peek(void* stream_context);

/**
 * Read from the network
 * @param stream_context the ConnectionContext
 * @param msg where to put the results
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_net_connection_read(void* stream_context, struct StreamMessage** msg, int timeout_secs);

/**
 * Reads a certain amount of bytes directly from the stream
 * @param stream_context the context
 * @param buffer where to put the results
 * @param buffer_size the number of bytes to read
 * @param timeout_secs number of seconds before a timeout
 * @returns number of bytes read, or -1 on error
 */
int libp2p_net_connection_read_raw(void* stream_context, uint8_t* buffer, int buffer_size, int timeout_secs);

/**
 * Writes to a stream
 * @param stream the stream context (usually a SessionContext pointer)
 * @param buffer what to write
 * @returns number of bytes written
 */
int libp2p_net_connection_write(void* stream_context, struct StreamMessage* msg);
