
/**
 * A raw network connection, that implements Stream
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include "libp2p/net/stream.h"
#include "libp2p/net/p2pnet.h"
#include "libp2p/utils/logger.h"
#include "multiaddr/multiaddr.h"

/**
 * Close a network connection
 * @param stream_context the ConnectionContext
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_net_connection_close(void* stream_context) {
	if (stream_context == NULL)
		return 0;
	struct ConnectionContext* ctx = (struct ConnectionContext*)stream_context;
	if (ctx != NULL) {
		if (ctx->socket_descriptor > 0) {
			close(ctx->socket_descriptor);
		}
		free(ctx);
		ctx = NULL;
		return 1;
	}
	// something went wrong
	return 0;
}

/***
 * Check and see if there is anything waiting on this network connection
 * @param stream_context the ConnectionContext
 * @returns number of bytes waiting, or -1 on error
 */
int libp2p_net_connection_peek(void* stream_context) {
	if (stream_context == NULL)
		return 0;
	struct ConnectionContext* ctx = (struct ConnectionContext*)stream_context;
	int socket_fd =  ctx->socket_descriptor;
	if (socket_fd < 0)
		return -1;

	int bytes = 0;
	int retVal = ioctl(socket_fd, FIONREAD, &bytes);
	if (retVal < 0) {
		// Ooff, we're having problems. Don't use this socket again.
		libp2p_logger_error("connectionstream", "Attempted a peek, but ioctl reported %s.\n", strerror(errno));
		return -1;
	}
	return bytes;
}

/**
 * Read from the network
 * @param stream_context the ConnectionContext
 * @param msg where to put the results
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_net_connection_read(void* stream_context, struct StreamMessage** msg, int timeout_secs) {
	return 0;
}

/**
 * Reads a certain amount of bytes directly from the stream
 * @param stream_context the context
 * @param buffer where to put the results
 * @param buffer_size the number of bytes to read
 * @param timeout_secs number of seconds before a timeout
 * @returns number of bytes read, or -1 on error
 */
int libp2p_net_connection_read_raw(void* stream_context, uint8_t* buffer, int buffer_size, int timeout_secs) {
	if (stream_context == NULL)
		return -1;
	struct ConnectionContext* ctx = (struct ConnectionContext*) stream_context;
	int num_read = 0;
	for(int i = 0; i < buffer_size; i++) {
		int retVal = socket_read(ctx->socket_descriptor, (char*)&buffer[i], 1, 0, timeout_secs);
		if (retVal < 1) { // get out of the loop
			if (retVal < 0) // error
				return -1;
			break;
		}
		num_read += retVal; // Everything ok, loop again (possibly)
	}
	return num_read;
}

/**
 * Writes to a stream
 * @param stream the stream context (usually a SessionContext pointer)
 * @param buffer what to write
 * @returns number of bytes written
 */
int libp2p_net_connection_write(void* stream_context, struct StreamMessage* msg) {
	if (stream_context == NULL)
		return -1;
	struct ConnectionContext* ctx = (struct ConnectionContext*) stream_context;
	return socket_write(ctx->socket_descriptor, (char*)msg->data, msg->data_size, 0);
}

/***
 * Create a new stream based on a network connection
 * @param fd the handle to the network connection
 * @param ip the IP address of the connection
 * @param port the port of the connection
 * @returns a Stream
 */
struct Stream* libp2p_net_connection_new(int fd, char* ip, int port) {
	struct Stream* out = (struct Stream*) malloc(sizeof(struct Stream));
	if (out != NULL) {
		out->close = libp2p_net_connection_close;
		out->peek = libp2p_net_connection_peek;
		out->read = libp2p_net_connection_read;
		out->read_raw = libp2p_net_connection_read_raw;
		out->write = libp2p_net_connection_write;
		// Multiaddresss
		char str[strlen(ip) + 25];
		memset(str, 0, strlen(ip) + 16);
		sprintf(str, "/ip4/%s/tcp/%d", ip, port);
		out->address = multiaddress_new_from_string(str);
		out->parent_stream = NULL;
		// mutex
		out->socket_mutex = (pthread_mutex_t*) malloc(sizeof(pthread_mutex_t));
		pthread_mutex_init(out->socket_mutex, NULL);
		// context
		struct ConnectionContext* ctx = (struct ConnectionContext*) malloc(sizeof(struct ConnectionContext));
		if (ctx != NULL) {
			out->stream_context = ctx;
			ctx->socket_descriptor = fd;
			if (!socket_connect4_with_timeout(ctx->socket_descriptor, hostname_to_ip(ip), port, 10) == 0) {
				// unable to connect
				libp2p_stream_free(out);
				out = NULL;
			}
		}
	}
	return out;
}
