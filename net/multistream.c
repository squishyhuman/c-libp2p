#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include "libp2p/os/utils.h"
#include "libp2p/net/p2pnet.h"
#include "libp2p/record/message.h"
#include "libp2p/secio/secio.h"
#include "varint.h"
#include "libp2p/net/multistream.h"
#include "libp2p/utils/logger.h"
#include "multiaddr/multiaddr.h"

// NOTE: this is normally set to 5 seconds, but you may want to increase this during debugging
int multistream_default_timeout = 5;

/***
 * An implementation of the libp2p multistream
 */

int libp2p_net_multistream_can_handle(const struct StreamMessage* msg) {
	char *protocol = "/multistream/1.0.0\n";
	int protocol_size = strlen(protocol);
	unsigned char* incoming = msg->data;
	size_t incoming_size = msg->data_size;
	// is there a varint in front?
	size_t num_bytes = 0;
	if (incoming[0] != '/' && incoming[1] != 'm') {
		varint_decode(incoming, incoming_size, &num_bytes);
	}
	if (incoming_size >= protocol_size - num_bytes) {
		if (strncmp(protocol, (char*) &incoming[num_bytes], protocol_size) == 0)
			return 1;
	}
	return 0;
}

/***
 * Send the multistream header out the default stream
 * @param context the context
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_net_multistream_send_protocol(struct SessionContext *context) {
	const char* protocol = "/multistream/1.0.0\n";
	struct StreamMessage msg;
	msg.data = (uint8_t*) protocol;
	msg.data_size = strlen(protocol);
	if (!context->default_stream->write(context, &msg)) {
		libp2p_logger_error("multistream", "send_protocol: Unable to send multistream protocol header.\n");
		return 0;
	}
	return 1;
}

/***
 * Check to see if the reply is the multistream protocol header we expect
 * NOTE: if we initiate the connection, we should expect the same back
 * @param context the SessionContext
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_net_multistream_receive_protocol(struct SessionContext* context) {
	char* protocol = "/multistream/1.0.0\n";
	struct StreamMessage* results = NULL;
	if (!context->default_stream->read(context, &results, 30)) {
		libp2p_logger_error("multistream", "receive_protocol: Unable to read results.\n");
		return 0;
	}
	// the first byte is the size, so skip it
	char* ptr = strstr((char*)&results[1], protocol);
	if (ptr == NULL || ptr - (char*)results > 1) {
		return 0;
	}
	return 1;
}

int libp2p_net_multistream_handle_message(const struct StreamMessage* msg, struct SessionContext* context, void* protocol_context) {
	// try sending the protocol back
	//if (!libp2p_net_multistream_send_protocol(context))
	//	return -1;

	struct MultistreamContext* multistream_context = (struct MultistreamContext*) protocol_context;

    // try to read from the network
	struct StreamMessage* results = NULL;
    int retVal = 0;
    int max_retries = 10;
    int numRetries = 0;
    // handle the call
   	for(;;) {
   		// try to read for 5 seconds
   	    if (context->default_stream->read(context, &results, 5)) {
   	    	// we read something from the network. Process it.
   	    	// NOTE: If it is a multistream protocol that we are receiving, ignore it.
   	    	if (libp2p_net_multistream_can_handle(results))
   	    		continue;
   	    	numRetries = 0;
   	   	retVal = libp2p_protocol_marshal(results, context, multistream_context->handlers);
   	   	if (results != NULL)
   	   		free(results);
   	   	// exit the loop on error (or if they ask us to no longer loop by returning 0)
   	   	if (retVal <= 0)
   	   		break;
   	    } else {
   	    		// we were unable to read from the network.
   	   	    // if it timed out, we should try again (if we're not out of retries)
   	    		if (numRetries >= max_retries)
   	    			break;
   	    		numRetries++;
   	    }
   	}

	return retVal;
}

int libp2p_net_multistream_shutdown(void* protocol_context) {
	struct MultistreamContext* context = (struct MultistreamContext*) protocol_context;
	if (context != NULL) {
		free(context);
	}
	return 1;
}

/***
 * The handler to handle calls to the protocol
 * @param stream_context the context
 * @returns the protocol handler
 */
struct Libp2pProtocolHandler* libp2p_net_multistream_build_protocol_handler(void* handler_vector) {

	// build the context
	struct MultistreamContext* context = (struct MultistreamContext*) malloc(sizeof(struct MultistreamContext));
	if (context == NULL)
		return NULL;
	context->handlers = (struct Libp2pVector*) handler_vector;

	// build the handler
	struct Libp2pProtocolHandler *handler = libp2p_protocol_handler_new();
	if (handler != NULL) {
		handler->context = context;
		handler->CanHandle = libp2p_net_multistream_can_handle;
		handler->HandleMessage = libp2p_net_multistream_handle_message;
		handler->Shutdown = libp2p_net_multistream_shutdown;
	}
	return handler;
}

/**
 * Close the connection and free memory
 * @param ctx the context
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_net_multistream_context_free(struct MultistreamContext* ctx) {
	int retVal = ctx->stream->close(ctx);
	// regardless of retVal, free the context
	// TODO: Evaluate if this is the correct way to do it:
	free(ctx);
	return retVal;
}

/***
 * Close the Multistream interface
 * NOTE: This also closes the socket
 * @param stream_context a SessionContext
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_net_multistream_close(void* stream_context) {
	if (stream_context == NULL) {
		return 0;
	}
	struct MultistreamContext* multistream_context = (struct MultistreamContext*)stream_context;
	return libp2p_net_multistream_context_free(multistream_context);
}

/***
 * Check the stream to see if there is something to read
 * @param stream_context a MultistreamContext
 * @returns number of bytes to be read, or -1 if there was an error
 */
int libp2p_net_multistream_peek(void* stream_context) {
	if (stream_context == NULL)
		return -1;

	struct MultistreamContext* multistream_context = (struct MultistreamContext*)stream_context;
	struct Stream* parent_stream = multistream_context->stream->parent_stream;
	if (parent_stream == NULL)
		return -1;

	return parent_stream->peek(parent_stream);
}

/**
 * Write to an open multistream host
 * @param stream_context the session context
 * @param msg the data to send
 * @returns the number of bytes written
 */
int libp2p_net_multistream_write(void* stream_context, struct StreamMessage* incoming) {
	struct MultistreamContext* multistream_context = (struct MultistreamContext*) stream_context;
	struct Stream* parent_stream = multistream_context->stream->parent_stream;
	int num_bytes = 0;

	if (incoming->data_size > 0) { // only do this is if there is something to send
		// first get the size as a varint
		unsigned char varint[12];
		size_t varint_size = 0;
		varint_encode(incoming->data_size, &varint[0], 12, &varint_size);
		// now put the size with the data
		struct StreamMessage outgoing;
		outgoing.data = (uint8_t*) malloc(varint_size + incoming->data_size);
		if (outgoing.data == NULL) {
			return 0;
		}
		memset(outgoing.data, 0, incoming->data_size + varint_size);
		memcpy(outgoing.data, varint, varint_size);
		memcpy(&outgoing.data[varint_size], incoming->data, incoming->data_size);
		// now ship it
		num_bytes = parent_stream->write(parent_stream, &outgoing);
		if (num_bytes > 0) {
			// update the last time we communicated
			multistream_context->session_context->last_comm_epoch = os_utils_gmtime();
		}
		free(outgoing.data);
	}

	return num_bytes;
}

/**
 * Read from a multistream socket
 * @param socket_fd the socket file descriptor
 * @param results where to put the results. NOTE: this memory is allocated
 * @param results_size the size of the results in bytes
 * @param timeout_secs the seconds before a timeout
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_net_multistream_read(void* stream_context, struct StreamMessage** results, int timeout_secs) {
	struct MultistreamContext* multistream_context = (struct MultistreamContext*)stream_context;
	struct Stream* parent_stream = multistream_context->stream->parent_stream;

	// find out the length
	uint8_t varint[12];
	size_t num_bytes_requested = 0;
	size_t varint_length = 0;
	for(int i = 0; i < 12; i++) {
		if (!parent_stream->read_raw(parent_stream->stream_context, &varint[i], 1, timeout_secs)) {
			return 0;
		}
		if (varint[i] >> 7 == 0) {
			num_bytes_requested = varint_decode(&varint[0], i+1, &varint_length);
			break;
		}
	}

	if (num_bytes_requested <= 0)
		return 0;

	// now get the data
	*results = libp2p_stream_message_new();
	struct StreamMessage* rslts = *results;
	rslts->data_size = num_bytes_requested;
	rslts->data = (uint8_t*) malloc(num_bytes_requested);
	if (rslts->data == NULL) {
		libp2p_stream_message_free(rslts);
		rslts = NULL;
	}
	// now get the data from the parent stream
	if (!parent_stream->read_raw(parent_stream->stream_context, rslts->data, rslts->data_size, timeout_secs)) {
		// problem reading from the parent stream
		libp2p_stream_message_free(*results);
		*results = NULL;
		return 0;
	}

	return 1;
}


/**
 * Connect to a multistream host, and this includes the multistream handshaking.
 * @param hostname the host
 * @param port the port
 * @returns the socket file descriptor of the connection, or -1 on error
 */
struct Stream* libp2p_net_multistream_connect(const char* hostname, int port) {
	return libp2p_net_multistream_connect_with_timeout(hostname, port, multistream_default_timeout);
}

/**
 * Connect to a multistream host, and this includes the multistream handshaking.
 * @param hostname the host
 * @param port the port
 * @param timeout_secs number of secs before timeout
 * @returns the socket file descriptor of the connection, or -1 on error
 */
struct Stream* libp2p_net_multistream_connect_with_timeout(const char* hostname, int port, int timeout_secs) {
	int retVal = -1, return_result = -1, socket = -1;
	struct StreamMessage* results = NULL;
	struct Stream* stream = NULL;

	uint32_t ip = hostname_to_ip(hostname);
	socket = socket_open4();

	// connect
	if (socket_connect4_with_timeout(socket, ip, port, timeout_secs) != 0)
		goto exit;

	// send the multistream handshake
	stream = libp2p_net_multistream_stream_new(socket, hostname, port);
	if (stream == NULL)
		goto exit;

	struct SessionContext session;
	session.insecure_stream = stream;
	session.secure_stream = NULL;
	session.default_stream = stream;

	// try to receive the protocol id
	return_result = libp2p_net_multistream_read(&session, &results, timeout_secs);
	if (results == NULL || return_result == 0 || results->data_size < 1 || !libp2p_net_multistream_can_handle(results)) {
		libp2p_logger_error("multistream", "Attempted to receive the multistream protocol header, but received %s.\n", results);
		goto exit;
	}

	if (!libp2p_net_multistream_send_protocol(&session)) {
		libp2p_logger_error("multistream", "Attempted to send the multistream protocol header, but could not.\n");
		goto exit;
	}

	// we are now in the loop, so we can switch to another protocol (i.e. /secio/1.0.0)

	retVal = socket;
	exit:
	if (results != NULL)
		free(results);
	if (retVal < 0 && stream != NULL) {
		libp2p_net_multistream_stream_free(stream);
		stream = NULL;
	}
	if (retVal < 0 && socket > 0)
		close(socket);
	return stream;
}

/**
 * Negotiate the multistream protocol by sending and receiving the protocol id. This is a server side function.
 * Servers should send the protocol ID, and then expect it back.
 * NOTE: the SessionContext should already contain the connected stream. If not, use
 * libp2p_net_multistream_connect instead of this method.
 *
 * @param session the struct Session, which contains all the context info
 * @returns true(1) on success, or false(0)
 */
int libp2p_net_multistream_negotiate(struct SessionContext* session) {
	const char* protocolID = "/multistream/1.0.0\n";
	struct StreamMessage outgoing;
	struct StreamMessage* results = NULL;
	int retVal = 0;
	// send the protocol id
	outgoing.data = (uint8_t*)protocolID;
	outgoing.data_size = strlen(protocolID);
	if (!libp2p_net_multistream_write(session, &outgoing))
		goto exit;
	// expect the same back
	libp2p_net_multistream_read(session, &results, multistream_default_timeout);
	if (results == NULL || results->data_size == 0)
		goto exit;
	if (strncmp((char*)results, protocolID, strlen(protocolID)) != 0)
		goto exit;
	retVal = 1;
	exit:
	if (results != NULL)
		free(results);
	return retVal;
}

void libp2p_net_multistream_stream_free(struct Stream* stream) {
	if (stream != NULL) {
		stream->parent_stream->close(stream->parent_stream->stream_context);
		// TODO: free memory allocations
	}
}

/**
 * Create a new MultiStream structure
 * @param socket_fd the file descriptor
 * @param ip the IP address
 * @param port the port
 */
struct Stream* libp2p_net_multistream_stream_new(int socket_fd, const char* ip, int port) {
	struct Stream* out = (struct Stream*)malloc(sizeof(struct Stream));
	if (out != NULL) {
		out->parent_stream = NULL;
		out->close = libp2p_net_multistream_close;
		out->read = libp2p_net_multistream_read;
		out->write = libp2p_net_multistream_write;
		out->peek = libp2p_net_multistream_peek;
		char str[strlen(ip) + 50];
		sprintf(str, "/ip4/%s/tcp/%d", ip, port);
		out->address = multiaddress_new_from_string(str);
	}
	return out;
}

