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
#include "libp2p/net/connectionstream.h"
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

// forward declarations
int libp2p_net_multistream_handle_message(const struct StreamMessage* msg, struct Stream* stream, void* protocol_context);


int libp2p_net_multistream_can_handle(const struct StreamMessage* msg) {
	if (msg == NULL || msg->data == NULL || msg->data_size == 0)
		return 0;
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

int libp2p_net_multistream_shutdown(void* protocol_context) {
	struct MultistreamContext* context = (struct MultistreamContext*) protocol_context;
	if (context != NULL) {
		free(context);
	}
	return 1;
}

/**
 * Close the connection and free memory
 * @param ctx the context
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_net_multistream_context_free(struct MultistreamContext* ctx) {
	struct Stream* parent_stream = ctx->stream->parent_stream;
	int retVal = parent_stream->close(parent_stream);
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
int libp2p_net_multistream_close(struct Stream* stream) {
	if (stream->stream_context == NULL) {
		return 0;
	}
	struct MultistreamContext* multistream_context = (struct MultistreamContext*)stream->stream_context;
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

	return parent_stream->peek(parent_stream->stream_context);
}

/**
 * Add the transmission size to the front of a StreamMessage.
 * NOTE: This is used internally by multistream. It is accessible to help
 * with testing.
 * @param incoming the incoming message
 * @returns a new StreamMessage, in the format of a MessageStream buffer
 */
struct StreamMessage* libp2p_net_multistream_prepare_to_send(struct StreamMessage* incoming) {
	struct StreamMessage* out = libp2p_stream_message_new();
	if (out != NULL) {
		unsigned char varint[12];
		size_t varint_size = 0;
		varint_encode(incoming->data_size, &varint[0], 12, &varint_size);
		out->data_size = varint_size + incoming->data_size;
		out->data = malloc(out->data_size);
		if (out->data == NULL) {
			libp2p_stream_message_free(out);
			return NULL;
		}
		memcpy(&out->data[0], varint, varint_size);
		memcpy(&out->data[varint_size], incoming->data, incoming->data_size);
	}
	return out;
}

/**
 * Write to an open multistream host
 * @param stream_context the session context
 * @param msg the data to send
 * @returns the number of bytes written
 */
int libp2p_net_multistream_write_without_check(void* stream_context, struct StreamMessage* incoming) {
	struct MultistreamContext* multistream_context = (struct MultistreamContext*) stream_context;
	struct Stream* parent_stream = multistream_context->stream->parent_stream;
	int num_bytes = 0;

	if (incoming->data_size > 0) { // only do this is if there is something to send
		struct StreamMessage* out = libp2p_net_multistream_prepare_to_send(incoming);
		// now ship it
		libp2p_logger_debug("multistream", "Attempting write %d bytes.\n", (int)out->data_size);
		num_bytes = parent_stream->write(parent_stream->stream_context, out);
		// subtract the varint if all went well
		if (num_bytes == out->data_size)
			num_bytes = incoming->data_size;
		libp2p_stream_message_free(out);
	}

	return num_bytes;
}

/***
 * Wait for multistream stream to become ready
 * @param session_context the session context to check
 * @param timeout_secs the number of seconds to wait for things to become ready
 * @returns true(1) if it becomes ready, false(0) otherwise
 */
int libp2p_net_multistream_ready(struct SessionContext* session_context, int timeout_secs) {
	int counter = 0;
	while (session_context->default_stream->stream_type != STREAM_TYPE_MULTISTREAM && counter <= timeout_secs) {
		counter++;
		sleep(1);
	}
	if (session_context->default_stream->stream_type == STREAM_TYPE_MULTISTREAM && counter < 5) {
		struct MultistreamContext* ctx = (struct MultistreamContext*)session_context->default_stream->stream_context;
		while (ctx->status != multistream_status_ack && counter <= timeout_secs) {
			counter++;
			sleep(1);
		}
		if (ctx->status == multistream_status_ack)
			return 1;
	}
	return 0;
}

/**
 * Write to an open multistream host
 * @param stream_context the session context
 * @param msg the data to send
 * @returns the number of bytes written
 */
int libp2p_net_multistream_write(void* stream_context, struct StreamMessage* incoming) {
	struct MultistreamContext* multistream_context = (struct MultistreamContext*) stream_context;

	if (multistream_context->status != multistream_status_ack) {
		libp2p_logger_error("multistream", "Attempt to write before protocol is completely set up.\n");
		return 0;
	}

	return libp2p_net_multistream_write_without_check(stream_context, incoming);
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
	memset(varint, 0, 12);
	size_t num_bytes_requested = 0;
	size_t varint_length = 0;
	for(int i = 0; i < 12; i++) {
		if (parent_stream->read_raw(parent_stream->stream_context, &varint[i], 1, timeout_secs) == -1) {
			libp2p_logger_debug("multistream", "read->read_raw returned false.\n");
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
		libp2p_logger_error("multistream", "read: Attempted allocation of stream message failed.\n");
		libp2p_stream_message_free(rslts);
		rslts = NULL;
	}
	// now get the data from the parent stream
	if (!parent_stream->read_raw(parent_stream->stream_context, rslts->data, rslts->data_size, timeout_secs)) {
		libp2p_logger_error("multistream", "read: Was supposed to read %d bytes, but read_raw returned false.\n", num_bytes_requested);
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
	// TODO: wire this back in
	//stream = libp2p_net_multistream_stream_new(socket, hostname, port, NULL);
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
 * Negotiate the multistream protocol by sending the protocol id. This is a server side function.
 * Servers should send the protocol ID, and then expect it back. Receiving the
 * protocol id back is the responsibility of a future read, not part of this function.
 * NOTE: the SessionContext should already contain the connected stream. If not, use
 * libp2p_net_multistream_connect instead of this method.
 *
 * @param ctx a MultistreamContext
 * @param theyRequested true(1) if the multistream ID has already been received from the client
 * @returns true(1) on success, or false(0)
 */
int libp2p_net_multistream_negotiate(struct MultistreamContext* ctx, int theyRequested) {
	const char* protocolID = "/multistream/1.0.0\n";
	struct StreamMessage outgoing;
	struct StreamMessage* results = NULL;
	int retVal = 0;
	//int haveTheirs = 0;
	//int peek_result = 0;

	/*
	if (!theyRequested) {
		// see if they're trying to send something first
		peek_result = libp2p_net_multistream_peek(ctx);
		if (peek_result > 0) {
			libp2p_logger_debug("multistream", "negotiate: There is %d bytes waiting for us. Perhaps it is the multistream header we're expecting.\n", peek_result);
			// get the protocol
			libp2p_net_multistream_read(ctx, &results, multistream_default_timeout);
			if (results == NULL || results->data_size == 0) {
				libp2p_logger_debug("multistream", "negotiate: We tried to read the %d bytes, but got nothing.\n", peek_result);
				goto exit;
			}
			if (strncmp((char*)results->data, protocolID, strlen(protocolID)) != 0) {
				libp2p_logger_debug("multistream", "negotiate: We expected the multistream id, but got %s.\n", results->data);
				goto exit;
			}
			libp2p_logger_debug("multistream", "negotiate: We read %d bytes from the network, and received the multistream id.\n", results->data_size);
			haveTheirs = 1;
		}
	}
	*/
	// send the protocol id
	outgoing.data = (uint8_t*)protocolID;
	outgoing.data_size = strlen(protocolID);
	if (!libp2p_net_multistream_write_without_check(ctx, &outgoing)) {
		libp2p_logger_debug("multistream", "negotiate: Attempted to send the multistream id, but the write failed.\n");
		goto exit;
	}

	// update the status
	if (theyRequested) {
		ctx->status = multistream_status_ack;
	} else {
		ctx->status = multistream_status_syn;
	}

	/*
	// wait for them to send the protocol id back
	if (!theyRequested && !haveTheirs) {
		libp2p_logger_debug("multistream", "negotiate: Wrote multistream id to network, awaiting reply...\n");
		// expect the same back
		int retVal = libp2p_net_multistream_read(ctx, &results, multistream_default_timeout);
		if (retVal == 0 || results == NULL || results->data_size == 0) {
			libp2p_logger_debug("multistream", "negotiate: expected the multistream id back, but got nothing. RetVal: %d.\n", retVal);
			goto exit;
		}
		if (strncmp((char*)results->data, protocolID, strlen(protocolID)) != 0) {
			libp2p_logger_debug("multistream", "negotiate: Expected the multistream id back, but did not receive it. We did receive %d bytes though.\n)", results->data_size);
			goto exit;
		}
	}
	*/

	retVal = 1;
	exit:
	if (results != NULL)
		free(results);
	return retVal;
}

void libp2p_net_multistream_stream_free(struct Stream* stream) {
	if (stream != NULL) {
		stream->parent_stream->close(stream->parent_stream);
		// TODO: free memory allocations
	}
}

int libp2p_net_multistream_read_raw(void* stream_context, uint8_t* buffer, int buffer_len, int timeout_secs) {
	if (stream_context == NULL)
		return 0;
	struct MultistreamContext* ctx = (struct MultistreamContext*) stream_context;
	return ctx->stream->parent_stream->read_raw(ctx->stream->parent_stream->stream_context, buffer, buffer_len, timeout_secs);
}

/**
 * We want to try and negotiate Multistream on the incoming stream
 */
struct Stream* libp2p_net_multistream_handshake(struct Stream* stream) {
	//TODO: implement this method
	return NULL;
}

/***
 * The protocol above is asking for an upgrade
 * @param multistream this stream (a multistream)
 * @param new_stream the protocol above
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_net_multistream_handle_upgrade(struct Stream* multistream, struct Stream* new_stream) {
	// take multistream out of the picture
	if (new_stream->parent_stream == multistream) {
		new_stream->parent_stream = multistream->parent_stream;
		multistream->parent_stream->handle_upgrade(multistream->parent_stream, new_stream);
	}
	return 1;
}

/**
 * Create a new MultiStream structure
 * @param parent_stream the stream
 * @param they_requested true(1) if they requested it (i.e. protocol id has already been sent)
 * @returns the new Stream
 */
struct Stream* libp2p_net_multistream_stream_new(struct Stream* parent_stream, int theyRequested) {
	struct Stream* out = (struct Stream*)malloc(sizeof(struct Stream));
	if (out != NULL) {
		out->stream_type = STREAM_TYPE_MULTISTREAM;
		out->parent_stream = parent_stream;
		out->close = libp2p_net_multistream_close;
		out->read = libp2p_net_multistream_read;
		out->write = libp2p_net_multistream_write;
		out->peek = libp2p_net_multistream_peek;
		out->read_raw = libp2p_net_multistream_read_raw;
		out->negotiate = libp2p_net_multistream_handshake;
		out->handle_upgrade = libp2p_net_multistream_handle_upgrade;
		out->address = parent_stream->address;
		out->socket_mutex = parent_stream->socket_mutex;
		out->handle_message = libp2p_net_multistream_handle_message;
		// build MultistreamContext
		struct MultistreamContext* ctx = (struct MultistreamContext*) malloc(sizeof(struct MultistreamContext));
		if (ctx == NULL) {
			libp2p_net_multistream_stream_free(out);
			return NULL;
		}
		ctx->status = multistream_status_initialized;
		out->stream_context = ctx;
		ctx->stream = out;
		ctx->handlers = NULL;
		ctx->session_context = NULL;
		// attempt to negotiate multistream protocol
		if (!libp2p_net_multistream_negotiate(ctx, theyRequested)) {
			libp2p_logger_debug("multistream", "multistream_stream_new: negotiate failed\n");
			libp2p_net_multistream_stream_free(out);
			return NULL;
		}
		if (!theyRequested) {
			int timeout = 5;
			int counter = 0;
			// wait for the response
			while(ctx->status != multistream_status_ack && counter < timeout) {
				sleep(1);
				counter++;
			}
		}
	}
	return out;
}

/***
 * The remote is attempting to negotiate the multistream protocol
 * @param msg incoming message
 * @param stream the incoming stream
 * @param protocol_context the context for the Multistream protocol (not stream specific)
 * @returns <0 on error, 0 for the caller to stop handling this, 1 for success
 */
int libp2p_net_multistream_handle_message(const struct StreamMessage* msg, struct Stream* stream, void* protocol_context) {
	if (stream->stream_type == STREAM_TYPE_MULTISTREAM) {
		// we sent a multistream, and this is them responding
		struct MultistreamContext* ctx = (struct MultistreamContext*) stream->stream_context;
		if (ctx->status == multistream_status_ack) {
			// uh oh, this stream is already set up. error
			return -1;
		} else {
			ctx->status = multistream_status_ack;
		}
		return 1;
	}
	// the incoming stream is not a multistream. They are attempting to upgrade to multistream
	struct Stream* new_stream = libp2p_net_multistream_stream_new(stream, 1);
	if (new_stream != NULL) {
		struct MultistreamContext* ctx = (struct MultistreamContext*)stream->stream_context;
		ctx->status = multistream_status_ack;
		// upgrade
		return stream->handle_upgrade(stream, new_stream);
	}
	return -1;
}

/***
 * The handler to handle calls to the protocol
 * @param handler_vector a Libp2pVector of protocol handlers
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

