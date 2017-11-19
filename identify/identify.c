#include <string.h>

#include "varint.h"
#include "libp2p/net/protocol.h"
#include "libp2p/net/protocol.h"
#include "libp2p/net/multistream.h"
#include "libp2p/utils/vector.h"
#include "libp2p/net/stream.h"
#include "libp2p/conn/session.h"
#include "libp2p/identify/identify.h"
#include "libp2p/utils/logger.h"

/**
 * Determines if this protocol can handle the incoming message
 * @param incoming the incoming data
 * @param incoming_size the size of the incoming data buffer
 * @returns true(1) if it can handle this message, false(0) if not
 */
int libp2p_identify_can_handle(const struct StreamMessage* msg) {
	const char *protocol = "/ipfs/id/1.0.0\n";
	int protocol_size = strlen(protocol);
	// is there a varint in front?
	size_t num_bytes = 0;
	if (msg->data[0] != protocol[0] && msg->data[1] != protocol[1]) {
		varint_decode(msg->data, msg->data_size, &num_bytes);
	}
	if (msg->data_size >= protocol_size - num_bytes) {
		if (strncmp(protocol, (char*) &msg->data[num_bytes], protocol_size) == 0)
			return 1;
	}
	return 0;
}

/***
 * Send the identify header out the default stream
 * @param context the context
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_identify_send_protocol(struct Stream *stream) {
	char *protocol = "/ipfs/id/1.0.0\n";
	struct StreamMessage msg;
	msg.data = (uint8_t*) protocol;
	msg.data_size = strlen(protocol);
	if (!stream->write(stream->stream_context, &msg)) {
		libp2p_logger_error("identify", "send_protocol: Unable to send identify protocol header.\n");
		return 0;
	}
	return 1;
}

/***
 * Check to see if the reply is the identify header we expect
 * NOTE: if we initiate the connection, we should expect the same back
 * @param stream the incoming stream of the underlying protocol
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_identify_receive_protocol(struct Stream* stream) {
	const char *protocol = "/ipfs/id/1.0.0\n";
	struct StreamMessage* results = NULL;
	if (!stream->read(stream->stream_context, &results, 30)) {
		libp2p_logger_error("identify", "receive_protocol: Unable to read results.\n");
		return 0;
	}
	// the first byte may be the size, so skip it
	int start = 0;
	if (results->data[0] != '/')
		start = 1;
	char* ptr = strstr((char*)&results->data[start], protocol);
	if (ptr == NULL || ptr - (char*)&results->data[start] > 1) {
		libp2p_stream_message_free(results);
		return 0;
	}
	libp2p_stream_message_free(results);
	return 1;
}

/**
 * A remote node is attempting to send us an Identify message
 * @param msg the message sent
 * @param context the SessionContext
 * @param protocol_context the identify protocol context
 * @returns <0 on error, 0 if loop should not continue, >0 on success
 */
int libp2p_identify_handle_message(const struct StreamMessage* msg, struct Stream* stream, void* protocol_context) {
	// attempt to create a new Identify connection with them.
	// send the protocol id back, and set up the channel
	struct Stream* new_stream = libp2p_identify_stream_new(stream);
	if (new_stream == NULL)
		return -1;
	return stream->handle_upgrade(stream, new_stream);
}

/**
 * Shutting down. Clean up any memory allocations
 * @param protocol_context the context
 * @returns true(1)
 */
int libp2p_identify_shutdown(void* protocol_context) {
	if (protocol_context == NULL)
		return 0;
	free(protocol_context);
	return 1;
}

struct Libp2pProtocolHandler* libp2p_identify_build_protocol_handler(struct Libp2pVector* handlers) {
	struct Libp2pProtocolHandler* handler = libp2p_protocol_handler_new();
	if (handler != NULL) {
		handler->context = handler;
		handler->CanHandle = libp2p_identify_can_handle;
		handler->HandleMessage = libp2p_identify_handle_message;
		handler->Shutdown = libp2p_identify_shutdown;
	}
	return handler;
}

int libp2p_identify_close(struct Stream* stream) {
	if (stream == NULL)
		return 0;
	if (stream->parent_stream != NULL)
		stream->parent_stream->close(stream->parent_stream);
	if (stream->stream_context != NULL)
		free(stream->stream_context);
	libp2p_stream_free(stream);
	return 1;
}

/***
 * Create a new stream that negotiates the identify protocol
 *
 * NOTE: This will be sent by our side (us asking them).
 * Incoming "Identify" requests should be handled by the
 * external protocol handler, not this function.
 *
 * @param parent_stream the parent stream
 * @returns a new Stream that can talk "identify"
 */
struct Stream* libp2p_identify_stream_new(struct Stream* parent_stream) {
	if (parent_stream == NULL)
		return NULL;
	struct Stream* out = libp2p_stream_new();
	if (out != NULL) {
		out->parent_stream = parent_stream;
		struct IdentifyContext* ctx = (struct IdentifyContext*) malloc(sizeof(struct IdentifyContext));
		if (ctx == NULL) {
			libp2p_stream_free(out);
			return NULL;
		}
		ctx->parent_stream = parent_stream;
		ctx->stream = out;
		out->stream_context = ctx;
		out->close = libp2p_identify_close;
		out->negotiate = libp2p_identify_stream_new;
		if (!libp2p_identify_send_protocol(parent_stream) || !libp2p_identify_receive_protocol(parent_stream)) {
			libp2p_stream_free(out);
			free(ctx);
			return NULL;
		}
	}
	return out;
}

/***
 * Create a new stream that negotiates the identify protocol
 * on top of the multistream protocol
 *
 * NOTE: This will be sent by our side (us asking them).
 * Incoming "Identify" requests should be handled by the
 * external protocol handler, not this function.
 *
 * @param parent_stream the parent stream
 * @returns a new Stream that is a multistream, but with "identify" already negotiated
 */
struct Stream* libp2p_identify_stream_new_with_multistream(struct Stream* parent_stream) {
	if (parent_stream == NULL)
		return NULL;
	struct Stream* multistream = libp2p_net_multistream_stream_new(parent_stream);
	struct Stream* out = libp2p_stream_new();
	if (out != NULL) {
		out->stream_type = STREAM_TYPE_IDENTIFY;
		out->parent_stream = multistream;
		struct IdentifyContext* ctx = (struct IdentifyContext*) malloc(sizeof(struct IdentifyContext));
		if (ctx == NULL) {
			libp2p_stream_free(out);
			return NULL;
		}
		ctx->parent_stream = multistream;
		ctx->stream = out;
		out->stream_context = ctx;
		out->close = libp2p_identify_close;
		out->negotiate = libp2p_identify_stream_new_with_multistream;
		if (!libp2p_identify_send_protocol(parent_stream) || !libp2p_identify_receive_protocol(parent_stream)) {
			libp2p_stream_free(out);
			free(ctx);
			return NULL;
		}
	}
	return out;
}
