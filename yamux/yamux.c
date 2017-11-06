#include <string.h>
#include <unistd.h>
#include "varint.h"
#include "libp2p/yamux/session.h"
#include "libp2p/yamux/yamux.h"
#include "libp2p/net/protocol.h"
#include "libp2p/net/stream.h"
#include "libp2p/conn/session.h"
#include "libp2p/utils/logger.h"

/**
 * Determines if this protocol can handle the incoming message
 * @param incoming the incoming data
 * @param incoming_size the size of the incoming data buffer
 * @returns true(1) if it can handle this message, false(0) if not
 */
int yamux_can_handle(const struct StreamMessage* msg) {
	char *protocol = "/yamux/1.0.0\n";
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

/**
 * the yamux stream received some bytes. Process them
 * @param stream the stream that the data came in on
 * @param msg the message
 * @param incoming the stream buffer
 */
/*
void yamux_read_stream(struct yamux_stream* stream, struct StreamMessage* msg) {
	struct Libp2pVector* handlers = stream->userdata;
	int retVal = libp2p_protocol_marshal(msg, stream->session->session_context, handlers);
	if (retVal == -1) {
		// TODO handle error condition
		libp2p_logger_error("yamux", "Marshalling returned error.\n");
	} else if (retVal > 0) {
		// TODO handle everything went okay
		libp2p_logger_debug("yamux", "Marshalling was successful. We should continue processing.\n");
	} else {
		// TODO we've been told we shouldn't do anything anymore
		libp2p_logger_debug("yamux", "Marshalling was successful. We should stop processing.\n");
	}
	return;
}
*/

/***
 * Send the yamux protocol out the default stream
 * NOTE: if we initiate the connection, we should expect the same back
 * @param context the SessionContext
 * @returns true(1) on success, false(0) otherwise
 */
int yamux_send_protocol(struct SessionContext* context) {
	char* protocol = "/yamux/1.0.0\n";
	struct StreamMessage outgoing;
	outgoing.data = (uint8_t*)protocol;
	outgoing.data_size = strlen(protocol);
	if (!context->default_stream->write(context, &outgoing))
		return 0;
	return 1;
}

/***
 * Check to see if the reply is the yamux protocol header we expect
 * NOTE: if we initiate the connection, we should expect the same back
 * @param context the SessionContext
 * @returns true(1) on success, false(0) otherwise
 */
int yamux_receive_protocol(struct SessionContext* context) {
	char* protocol = "/yamux/1.0.0\n";
	struct StreamMessage* results = NULL;
	int retVal = 0;

	if (!context->default_stream->read(context, &results, 30)) {
		libp2p_logger_error("yamux", "receive_protocol: Unable to read results.\n");
		goto exit;
	}
	// the first byte is the size, so skip it
	char* ptr = strstr((char*)&results->data[1], protocol);
	if (ptr == NULL || ptr - (char*)results->data > 1) {
		goto exit;
	}
	retVal = 1;
	exit:
	libp2p_stream_message_free(results);
	return retVal;
}

/***
 * The remote is attempting to negotiate yamux
 * @param msg the incoming message
 * @param incoming_size the size of the incoming data buffer
 * @param session_context the information about the incoming connection
 * @param protocol_context the protocol-dependent context
 * @returns 0 if the caller should not continue looping, <0 on error, >0 on success
 */
int yamux_handle_message(const struct StreamMessage* msg, struct SessionContext* session_context, void* protocol_context) {
	struct yamux_session* yamux = yamux_session_new(NULL, session_context->default_stream, yamux_session_server, protocol_context);
	uint8_t* buf = (uint8_t*) malloc(msg->data_size);
	if (buf == NULL)
		return -1;
	memcpy(buf, msg->data, msg->data_size);
	for(;;) {
		int retVal = yamux_decode(yamux, msg->data, msg->data_size);
		free(buf);
		buf = NULL;
		if (!retVal)
			break;
		else { // try to read more from this stream
			// TODO need more information as to what this loop should do
		}
	}

	return 1;
}

/**
 * Shutting down. Clean up any memory allocations
 * @param protocol_context the context
 * @returns true(1)
 */
int yamux_shutdown(void* protocol_context) {
	return 0;
}

struct Libp2pProtocolHandler* yamux_build_protocol_handler(struct Libp2pVector* handlers) {
	struct Libp2pProtocolHandler* handler = libp2p_protocol_handler_new();
	if (handler != NULL) {
		handler->context = handlers;
		handler->CanHandle = yamux_can_handle;
		handler->HandleMessage = yamux_handle_message;
		handler->Shutdown = yamux_shutdown;
	}
	return handler;
}

int libp2p_yamux_close(void* stream_context) {
	if (stream_context == NULL)
		return 0;
	struct YamuxContext* ctx = (struct YamuxContext*)stream_context;
	libp2p_yamux_stream_free(ctx->stream);
	return 0;
}

/**
 * Read from the network, expecting a yamux frame.
 * NOTE: This will also dispatch the frame to the correct protocol
 * @param stream_context the YamuxContext
 * @param message the resultant message
 * @param timeout_secs when to give up
 * @returns true(1) on success, false(0) on failure
 */
int libp2p_yamux_read(void* stream_context, struct StreamMessage** message, int timeout_secs) {
	if (stream_context == NULL)
		return 0;
	// look at the first byte of the context to determine if this is a YamuxContext (we're negotiating)
	// or a YamuxChannelContext (we're talking to an established channel)
	struct YamuxContext* ctx = NULL;
	struct YamuxChannelContext* channel = NULL;
	char proto = ((uint8_t*)stream_context)[0];
	if (proto == YAMUX_CHANNEL_CONTEXT) {
		channel = (struct YamuxChannelContext*)stream_context;
		ctx = channel->yamux_context;
	} else if (proto == YAMUX_CONTEXT) {
		ctx = (struct YamuxContext*)stream_context;
	}

	if (channel != NULL && channel->channel != NULL) {
		// we have an established channel. Use it.
		if (!channel->yamux_context->stream->parent_stream->read(channel->yamux_context->stream->parent_stream->stream_context, message, yamux_default_timeout))
			return 0;
		// TODO: This is not right. It must be sorted out.
		struct StreamMessage* msg = *message;
		return yamux_decode(channel->channel->session, msg->data, msg->data_size);
	} else if (ctx != NULL) {
		// We are still negotiating...
		return ctx->stream->parent_stream->read(ctx->stream->parent_stream->stream_context, message, yamux_default_timeout);
	}
	return 0;
}

/***
 * Write to the remote
 * @param stream_context the context. Could be a YamuxContext or YamuxChannelContext
 * @param message the message to write
 * @returns the number of bytes written
 */
int libp2p_yamux_write(void* stream_context, struct StreamMessage* message) {
	if (stream_context == NULL)
		return 0;
	// look at the first byte of the context to determine if this is a YamuxContext (we're negotiating)
	// or a YamuxChannelContext (we're talking to an established channel)
	struct YamuxContext* ctx = NULL;
	struct YamuxChannelContext* channel = NULL;
	char proto = ((uint8_t*)stream_context)[0];
	if (proto == YAMUX_CHANNEL_CONTEXT) {
		channel = (struct YamuxChannelContext*)stream_context;
		ctx = channel->yamux_context;
	} else if (proto == YAMUX_CONTEXT) {
		ctx = (struct YamuxContext*)stream_context;
	}

	if (channel != NULL && channel->channel != NULL) {
		// we have an established channel. Use it.
		return yamux_stream_write(channel->channel, message->data_size, message->data);
	} else if (ctx != NULL) {
		// We are still negotiating...
		return ctx->stream->parent_stream->write(ctx->stream->parent_stream->stream_context, message);
	}
	return 0;
}

/***
 * Check to see if there is anything waiting on the network.
 * @param stream_context the YamuxContext
 * @returns the number of bytes waiting, or -1 on error
 */
int libp2p_yamux_peek(void* stream_context) {
	if (stream_context == NULL)
		return -1;

	struct YamuxContext* ctx = (struct YamuxContext*)stream_context;
	struct Stream* parent_stream = ctx->stream->parent_stream;
	if (parent_stream == NULL)
		return -1;

	return parent_stream->peek(parent_stream->stream_context);
}

int libp2p_yamux_read_raw(void* stream_context, uint8_t* buffer, int buffer_size, int timeout_secs) {
	//TODO: Implement
	return -1;
}

struct YamuxContext* libp2p_yamux_context_new() {
	struct YamuxContext* ctx = (struct YamuxContext*) malloc(sizeof(struct YamuxContext));
	if (ctx != NULL) {
		ctx->type = YAMUX_CONTEXT;
		ctx->stream = NULL;
		ctx->channels = libp2p_utils_vector_new(1);
	}
	return ctx;
}

void libp2p_yamux_context_free(struct YamuxContext* ctx) {
	if (ctx == NULL)
		return;
	libp2p_utils_vector_free(ctx->channels);
	free(ctx);
	return;
}

int libp2p_yamux_negotiate(struct YamuxContext* ctx) {
	const char* protocolID = "/yamux/1.0.0\n";
	struct StreamMessage outgoing;
	struct StreamMessage* results = NULL;
	int retVal = 0;
	int haveTheirs = 0;
	int peek_result = 0;

	// see if they're trying to send something first
	peek_result = libp2p_yamux_peek(ctx);
	if (peek_result > 0) {
		libp2p_logger_debug("yamux", "There is %d bytes waiting for us. Perhaps it is the yamux header we're expecting.\n", peek_result);
		// get the protocol
		ctx->stream->parent_stream->read(ctx->stream->parent_stream, &results, yamux_default_timeout);
		if (results == NULL || results->data_size == 0) {
			libp2p_logger_error("yamux", "We thought we had a yamux header, but we got nothing.\n");
			goto exit;
		}
		if (strncmp((char*)results->data, protocolID, strlen(protocolID)) != 0) {
			libp2p_logger_error("yamux", "We thought we had a yamux header, but we received %d bytes that contained %s.\n", (int)results->data_size, results->data);
			goto exit;
		}
		haveTheirs = 1;
	}

	// send the protocol id
	outgoing.data = (uint8_t*)protocolID;
	outgoing.data_size = strlen(protocolID);
	if (!ctx->stream->parent_stream->write(ctx->stream->parent_stream->stream_context, &outgoing)) {
		libp2p_logger_error("yamux", "We attempted to write the yamux protocol id, but the write call failed.\n");
		goto exit;
	}

	// wait for them to send the protocol id back
	if (!haveTheirs) {
		// expect the same back
		ctx->stream->parent_stream->read(ctx->stream->parent_stream->stream_context, &results, yamux_default_timeout);
		if (results == NULL || results->data_size == 0) {
			libp2p_logger_error("yamux", "We tried to retrieve the yamux header, but we got nothing.\n");
			goto exit;
		}
		if (strncmp((char*)results->data, protocolID, strlen(protocolID)) != 0) {
			libp2p_logger_error("yamux", "We tried to retrieve the yamux header, but we received %d bytes that contained %s.\n", (int)results->data_size, results->data);
			goto exit;
		}
	}

	//TODO: okay, we're almost done. Let incoming stuff be marshaled to the correct handler.
	// this should be somewhat automatic, as they ask, and we negotiate
	//TODO: we should open some streams with them (multistream, id, kademlia, relay)
	// this is not automatic, as we need to start the negotiation process

	retVal = 1;
	exit:
	if (results != NULL)
		free(results);
	return retVal;
}

/***
 * Negotiate the Yamux protocol
 * @param parent_stream the parent stream
 * @returns a Stream initialized and ready for yamux
 */
struct Stream* libp2p_yamux_stream_new(struct Stream* parent_stream) {
	struct Stream* out = libp2p_stream_new();
	if (out != NULL) {
		out->parent_stream = parent_stream;
		out->close = libp2p_yamux_close;
		out->read = libp2p_yamux_read;
		out->write = libp2p_yamux_write;
		out->peek = libp2p_yamux_peek;
		out->read_raw = libp2p_yamux_read_raw;
		out->address = parent_stream->address;
		// build YamuxContext
		struct YamuxContext* ctx = libp2p_yamux_context_new();
		if (ctx == NULL) {
			libp2p_yamux_stream_free(out);
			return NULL;
		}
		out->stream_context = ctx;
		ctx->stream = out;
		// attempt to negotiate yamux protocol
		if (!libp2p_yamux_negotiate(ctx)) {
			libp2p_yamux_stream_free(out);
			return NULL;
		}
	}
	return out;
}

/**
 * Frees resources held by the stream
 * @param yamux_stream the stream
 */
void libp2p_yamux_stream_free(struct Stream* yamux_stream) {
	if (yamux_stream == NULL)
		return;
	struct YamuxContext* ctx = (struct YamuxContext*)yamux_stream->stream_context;
	libp2p_yamux_context_free(ctx);
	libp2p_stream_free(yamux_stream);
}

/****
 * Add a stream "channel" to the yamux handler
 * @param ctx the context
 * @param stream the stream to add
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_yamux_stream_add(struct YamuxContext* ctx, struct Stream* stream) {
	if (stream == NULL)
		return 0;
	// the stream's parent should have a YamuxChannelContext
	char proto = ((uint8_t*)stream->parent_stream->stream_context)[0];
	if (proto == YAMUX_CHANNEL_CONTEXT) {
		// the negotiation was successful. Add it to the list of channels that we have
		int itemNo = libp2p_utils_vector_add(ctx->channels, stream);
		struct YamuxChannelContext* incoming = (struct YamuxChannelContext*)stream->parent_stream->stream_context;
		if (incoming->channel == NULL) {
			// this is wrong. There should have been a yamux_stream there
			return 0;
		}
		incoming->channel->id = itemNo;
		return 1;
	}
	return 0;
}

/**
 * Create a stream that has a "YamuxChannelContext" related to this yamux protocol
 * @param parent_stream the parent yamux stream
 * @returns a new Stream that is a YamuxChannelContext
 */
struct Stream* libp2p_yamux_channel_new(struct Stream* parent_stream) {
	struct Stream* out = libp2p_stream_new();
	if (out != NULL) {
		out->address = parent_stream->address;
		out->close = parent_stream->close;
		out->parent_stream = parent_stream;
		out->peek = parent_stream->peek;
		out->read = parent_stream->read;
		out->read_raw = parent_stream->read_raw;
		out->socket_mutex = parent_stream->socket_mutex;
		struct YamuxChannelContext* ctx = (struct YamuxChannelContext*)malloc(sizeof(struct YamuxChannelContext));
		ctx->type = YAMUX_CHANNEL_CONTEXT;
		ctx->yamux_context = parent_stream->stream_context;
		out->stream_context = ctx;
		out->write = parent_stream->write;
	}
	return out;
}


