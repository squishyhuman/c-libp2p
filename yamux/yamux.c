#include <string.h>
#include <unistd.h>
#include "varint.h"
#include "libp2p/yamux/session.h"
#include "libp2p/yamux/yamux.h"
#include "libp2p/net/protocol.h"
#include "libp2p/net/stream.h"
#include "libp2p/net/connectionstream.h"
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
int yamux_send_protocol(struct Stream* stream) {
	char* protocol = "/yamux/1.0.0\n";
	struct StreamMessage outgoing;
	outgoing.data = (uint8_t*)protocol;
	outgoing.data_size = strlen(protocol);
	if (!stream->write(stream->stream_context, &outgoing))
		return 0;
	return 1;
}

/***
 * Check to see if the reply is the yamux protocol header we expect
 * NOTE: if we initiate the connection, we should expect the same back
 * @param context the SessionContext
 * @returns true(1) on success, false(0) otherwise
 */
int yamux_receive_protocol(struct YamuxContext* context) {
	char* protocol = "/yamux/1.0.0\n";
	struct StreamMessage* results = NULL;
	int retVal = 0;

	if (!context->stream->parent_stream->read(context->stream->parent_stream->stream_context, &results, 30)) {
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
 * @param stream the incoming stream
 * @param protocol_context the protocol-dependent context
 * @returns 0 if the caller should not continue looping, <0 on error, >0 on success
 */
int yamux_handle_message(const struct StreamMessage* msg, struct Stream* stream, void* protocol_context) {
	struct Stream* new_stream = libp2p_yamux_stream_new(stream, 1, protocol_context);
	if (new_stream == NULL)
		return -1;
	// upgrade
	stream->handle_upgrade(stream, new_stream);
	return 1;
}

/**
 * Shutting down. Clean up any memory allocations
 * @param protocol_context the context
 * @returns true(1)
 */
int yamux_shutdown(void* protocol_context) {
	if (protocol_context != NULL)
		free(protocol_context);
	return 0;
}

struct Libp2pProtocolHandler* libp2p_yamux_build_protocol_handler(struct Libp2pVector* handlers) {
	struct Libp2pProtocolHandler* handler = libp2p_protocol_handler_new();
	if (handler != NULL) {
		handler->context = handlers;
		handler->CanHandle = yamux_can_handle;
		handler->HandleMessage = yamux_handle_message;
		handler->Shutdown = yamux_shutdown;
	}
	return handler;
}

/***
 * Close the stream and clean up all resources
 * NOTE: This also goes through the channels
 * @param stream_context the YamuxContext
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_yamux_close(struct Stream* stream) {
	if (stream == NULL)
		return 0;
	if (stream->stream_context == NULL)
		return 0;
	struct Stream* parent_stream = stream->parent_stream;
	// this should close everything above yamux (i.e. the protocols that are riding on top of yamux)
	libp2p_yamux_stream_free(stream);
	// and this should close everything below
	parent_stream->close(parent_stream);
	return 1;
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

	if (channel != NULL && channel->channel != 0) {
		// we have an established channel. Use it.
		if (!channel->yamux_context->stream->parent_stream->read(channel->yamux_context->stream->parent_stream->stream_context, message, yamux_default_timeout))
			return 0;
		// TODO: This is not right. It must be sorted out.
		struct StreamMessage* msg = *message;
		if (yamux_decode(channel, msg->data, msg->data_size, message) == 0)
			return 1;
	} else if (ctx != NULL) {
		// We are still negotiating. They are probably attempting to negotiate a new protocol
		struct StreamMessage* incoming = NULL;
		if (ctx->stream->parent_stream->read(ctx->stream->parent_stream->stream_context, &incoming, yamux_default_timeout)) {
			// parse the frame
			if (yamux_decode(ctx, incoming->data, incoming->data_size, message) == 0) {
				libp2p_stream_message_free(incoming);
				return 1;
			}
			libp2p_stream_message_free(incoming);
		}
	}
	return 0;
}

/***
 * Prepare a new Yamux StreamMessage based on another StreamMessage
 * NOTE: The frame is not encoded yet
 * @param incoming the incoming message
 * @returns a new StreamMessage that has a yamux_frame
 */
struct StreamMessage* libp2p_yamux_prepare_to_send(struct StreamMessage* incoming) {
	struct StreamMessage* out = libp2p_stream_message_new();
	if (out != NULL) {
		out->data_size = sizeof(struct yamux_frame) + incoming->data_size;
		out->data = (uint8_t*) malloc(out->data_size);
		if (out->data == NULL) {
			libp2p_stream_message_free(out);
			return NULL;
		}
		memset(out->data, 0, out->data_size);
		// the first part of the data is the yamux frame
		// Set values in the frame, which is the first part of the outgoing message data
		struct yamux_frame* frame = (struct yamux_frame*)out->data;
		frame->length = incoming->data_size;
		frame->type = yamux_frame_data;
		frame->version = YAMUX_VERSION;
		// the last part of the data is the original data
		memcpy(&out->data[sizeof(struct yamux_frame)], incoming->data, incoming->data_size);
	}
	return out;
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

	if (ctx == NULL && channel == NULL)
		return 0;

	struct StreamMessage* outgoing_message = libp2p_yamux_prepare_to_send(message);
	// now convert fame for network use
	struct yamux_frame* frame = (struct yamux_frame*)outgoing_message->data;
	// set a few more flags
	frame->flags = get_flags(stream_context);
	if (channel != NULL)
		frame->streamid = channel->channel;
	encode_frame(frame);

	int retVal = 0;
	if (channel != NULL && channel->channel != 0) {
		// we have an established channel. Use it.
		retVal = channel->stream->write(channel->stream->stream_context, outgoing_message);
	} else if (ctx != NULL) {
		retVal = ctx->stream->parent_stream->write(ctx->stream->parent_stream, outgoing_message);
	}
	libp2p_stream_message_free(outgoing_message);

	return retVal;
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

/**
 * Create a new YamuxContext struct
 * @param stream the parent stream
 * @returns a YamuxContext
 */
struct YamuxContext* libp2p_yamux_context_new(struct Stream* stream) {
	struct YamuxContext* ctx = (struct YamuxContext*) malloc(sizeof(struct YamuxContext));
	if (ctx != NULL) {
		ctx->type = YAMUX_CONTEXT;
		ctx->stream = NULL;
		ctx->channels = libp2p_utils_vector_new(1);
		ctx->session = yamux_session_new(NULL, stream, yamux_session_server, NULL);
		ctx->am_server = 0;
		ctx->state = 0;
	}
	return ctx;
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
		libp2p_stream_message_free(results);
		results = NULL;
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
		libp2p_stream_message_free(results);
	return retVal;
}

/***
 * A new protocol was asked for. Give it a "channel"
 * @param yamux_stream the yamux stream
 * @param new_stream the newly negotiated protocol
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_yamux_handle_upgrade(struct Stream* yamux_stream, struct Stream* new_stream) {
	// put this stream in the collection, and tie it to an id
	struct YamuxContext* yamux_context = (struct YamuxContext*)yamux_stream->stream_context;
	return libp2p_yamux_stream_add(yamux_context, new_stream);
}

void libp2p_yamux_read_from_yamux_session(struct yamux_stream* stream, uint32_t data_len, void* data) {

}

/***
 * Internal yamux code calls this when a new stream is created
 * @param context the context
 * @param stream the new stream
 */
void libp2p_yamux_new_stream(struct YamuxContext* context, struct Stream* stream, struct StreamMessage* msg) {
	// ok, we have the new stream structure. We now need to read what was sent.
	libp2p_protocol_marshal(msg, stream, context->protocol_handlers);
}

/***
 * Negotiate the Yamux protocol
 * @param parent_stream the parent stream
 * @param am_server true(1) if we are considered the server, false(0) if we are the client.
 * @param protocol_handlers the protocol handlers
 * @returns a Stream initialized and ready for yamux
 */
struct Stream* libp2p_yamux_stream_new(struct Stream* parent_stream, int am_server, struct Libp2pVector* protocol_handlers) {
	struct Stream* out = libp2p_stream_new();
	if (out != NULL) {
		out->stream_type = STREAM_TYPE_YAMUX;
		out->parent_stream = parent_stream;
		out->close = libp2p_yamux_close;
		out->read = libp2p_yamux_read;
		out->write = libp2p_yamux_write;
		out->peek = libp2p_yamux_peek;
		out->read_raw = libp2p_yamux_read_raw;
		out->handle_upgrade = libp2p_yamux_handle_upgrade;
		out->address = parent_stream->address;
		// build YamuxContext
		struct YamuxContext* ctx = libp2p_yamux_context_new(out);
		if (ctx == NULL) {
			libp2p_yamux_stream_free(out);
			return NULL;
		}
		ctx->session->new_stream_fn = libp2p_yamux_new_stream;
		out->stream_context = ctx;
		ctx->stream = out;
		ctx->am_server = am_server;
		ctx->protocol_handlers = protocol_handlers;
		// attempt to negotiate yamux protocol
		if (!libp2p_yamux_negotiate(ctx)) {
			libp2p_yamux_stream_free(out);
			return NULL;
		}
	}
	return out;
}


/**
 * Clean up resources from libp2p_yamux_channel_new
 * @param ctx the YamuxChannelContext
 */
int libp2p_yamux_channel_close(void* context) {
	if (context == NULL)
		return 0;
	struct YamuxChannelContext* ctx = (struct YamuxChannelContext*)context;
	if (ctx != NULL) {
		// close the child's stream
		ctx->child_stream->close(ctx->child_stream);
		libp2p_stream_free(ctx->stream);
		free(ctx);
	}
	return 1;
}

/***
 * Free the resources from libp2p_yamux_context_new
 * @param ctx the context
 */
void libp2p_yamux_context_free(struct YamuxContext* ctx) {
	if (ctx == NULL)
		return;
	// free all the channels
	if (ctx->channels) {
		for(int i = 0; i < ctx->channels->total; i++) {
			struct Stream* curr = (struct Stream*) libp2p_utils_vector_get(ctx->channels, i);
			//curr->close(curr->stream_context);
			libp2p_yamux_channel_close(curr->stream_context);
		}
		libp2p_utils_vector_free(ctx->channels);
	}
	if (ctx->session != NULL)
		yamux_session_free(ctx->session);
	free(ctx);
	return;
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

/***
 * Channels calling close on the stream should not be able
 * to clean up layers below
 * @param context the context
 * @returns true(1);
 */
int libp2p_yamux_channel_null_close(struct Stream* stream) {
	return 1;
}

/**
 * Create a stream that has a "YamuxChannelContext" related to this yamux protocol
 * NOTE: If incoming_stream is not of the Yamux protocol, this "wraps" the incoming
 * stream, so that the returned stream is the parent of the incoming_stream. If the
 * incoming stream is of the yamux protocol, the YamuxChannelContext.child_stream
 * will be NULL, awaiting an upgrade to fill it in.
 * @param incoming_stream the stream of the new protocol
 * @param channelNumber the channel number (0 if unknown)
 * @returns a new Stream that has a YamuxChannelContext
 */
struct Stream* libp2p_yamux_channel_stream_new(struct Stream* incoming_stream, int channelNumber) {
	struct Stream* out = libp2p_stream_new();
	if (out != NULL) {
		int isYamux = 0;
		char first_char = ((uint8_t*)incoming_stream->stream_context)[0];
		if (first_char == YAMUX_CONTEXT)
			isYamux = 1;
		out->stream_type = STREAM_TYPE_YAMUX;
		out->address = incoming_stream->address;
		// don't allow the incoming_stream to close the channel
		out->close = libp2p_yamux_channel_null_close;
		struct YamuxChannelContext* ctx = (struct YamuxChannelContext*)malloc(sizeof(struct YamuxChannelContext));
		if (!isYamux) {
			out->parent_stream = incoming_stream->parent_stream;
			out->peek = incoming_stream->parent_stream->peek;
			out->read = incoming_stream->parent_stream->read;
			out->read_raw = incoming_stream->parent_stream->read_raw;
			out->write = incoming_stream->parent_stream->write;
			out->socket_mutex = incoming_stream->parent_stream->socket_mutex;
			ctx->yamux_context = incoming_stream->parent_stream->stream_context;
			ctx->child_stream = incoming_stream;
			// this does the wrap
			incoming_stream->parent_stream = out;
		} else {
			 out->parent_stream = incoming_stream;
			 out->peek = incoming_stream->peek;
			 out->read = incoming_stream->read;
			 out->read_raw = incoming_stream->read_raw;
			 out->write = incoming_stream->write;
			 out->socket_mutex = incoming_stream->socket_mutex;
			 ctx->yamux_context = incoming_stream->stream_context;
			 ctx->child_stream = NULL;
		}
		ctx->channel = channelNumber;
		ctx->closed = 0;
		ctx->state = 0;
		ctx->window_size = 0;
		ctx->type = YAMUX_CHANNEL_CONTEXT;
		ctx->stream = out;
		out->stream_context = ctx;
	}
	return out;
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
	// wrap the new stream in a YamuxChannelContext
	struct Stream* channel_stream = libp2p_yamux_channel_stream_new(stream, 0);
	if (channel_stream == NULL)
		return 0;
	struct YamuxChannelContext* channel_context = (struct YamuxChannelContext*)channel_stream->stream_context;
	// the negotiation was successful. Add it to the list of channels that we have
	int itemNo = libp2p_utils_vector_add(ctx->channels, channel_stream);
	// There are 2 streams for each protocol. A server has the even numbered streams, the
	// client the odd number streams. If we are the server, we need to kick off the
	// process to add a stream of the same type.
	channel_context->channel = itemNo;
	if (ctx->am_server && itemNo % 2 != 0) {
		// we're the server, and they have a negotiated a new protocol.
		// negotiate a stream for us to talk to them.
		struct Stream* yamux_stream = stream->parent_stream->parent_stream;
		struct Stream* server_to_client_stream = stream->negotiate(yamux_stream);
		libp2p_yamux_stream_add(ctx, server_to_client_stream);
	}
	return 1;
}
