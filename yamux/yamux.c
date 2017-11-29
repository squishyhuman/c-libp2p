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

// function declarations that we don't want in the header file
int libp2p_yamux_channels_free(struct YamuxContext* ctx);
struct Stream* libp2p_yamux_get_parent_stream(void* context);

/**
 * Given a context, get the YamuxChannelContext
 * @param stream_context the context
 * @returns the YamuxChannelContext or NULL if there was none
 */
struct YamuxChannelContext* libp2p_yamux_get_channel_context(void* stream_context) {
	char proto = ((uint8_t*)stream_context)[0];
	if (proto == YAMUX_CHANNEL_CONTEXT) {
		return (struct YamuxChannelContext*)stream_context;
	}
	return NULL;
}

/***
 * Given a context, get the YamuxContext
 * @param stream_context a YamuxChannelContext or a YamuxContext
 * @returns the YamuxContext, or NULL on error
 */
struct YamuxContext* libp2p_yamux_get_context(void* stream_context) {
	char proto = ((uint8_t*)stream_context)[0];
	struct YamuxChannelContext* channel = NULL;
	struct YamuxContext* ctx = NULL;
	if (proto == YAMUX_CHANNEL_CONTEXT) {
		channel = (struct YamuxChannelContext*)stream_context;
		ctx = channel->yamux_context;
	} else if (proto == YAMUX_CONTEXT) {
		ctx = (struct YamuxContext*)stream_context;
	}
	return ctx;
}


/**
 * Determines if this protocol can handle the incoming message
 * @param incoming the incoming data
 * @param incoming_size the size of the incoming data buffer
 * @returns true(1) if it can handle this message, false(0) if not
 */
int yamux_can_handle(const struct StreamMessage* msg) {
	if (msg == NULL || msg->data_size == 0 || msg->data == NULL)
		return 0;
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

/***
 * The remote is attempting to negotiate yamux
 * @param msg the incoming message
 * @param incoming_size the size of the incoming data buffer
 * @param stream the incoming stream
 * @param protocol_context the protocol-dependent context
 * @returns 0 if the caller should not continue looping, <0 on error, >0 on success
 */
int yamux_handle_message(const struct StreamMessage* msg, struct Stream* stream, void* protocol_context) {
	// get latest stream (multithreaded, so could be stale)
	stream = libp2p_net_connection_get_session_context(stream)->default_stream;
	if (stream->stream_type == STREAM_TYPE_YAMUX) {
		struct YamuxContext* ctx = (struct YamuxContext*) stream->stream_context;
		if (ctx->state == yamux_stream_est) {
			// TODO: This is probably a frame. we need to handle this.
			return -1;
		} else {
			//TODO: check to make sure they sent the yamux protocol id
			// we sent a protocol ID, and this is them responding
			ctx->state = yamux_stream_est;
		}
		return 1;
	}
	// the incoming stream is not yamux. They are attempting to upgrade to yamux
	struct YamuxProtocolContext* yamuxProtocolContext = (struct YamuxProtocolContext*)protocol_context;
	struct Stream* new_stream = libp2p_yamux_stream_new(stream, 0, yamuxProtocolContext->protocol_handlers);
	if (new_stream != NULL) {
		struct YamuxContext* ctx = (struct YamuxContext*) new_stream->stream_context;
		ctx->state = yamux_stream_est;
		// upgrade
		return stream->handle_upgrade(stream, new_stream);
	}
	return -1;
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
		struct YamuxProtocolContext* ctx = (struct YamuxProtocolContext*) malloc(sizeof(struct YamuxProtocolContext));
		if (ctx == NULL) {
			libp2p_protocol_handler_free(handler);
			return NULL;
		}
		ctx->protocol_handlers = handlers;
		handler->context = ctx;
		handler->CanHandle = yamux_can_handle;
		handler->HandleMessage = yamux_handle_message;
		handler->Shutdown = yamux_shutdown;
	}
	return handler;
}

/**
 * Close the main yamux connection
 * @param stream the stream to close
 * @returns true(1) on success, false(0) on error
 */
int libp2p_yamux_send_go_away(struct Stream* stream) {
	struct YamuxChannelContext* channel = libp2p_yamux_get_channel_context(stream->stream_context);
	struct YamuxContext* ctx = libp2p_yamux_get_context(stream->stream_context);
	if (ctx != NULL) {
		struct StreamMessage* msg = libp2p_stream_message_new();
		msg->data_size = sizeof(struct yamux_frame);
		msg->data = malloc(msg->data_size);
		struct yamux_frame* f = (struct yamux_frame*) msg->data;
		f->type = yamux_frame_go_away;
		f->flags = yamux_frame_fin;
		f->streamid = 0;
		f->version = 0;
		f->length = 0;
		if (channel != NULL) {
			f->streamid = channel->channel;
		}
		encode_frame(f);
		stream->parent_stream->write(stream->parent_stream->stream_context, msg);
		libp2p_stream_message_free(msg);
		return 1;
	}
	return 0;
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
	libp2p_yamux_channels_free(stream->stream_context);
	// send a FIN
	libp2p_yamux_send_go_away(stream);
	// and this should close everything below
	parent_stream->close(parent_stream);
	return 1;
}

/***
 * Determine if the incoming is a data frame, but we need more data
 * @param incoming the incoming message
 * @returns > 0 if we need more data, 0 if not
 */
int yamux_more_to_read(struct StreamMessage* incoming) {
	if (incoming == NULL)
		return 0;
	if (incoming->data_size < 12) {
		return 0;
	}
	// get frame
	struct yamux_frame* original_frame = (struct yamux_frame*)incoming->data;
	struct yamux_frame* copy = (struct yamux_frame*) malloc(sizeof(struct yamux_frame));
	memcpy(copy, original_frame, sizeof(struct yamux_frame));
	decode_frame(copy);
	if (copy->type == yamux_frame_data) {
		libp2p_logger_debug("yamux", "Checking frame sizes. It says we should have %d, and I see %d.\n", copy->length, incoming->data_size - sizeof(struct yamux_frame));
		int retVal = copy->length - (incoming->data_size - sizeof(struct yamux_frame));
		free(copy);
		return retVal;
	}
	free(copy);
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
	if (stream_context == NULL) {
		libp2p_logger_error("yamux", "read was passed a null context.\n");
		return 0;
	}
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

	if (ctx == NULL) {
		libp2p_logger_error("yamux", "read: The incoming stream is not a yamux stream.\n");
		return 0;
	}

	if (ctx->state != yamux_stream_est) {
		libp2p_logger_debug("yamux", "read: Yamux still not inited, so passing to lower protocol.\n");
		// perhaps this is the yamux protocol id we've been expecting
		int retVal = ctx->stream->parent_stream->read(ctx->stream->parent_stream->stream_context, message, timeout_secs);
		libp2p_logger_debug("yamux", "read: we did the lower read, and received a %d.\n", retVal);
		if (retVal > 0) {
			struct StreamMessage* incoming_message = *message;
			libp2p_logger_debug("yamux", "read: The lower read has a message of %d bytes that says: %s.\n", incoming_message->data_size, incoming_message->data);
			if (strstr((char*)incoming_message->data, "/yamux/1.0.0") != NULL) {
				libp2p_logger_debug("yamux", "read: We got the protocol we've been waiting for.\n");
				ctx->state = yamux_stream_est;
				libp2p_stream_message_free(incoming_message);
				*message = NULL;
				return 0;
			}
		}
		return retVal;
	}

	struct Stream* parent_stream = libp2p_yamux_get_parent_stream(stream_context);
	if (channel != NULL && channel->channel != 0) {
		// I don't think this will ever be the case. This I believe to be dead code
		libp2p_logger_debug("yamux", "Data received on yamux stream %d.\n", channel->channel);
		// we have an established channel. Use it.
		if (!parent_stream->read(parent_stream->stream_context, message, yamux_default_timeout)) {
			libp2p_logger_error("yamux", "Read: Attepted to read from channel %d, but the read failed.\n", channel->channel);
			return 0;
		}
		if (message == NULL) {
			libp2p_logger_error("yamux", "Read: Successfully read from channel %d, but message was NULL.\n", channel->channel);
		}
		// TODO: This is not right. It must be sorted out.
		struct StreamMessage* msg = *message;
		libp2p_logger_debug("yamux", "Read: Received %d bytes on channel %d.\n", msg->data_size, channel->channel);
		if (yamux_decode(channel, msg->data, msg->data_size, message) == 0) {
			return 1;
		}
		libp2p_logger_error("yamux", "yamux_decode returned error.\n");
	} else if (ctx != NULL) {
		// this is the normal situation (not dead code).
		struct StreamMessage* incoming = NULL;
		// we need a lock
		if (parent_stream->read(parent_stream->stream_context, &incoming, yamux_default_timeout)) {
			libp2p_logger_debug("yamux", "read: successfully read %d bytes from network.\n", incoming->data_size);
			// This could be a data frame with the actual data coming later. Yuck.
			// JMJ in the case of an incomplete buffer, the next read should be the data. This must
			// be true, as the next data does not have a frame. We should only read the bytes we need.
			int moreToRead = yamux_more_to_read(incoming);
			if (moreToRead > 0) {
				uint8_t buffer[moreToRead];
				if (parent_stream->read_raw(parent_stream->stream_context, buffer, moreToRead, timeout_secs) == moreToRead) {
					// we have the bytes we need
					uint8_t* new_buffer = (uint8_t*) malloc(incoming->data_size + moreToRead);
					memcpy(new_buffer, incoming->data, incoming->data_size);
					memcpy(&new_buffer[incoming->data_size], buffer, moreToRead);
					incoming->data_size += moreToRead;
					free(incoming->data);
					incoming->data = new_buffer;
				} else {
					// we didn't get the bytes we needed
					return 0;
				}
			}
			// parse the frame. This is where the work happens.
			if (yamux_decode(ctx, incoming->data, incoming->data_size, message) >= 0) {
				libp2p_stream_message_free(incoming);
				// The message may not have anything in it. If so, return 0, as if nothing was done. Everything has been handled
				if (*message != NULL && (*message)->data_size == 0) {
					libp2p_stream_message_free(*message);
					*message = NULL;
					return 0;
				}
				return 1;
			}
			libp2p_logger_error("yamux", "yamux_decode returned error.\n");
			libp2p_stream_message_free(incoming);
		} else {
			// read failed
		}
	}
	libp2p_logger_error("yamux", "Unable to do network read.\n");
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
 * Get the next usable ID for a channel
 * NOTE: Also increments the yamux_session_.nextid counter
 * NOTE: Odd = client, Even = server
 * @param ctx the context
 * @returns the next id
 */
uint32_t libp2p_yamux_get_next_id(struct YamuxContext* ctx) {
	uint32_t next_id = ctx->session->nextid;
	if ( (ctx->am_server && next_id % 2 == 1)
			|| (!ctx->am_server && next_id % 2 == 0))
		next_id += 1;
	ctx->session->nextid = next_id + 1;
	return next_id;
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

	if (ctx->state != yamux_stream_est) {
		struct Stream* parent_stream = ctx->stream->parent_stream;
		return parent_stream->write(parent_stream->stream_context, message);
	}

	struct StreamMessage* outgoing_message = libp2p_yamux_prepare_to_send(message);
	// now convert fame for network use
	struct yamux_frame* frame = (struct yamux_frame*)outgoing_message->data;
	// set a few more flags
	frame->flags = get_flags(stream_context);
	if (channel == NULL) {
		// if we don't yet have a channel, set the id to the next available
		frame->streamid = libp2p_yamux_get_next_id(ctx);
	} else {
		frame->streamid = channel->channel;
	}
	encode_frame(frame);

	int retVal = 0;
	if (channel != NULL && channel->channel != 0) {
		// we have an established channel. Use it.
		libp2p_logger_debug("yamux", "About to write %d bytes to yamux channel %d.\n", outgoing_message->data_size, channel->channel);
		struct Stream* parent_stream = libp2p_yamux_get_parent_stream(stream_context);
		retVal = parent_stream->write(parent_stream->stream_context, outgoing_message);
	} else if (ctx != NULL) {
		libp2p_logger_debug("yamux", "About to write %d bytes to stream.\n", outgoing_message->data_size);
		retVal = ctx->stream->parent_stream->write(ctx->stream->parent_stream->stream_context, outgoing_message);
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

	struct YamuxContext* ctx = libp2p_yamux_get_context(stream_context);
	struct Stream* parent_stream = ctx->stream->parent_stream;
	if (parent_stream == NULL)
		return -1;

	return parent_stream->peek(parent_stream->stream_context);
}

/***
 * Read from the network, and place it in the buffer
 * NOTE: This may put something in the internal read buffer (i.e. buffer_size is too small)
 * @param stream_context the yamux context
 * @param buffer the buffer
 * @param buffer_size the size of the incoming buffer (max number of bytes to read)
 * @param timeout_secs timeout
 * @returns number of bytes read.
 */
int libp2p_yamux_read_raw(void* stream_context, uint8_t* buffer, int buffer_size, int timeout_secs) {
	if (stream_context == NULL) {
		return -1;
	}
	struct YamuxContext* ctx = libp2p_yamux_get_context(stream_context);
	if (ctx->buffered_message_pos == -1 || ctx->buffered_message == NULL) {
		// we need to get info from the network
		if (!libp2p_yamux_read(stream_context, &ctx->buffered_message, timeout_secs)) {
			libp2p_logger_error("yamux", "read_raw: Unable to read from network.\n");
			return -1;
		}
		ctx->buffered_message_pos = 0;
	} else {
		// we have some data from a previous read_raw call the code
		// below should handle this.
	}
	// max_to_read is the lesser of bytes read or buffer_size
	int max_to_read = (buffer_size > (ctx->buffered_message->data_size-ctx->buffered_message_pos) ? ctx->buffered_message->data_size-ctx->buffered_message_pos : buffer_size);
	memcpy(buffer, &ctx->buffered_message->data[ctx->buffered_message_pos], max_to_read);
	ctx->buffered_message_pos += max_to_read;
	if (ctx->buffered_message_pos == ctx->buffered_message->data_size) {
		// we read everything
		libp2p_stream_message_free(ctx->buffered_message);
		ctx->buffered_message = NULL;
		ctx->buffered_message_pos = -1;
	} else {
		// we didn't read everything.
		ctx->buffered_message_pos = max_to_read;
	}
	return max_to_read;
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
		ctx->buffered_message = NULL;
		ctx->buffered_message_pos = -1;
		ctx->protocol_handlers = NULL;
	}
	return ctx;
}

/***
 * Write the protocol id for yamux to the stream
 * @param stream the stream to write to
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_yamux_send_protocol(struct Stream* stream) {
	// JMJ debug
	libp2p_logger_debug("yamux", "Sending protocol through stream of type %d and channel %d.\n", stream->stream_type, stream->channel);
	const char* protocolID = "/yamux/1.0.0\n";
	struct StreamMessage outgoing;
	outgoing.data_size = strlen(protocolID);
	outgoing.data = (uint8_t*)protocolID;
	outgoing.error_number = 0;
	return stream->write(stream->stream_context, &outgoing);
}

/***
 * A new protocol was asked for. Give it a "channel"
 * @param yamux_stream the yamux stream
 * @param new_stream the newly negotiated protocol
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_yamux_handle_upgrade(struct Stream* yamux_stream, struct Stream* new_stream) {
	// put this stream in the collection, and tie it to an id
	if (libp2p_logger_watching_class("yamux")) {
		const char* stream_type = "";
		if (new_stream->stream_type == STREAM_TYPE_MULTISTREAM) {
			stream_type = "Multistream";
		}
		libp2p_logger_debug("yamux", "handle_upgrade called for stream %s.\n", stream_type);
	}
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
	//libp2p_protocol_marshal(msg, stream, context->protocol_handlers);
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
		out->socket_mutex = parent_stream->socket_mutex;
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
		ctx->state = yamux_stream_inited;
		// tell protocol below that we want to upgrade
		parent_stream->handle_upgrade(parent_stream, out);
		// attempt to negotiate yamux protocol
		if (!libp2p_yamux_send_protocol(parent_stream)) {
			libp2p_yamux_stream_free(out);
			return NULL;
		}
	}
	return out;
}

/***
 * This will retrieve the stream that yamux is riding on top of
 * @param context a YamuxContext or YamuxChannelContext
 * @returns the Stream that yamux is riding on top of
 */
struct Stream* libp2p_yamux_get_parent_stream(void* context) {
	if (context == NULL)
		return NULL;
	struct YamuxContext* ctx = libp2p_yamux_get_context(context);
	if (ctx == NULL)
		return NULL;
	return ctx->stream->parent_stream;
}

/***
 * Sends a FIN to close a channel
 * @param channel the channel to close
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_yamux_channel_send_FIN(struct YamuxChannelContext* channel) {
	if (channel == NULL)
		return 0;
	struct YamuxContext* ctx = channel->yamux_context;
	if (ctx != NULL) {
		struct StreamMessage* msg = libp2p_stream_message_new();
		msg->data_size = sizeof(struct yamux_frame);
		msg->data = malloc(msg->data_size);
		struct yamux_frame* f = (struct yamux_frame*) msg->data;
		f->type = yamux_frame_window_update;
		f->flags = yamux_frame_fin;
		f->streamid = channel->channel;
		f->version = 0;
		f->length = 0;
		encode_frame(f);
		struct Stream* parent_to_yamux = libp2p_yamux_get_parent_stream(channel);
		if (parent_to_yamux != NULL)
			parent_to_yamux->write(parent_to_yamux->stream_context, msg);
		libp2p_stream_message_free(msg);
		return 1;
	}
	return 0;

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
		//Send FIN
		libp2p_yamux_channel_send_FIN(ctx);
		// close the child's stream
		ctx->child_stream->close(ctx->child_stream);
		libp2p_stream_free(ctx->stream);
		free(ctx);
	}
	return 1;
}

/***
 * Close all channels
 * @param ctx the YamuxContext that contains a vector of channels
 * @returns true(1)
 */
int libp2p_yamux_channels_free(struct YamuxContext* ctx) {
	if (ctx->channels) {
		for(int i = 0; i < ctx->channels->total; i++) {
			struct Stream* curr = (struct Stream*) libp2p_utils_vector_get(ctx->channels, i);
			libp2p_yamux_channel_close(curr->stream_context);
		}
		libp2p_utils_vector_free(ctx->channels);
		ctx->channels = NULL;
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
	if (ctx->buffered_message != NULL) {
		libp2p_stream_message_free(ctx->buffered_message);
		ctx->buffered_message = NULL;
	}
	// free all the channels
	libp2p_yamux_channels_free(ctx);
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
		ctx->channel = (uint32_t) channelNumber;
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
	uint32_t itemNo = (uint32_t) libp2p_utils_vector_add(ctx->channels, channel_stream);
	// There are 2 streams for each protocol. A server has the even numbered streams, the
	// client the odd number streams. If we are the server, we need to kick off the
	// process to add a stream of the same type.
	channel_context->channel = itemNo;
	if (ctx->am_server && itemNo % 2 != 0) {
		// we're the server, and they have a negotiated a new protocol.
		// negotiate a stream for us to talk to them.
		struct Stream* yamux_stream = ctx->stream;
		struct Stream* server_to_client_stream = stream->negotiate(yamux_stream);
		libp2p_yamux_stream_add(ctx, server_to_client_stream);
	}
	return 1;
}

/***
 * Wait for yamux stream to become ready
 * @param session_context the session context to check
 * @param timeout_secs the number of seconds to wait for things to become ready
 * @returns true(1) if it becomes ready, false(0) otherwise
 */
int libp2p_yamux_stream_ready(struct SessionContext* session_context, int timeout_secs) {
	int counter = 0;
	while (session_context != NULL
			&& session_context->default_stream != NULL
			&& session_context->default_stream->stream_type != STREAM_TYPE_YAMUX
			&& counter <= timeout_secs) {
		counter++;
		sleep(1);
	}
	if (session_context != NULL
			&& session_context->default_stream != NULL
			&& session_context->default_stream->stream_type == STREAM_TYPE_YAMUX
			&& counter < 5) {
		struct YamuxContext* ctx = (struct YamuxContext*)session_context->default_stream->stream_context;
		while (ctx->state != yamux_stream_est && counter <= timeout_secs) {
			counter++;
			sleep(1);
		}
		if (ctx->state == yamux_stream_est)
			return 1;
	}
	return 0;
}

