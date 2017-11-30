#include <string.h>

#include "varint.h"
#include "protobuf.h"
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
	if (msg == NULL || msg->data_size == 0 || msg->data == 0)
		return 0;
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
 * Create a Identify struct
 * @returns the newly allocated record struct
 */
Identify* libp2p_identify_new() {
        Identify* out = (Identify*)malloc(sizeof(Identify));
        if (out != NULL) {
                out->PublicKey = NULL;
                out->ListenAddrs = NULL;
                out->Protocols = NULL;
                out->ObservedAddr = NULL;
                out->ProtocolVersion = IDENTIFY_PROTOCOL_VERSION;
                out->AgentVersion = IDENTIFY_AGENT_VERSION;
                out->XXX_unrecognized = NULL;
        }
        return out;
}

/**
 * Free the resources from a identify struct
 * @param in the struct to free
 */
void libp2p_identify_free(Identify* in) {
	int i;

	if (in != NULL) {
		if (in->PublicKey != NULL)
			free(in->PublicKey);
		if (in->ListenAddrs != NULL) {
			// free every item
			for (i = 0 ; in->ListenAddrs[i] ; i++)
				free(in->ListenAddrs[i]);
			// free array
			free(in->ListenAddrs);
		}
		if (in->Protocols != NULL) {
			for (i = 0 ; in->Protocols[i] ; i++)
				free(in->Protocols[i]);
			free(in->Protocols);
		}
		if (in->ObservedAddr != NULL)
			free(in->ObservedAddr);
		if (in->XXX_unrecognized != NULL)
			free(in->XXX_unrecognized);
		free(in);
	}
}

/* helper to alloc and copy an item.
 * @param item the item.
 * @returns a pointer on success, otherwise NULL.
 */
char *libp2p_identify_new_item(char *item, size_t size) {
	char *dst = NULL;
	if (item) {
		dst = malloc(size);
		if (dst) {
			memcpy(dst, item, size);
		}
	}
	return dst;
}

/* helper to add an item to an array.
 * @param array the array.
 * @param item the item.
 * @returns count itens on success, otherwise zero.
 */
int libp2p_identify_array_add_item(char ***array, char *item) {
	int count = 0;
	if (array && item) {
		if (*array) {
			// count itens already in.
			while (*array[count++]);
		}
		// alloc the necessary array count or realloc more if alread allocated.
		*array = realloc(*array, sizeof(char*) * (count + 2)); // 2, the new and the NULL
		*array[count++] = item;
		*array[count] = NULL;
	}
	return count;
}

/**
 * Convert a identify struct into protobuf format
 * @param in the Identify struct to convert
 * @param buffer where to store the protobuf
 * @param max_buffer_size the size of the allocated buffer
 * @param bytes_written the size written into buffer
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_identify_protobuf_encode(const Identify* in, unsigned char* buffer, size_t max_buffer_size, size_t* bytes_written) {
	// data & data_size
	size_t bytes_used = 0;
	*bytes_written = 0;
	int i, retVal = 0;

	// field 1
	retVal = protobuf_encode_string(1, WIRETYPE_LENGTH_DELIMITED, in->PublicKey, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
	if (retVal == 0)
		return 0;
	*bytes_written += bytes_used;
	// field 2
	for (i = 0 ; in->ListenAddrs[i] ; i++) {
		retVal = protobuf_encode_string(2, WIRETYPE_LENGTH_DELIMITED, in->ListenAddrs[i], &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
		if (retVal == 0)
			return 0;
		*bytes_written += bytes_used;
	}
	// field 3
	for (i = 0 ; in->Protocols[i] ; i++) {
		retVal = protobuf_encode_string(3, WIRETYPE_LENGTH_DELIMITED, in->Protocols[i], &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
		if (retVal == 0)
			return 0;
		*bytes_written += bytes_used;
	}
	// field 4
	retVal = protobuf_encode_string(4, WIRETYPE_LENGTH_DELIMITED, in->ObservedAddr, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
	if (retVal == 0)
		return 0;
	*bytes_written += bytes_used;
	// field 5
	retVal = protobuf_encode_string(5, WIRETYPE_LENGTH_DELIMITED, in->ProtocolVersion, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
	if (retVal == 0)
		return 0;
	*bytes_written += bytes_used;
	// field 6
	retVal = protobuf_encode_string(6, WIRETYPE_LENGTH_DELIMITED, in->AgentVersion, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
	if (retVal == 0)
		return 0;
	*bytes_written += bytes_used;

	return 1;
}

/**
 * Convert a protobuf byte array into a Identify struct
 * @param in the byte array
 * @param in_size the size of the byte array
 * @param out a pointer to the new Identify struct
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_identify_protobuf_decode(const unsigned char* in, size_t in_size, Identify** out) {
	size_t pos = 0;
	int count, retVal = 0;
	char *item;

	if ( (*out = libp2p_identify_new()) == NULL)
		goto exit;

	while(pos < in_size) {
		size_t bytes_read = 0;
		int field_no;
		enum WireType field_type;
		if (!protobuf_decode_field_and_type(&in[pos], in_size, &field_no, &field_type, &bytes_read)) {
			goto exit;
		}
		pos += bytes_read;
		switch(field_no) {
			case (1): // PublicKey
				if (!protobuf_decode_string(&in[pos], in_size - pos, (char**)&((*out)->PublicKey), &bytes_read))
					goto exit;
				pos += bytes_read;
				break;
			case (2): // ListenAddrs
				if (!protobuf_decode_string(&in[pos], in_size - pos, (char**)&(item), &bytes_read))
					goto exit;
				if (!libp2p_identify_array_add_item(&((*out)->ListenAddrs), item))
					goto exit;
				pos += bytes_read;
				break;
			case (3): // Protocols
				if (!protobuf_decode_string(&in[pos], in_size - pos, (char**)&(item), &bytes_read))
					goto exit;
				if (!libp2p_identify_array_add_item(&((*out)->Protocols), item))
					goto exit;
				pos += bytes_read;
				break;
			case (4): // ObservedAddr
				if (!protobuf_decode_string(&in[pos], in_size - pos, (char**)&((*out)->ObservedAddr), &bytes_read))
					goto exit;
				pos += bytes_read;
				break;
			case (5): // ProtocolVersion
				if (!protobuf_decode_string(&in[pos], in_size - pos, (char**)&((*out)->ProtocolVersion), &bytes_read))
					goto exit;
				pos += bytes_read;
				break;
			case (6): // AgentVersion
				if (!protobuf_decode_string(&in[pos], in_size - pos, (char**)&((*out)->AgentVersion), &bytes_read))
					goto exit;
				pos += bytes_read;
				break;
			default: // XXX_unrecognized
				// create a comma-separated string of each unrecognized item.
				if (!protobuf_decode_string(&in[pos], in_size - pos, (char**)&(item), &bytes_read))
					goto exit;
				count = 0;
				if ((*out)->XXX_unrecognized) {
					count = strlen((*out)->XXX_unrecognized);
					(*out)->XXX_unrecognized[count++] = ','; // null terminator is now a comma.
				}
				(*out)->XXX_unrecognized = realloc((*out)->XXX_unrecognized, count + bytes_read);
				if (!(*out)->XXX_unrecognized)
					goto exit;
				// append after the comma.
				memcpy((*out)->XXX_unrecognized+count, item, bytes_read);
				free(item);
				pos += bytes_read;
				break;
		}
	}

	retVal = 1;

exit:
	if (retVal == 0) {
		libp2p_identify_free(*out);
		*out = NULL;
	}
	return retVal;
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
		handler->context = NULL;
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
		out->bytes_waiting = NULL;
		// do we expect a reply?
		if (!libp2p_identify_send_protocol(parent_stream) /* || !libp2p_identify_receive_protocol(parent_stream) */) {
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
	struct Stream* multistream = libp2p_net_multistream_stream_new(parent_stream, 0);
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
