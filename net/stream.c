#include <stdlib.h>

#include "multiaddr/multiaddr.h"
#include "libp2p/net/stream.h"
#include "libp2p/net/connectionstream.h"
#include "libp2p/yamux/yamux.h"

int libp2p_stream_default_handle_upgrade(struct Stream* parent_stream, struct Stream* new_stream) {
	return libp2p_net_connection_upgrade(parent_stream, new_stream);
}

struct Stream* libp2p_stream_new() {
	struct Stream* stream = (struct Stream*) malloc(sizeof(struct Stream));
	if (stream != NULL) {
		stream->address = NULL;
		stream->close = NULL;
		stream->parent_stream = NULL;
		stream->peek = NULL;
		stream->read = NULL;
		stream->read_raw = NULL;
		stream->socket_mutex = NULL;
		stream->stream_context = NULL;
		stream->write = NULL;
		stream->handle_upgrade = libp2p_stream_default_handle_upgrade;
		stream->channel = -1;
	}
	return stream;
}

void libp2p_stream_free(struct Stream* stream) {
	if (stream != NULL) {
		if (stream->socket_mutex != NULL) {
			free(stream->socket_mutex);
			stream->socket_mutex = NULL;
		}
		if (stream->address != NULL) {
			multiaddress_free(stream->address);
			stream->address = NULL;
		}
		free(stream);
	}
}

int libp2p_stream_is_open(struct Stream* stream) {
	if (stream == NULL)
		return 0;

	struct Stream* base_stream = stream;
	while (base_stream->parent_stream != NULL)
		base_stream = base_stream->parent_stream;
	if (base_stream->stream_type == STREAM_TYPE_RAW) {
		struct ConnectionContext* ctx = (struct ConnectionContext*)base_stream->stream_context;
		if (ctx->socket_descriptor > 0)
			return 1;
	}
	return 0;
}

// forward declaration
struct YamuxChannelContext* libp2p_yamux_get_channel_context(void* stream_context);

/**
 * Look for the latest stream
 * (properly handles both raw streams and yamux streams)
 * @param in the incoming stream
 * @returns the latest child stream
 */
struct Stream* libp2p_stream_get_latest_stream(struct Stream* in) {
	if (in == NULL)
		return NULL;
	if (in->stream_type == STREAM_TYPE_RAW) {
		struct ConnectionContext* ctx = (struct ConnectionContext*)in->stream_context;
		return ctx->session_context->default_stream;
	} else if (in->stream_type == STREAM_TYPE_YAMUX) {
		struct YamuxChannelContext* ctx = libp2p_yamux_get_channel_context(in->stream_context);
		if (ctx != NULL)
			return ctx->child_stream;
	}
	return libp2p_stream_get_latest_stream(in->parent_stream);
}
