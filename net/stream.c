#include <stdlib.h>

#include "multiaddr/multiaddr.h"
#include "libp2p/net/stream.h"
#include "libp2p/net/connectionstream.h"

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
