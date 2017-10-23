#include <stdlib.h>

#include "libp2p/net/stream.h"

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
	}
	return stream;
}

void libp2p_stream_free(struct Stream* stream) {
	if (stream != NULL) {
		free(stream);
	}
}
