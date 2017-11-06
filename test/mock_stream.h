#pragma once

#include <unistd.h>
#include "libp2p/net/stream.h"

struct MockContext {
	struct Stream* stream;
};

void mock_stream_free(struct Stream* stream);

int mock_stream_close(void* context) {
	if (context == NULL)
		return 1;
	struct MockContext* ctx = (struct MockContext*)context;
	mock_stream_free(ctx->stream);
	return 1;
}

int mock_stream_peek(void* context) {
	return 1;
}

int mock_stream_read(void* context, struct StreamMessage** msg, int timeout_secs) {
	return 1;
}

int mock_stream_read_raw(void* context, uint8_t* buffer, int buffer_size, int timeout_secs) {
	return 1;
}

int mock_stream_write(void* context, struct StreamMessage* msg) {
	return 1;
}

struct Stream* mock_stream_new() {
	struct Stream* out = libp2p_stream_new();
	if (out != NULL) {
		out->close = mock_stream_close;
		out->peek = mock_stream_peek;
		out->read = mock_stream_read;
		out->read_raw = mock_stream_read_raw;
		out->write = mock_stream_write;
		struct MockContext* ctx = malloc(sizeof(struct MockContext));
		ctx->stream = out;
		out->stream_context = ctx;
	}
	return out;
}

void mock_stream_free(struct Stream* stream) {
	if (stream == NULL)
		return;
	if (stream->stream_context != NULL)
		free(stream->stream_context);
	free(stream);
}
