#pragma once
#include "libp2p/yamux/yamux.h"
#include "libp2p/identify/identify.h"
#include "mock_stream.h"
#include "libp2p/utils/logger.h"

/***
 * Helpers
 */

/***
 * Sends back the yamux protocol to fake negotiation
 */
int mock_yamux_read_protocol(void* context, struct StreamMessage** msg, int network_timeout) {
	*msg = libp2p_stream_message_new();
	struct StreamMessage* message = *msg;
	const char* id = "/yamux/1.0.0\n";
	message->data_size = strlen(id);
	message->data = malloc(message->data_size);
	memcpy(message->data, id, message->data_size);
	return 1;
}

/***
 * Sends back the yamux protocol to fake negotiation
 */
int mock_identify_read_protocol(void* context, struct StreamMessage** msg, int network_timeout) {
	*msg = libp2p_stream_message_new();
	struct StreamMessage* message = *msg;
	const char* id = "/ipfs/id/1.0.0\n";
	message->data_size = strlen(id);
	message->data = malloc(message->data_size);
	memcpy(message->data, id, message->data_size);
	return 1;
}

/***
 * Tests
 */

/***
 * Verify that we can initiate a yamux session
 */
int test_yamux_stream_new() {
	int retVal = 0;
	// setup
	struct Stream* mock_stream = mock_stream_new();
	mock_stream->read = mock_yamux_read_protocol;
	struct Stream* yamux_stream = libp2p_yamux_stream_new(mock_stream);
	if (yamux_stream == NULL)
		goto exit;
	// tear down
	retVal = 1;
	exit:
	if (yamux_stream != NULL)
		yamux_stream->close(yamux_stream->stream_context);
	mock_stream->close(mock_stream->stream_context);
	return retVal;
}

/***
 * Attempt to add a protocol to the Yamux protocol
 */
int test_yamux_identify() {
	int retVal = 0;
	// setup
	struct Stream* mock_stream = mock_stream_new();
	mock_stream->read = mock_yamux_read_protocol;
	struct Stream* yamux_stream = libp2p_yamux_stream_new(mock_stream);
	if (yamux_stream == NULL)
		goto exit;
	// Now add in another protocol
	mock_stream->read = mock_identify_read_protocol;
	if (!libp2p_yamux_stream_add(yamux_stream->stream_context, libp2p_identify_stream_new(libp2p_yamux_channel_new(yamux_stream)))) {
		goto exit;
	}
	// tear down
	retVal = 1;
	exit:
	if (yamux_stream != NULL)
		yamux_stream->close(yamux_stream->stream_context);
	mock_stream->close(mock_stream->stream_context);
	return retVal;
}

int test_yamux_incoming_protocol_request() {
	int retVal = 0;
	// setup
	struct Stream* mock_stream = mock_stream_new();
	mock_stream->read = mock_yamux_read_protocol;
	struct Stream* yamux_stream = libp2p_yamux_stream_new(mock_stream);
	if (yamux_stream == NULL)
		goto exit;
	// build the protocol handler that can handle identify protocol
	struct Libp2pVector* protocol_handlers = libp2p_utils_vector_new(1);
	struct Libp2pProtocolHandler* handler = libp2p_identify_build_protocol_handler(protocol_handlers);
	libp2p_utils_vector_add(protocol_handlers, handler);
	struct SessionContext session_context;
	session_context.default_stream = yamux_stream;
	// Someone is requesting the identity protocol
	mock_stream->read = mock_identify_read_protocol;
	struct StreamMessage* result_message;
	if (!yamux_stream->read(yamux_stream->stream_context, &result_message, 10)) {
		libp2p_logger_error("test_yamux", "Unable to read identify protocol.\n");
		goto exit;
	}
	// handle the marshaling of the protocol
	libp2p_protocol_marshal(result_message, &session_context, protocol_handlers);
	// now verify the results
	struct YamuxContext* yamux_context = (struct YamuxContext*)yamux_stream->stream_context;
	if (yamux_context->channels->total != 1) {
		libp2p_logger_error("test_yamux", "Identify protocol was not found.\n");
		goto exit;
	}

	// tear down
	retVal = 1;
	exit:
	if (yamux_stream != NULL)
		yamux_stream->close(yamux_stream->stream_context);
	mock_stream->close(mock_stream->stream_context);
	return retVal;
}
