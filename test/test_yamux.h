#pragma once
#include "libp2p/yamux/yamux.h"
#include "libp2p/identify/identify.h"
#include "mock_stream.h"
#include "libp2p/utils/logger.h"
#include "libp2p/net/stream.h"
#include "libp2p/net/multistream.h"
#include "libp2p/net/server.h"

/***
 * Helpers
 */

struct StreamMessage* build_message(const char* data) {
	struct StreamMessage* out = libp2p_stream_message_new();
	if (out != NULL) {
		out->data_size = strlen(data);
		out->data = (uint8_t*) malloc(out->data_size);
		memcpy(out->data, data, out->data_size);
	}
	return out;
}
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
 * Sends back the identify protocol (in a yamux wrapper) to fake negotiation
 */
int mock_identify_read_protocol(void* context, struct StreamMessage** msg, int network_timeout) {
	struct StreamMessage message;
	const char* id = "/ipfs/id/1.0.0\n";
	message.data_size = strlen(id);
	message.data = (uint8_t*)id;

	*msg = libp2p_yamux_prepare_to_send(&message);
	// adjust the frame
	struct yamux_frame* frame = (struct yamux_frame*)(*msg)->data;
	frame->streamid = 1;
	frame->flags = yamux_frame_syn;
	encode_frame(frame);
	return 1;
}

/***
 * Sends back the identify protocol (in a yamux wrapper) to fake negotiation
 */
int mock_multistream_read_protocol(void* context, struct StreamMessage** msg, int network_timeout) {
	struct StreamMessage message;
	const char* id = "/multistream/1.0.0\n";
	message.data_size = strlen(id);
	message.data = (uint8_t*)id;

	*msg = libp2p_yamux_prepare_to_send(&message);
	// adjust the frame
	struct yamux_frame* frame = (struct yamux_frame*)(*msg)->data;
	frame->streamid = 1;
	frame->flags = yamux_frame_syn;
	encode_frame(frame);
	return 1;
}

int mock_counter = 0;

/***
 * Sends back the yamux protocol to fake negotiation
 */
int mock_multistream_then_identify_read_protocol(void* context, struct StreamMessage** msg, int network_timeout) {
	// prepare the message
	*msg = libp2p_stream_message_new();
	struct StreamMessage* message = *msg;
	message->data_size = mock_message->data_size - mock_message_position;
	message->data = malloc(message->data_size);
	memcpy(message->data, &mock_message->data[mock_message_position], message->data_size);
	if (mock_counter == 0) {
		// this is the first time through. Set mock_message to the identify protocol
		libp2p_stream_message_free(mock_message);
		mock_message = libp2p_net_multistream_prepare_to_send(build_message("/ipfs/id/1.0.0\n"));
		mock_message_position = 0;
	} else {
		libp2p_stream_message_free(mock_message);
		mock_message = NULL;
		mock_message_position = 0;
	}
	return (*msg != NULL);
}


/***
 * Tests
 */

/***
 * Verify that we can initiate a yamux session
 */
int test_yamux_stream_new() {
	int retVal = 0;
	const char* yamux_id = "/yamux/1.0.0\n";
	// setup
	struct Stream* mock_stream = mock_stream_new();
	mock_message = build_message(yamux_id);
	struct Stream* yamux_stream = libp2p_yamux_stream_new(mock_stream, 0, NULL);
	if (yamux_stream == NULL)
		goto exit;
	// tear down
	retVal = 1;
	exit:
	if (yamux_stream != NULL)
		yamux_stream->close(yamux_stream);
	if (mock_message != NULL)
		libp2p_stream_message_free(mock_message);
	return retVal;
}

/***
 * Attempt to add a protocol to the Yamux protocol
 */
int test_yamux_identify() {
	int retVal = 0;
	// setup
	// mock
	struct Stream* mock_stream = mock_stream_new();
	mock_stream->read = mock_yamux_read_protocol;
	// protocol handlers
	struct Libp2pVector* protocol_handlers = libp2p_utils_vector_new(1);
	struct Libp2pProtocolHandler* handler = libp2p_identify_build_protocol_handler(protocol_handlers);
	libp2p_utils_vector_add(protocol_handlers, handler);
	// yamux
	struct Stream* yamux_stream = libp2p_yamux_stream_new(mock_stream, 0, protocol_handlers);
	if (yamux_stream == NULL)
		goto exit;
	// Now add in another protocol
	mock_stream->read = mock_identify_read_protocol;
	if (!libp2p_yamux_stream_add(yamux_stream->stream_context, libp2p_identify_stream_new(yamux_stream))) {
		goto exit;
	}
	// tear down
	retVal = 1;
	exit:
	if (yamux_stream != NULL)
		yamux_stream->close(yamux_stream);
	libp2p_protocol_handlers_shutdown(protocol_handlers);
	if (mock_message != NULL) {
		libp2p_stream_message_free(mock_message);
		mock_message = NULL;
	}
	return retVal;
}

/***
 * Attempt to add a protocol to the Yamux protocol
 */
/*
int test_yamux_multistream() {
	int retVal = 0;
	// setup
	// mock
	struct Stream* mock_stream = mock_stream_new();
	mock_stream->read = mock_yamux_read_protocol;
	// protocol handlers
	struct Libp2pVector* protocol_handlers = libp2p_utils_vector_new(1);
	struct Libp2pProtocolHandler* handler = libp2p_identify_build_protocol_handler(protocol_handlers);
	libp2p_utils_vector_add(protocol_handlers, handler);
	// yamux
	struct Stream* yamux_stream = libp2p_yamux_stream_new(mock_stream, 0, protocol_handlers);
	if (yamux_stream == NULL)
		goto exit;
	// Now add in another protocol
	mock_stream->read = mock_multistream_read_protocol;
	if (!libp2p_yamux_stream_add(yamux_stream->stream_context, libp2p_multistream_stream_new(yamux_stream))) {
		goto exit;
	}
	// tear down
	retVal = 1;
	exit:
	if (yamux_stream != NULL)
		yamux_stream->close(yamux_stream);
	libp2p_protocol_handlers_shutdown(protocol_handlers);
	if (mock_message != NULL) {
		libp2p_stream_message_free(mock_message);
		mock_message = NULL;
	}
	return retVal;
}
*/

int test_yamux_incoming_protocol_request() {
	int retVal = 0;

	// setup
	// build the protocol handler that can handle yamux, multistream, and identify protocol
	struct Libp2pVector* protocol_handlers = libp2p_utils_vector_new(1);
	struct Libp2pProtocolHandler* handler = libp2p_identify_build_protocol_handler(protocol_handlers);
	libp2p_utils_vector_add(protocol_handlers, handler);
	handler = libp2p_yamux_build_protocol_handler(protocol_handlers);
	libp2p_utils_vector_add(protocol_handlers, handler);
	handler = libp2p_net_multistream_build_protocol_handler(protocol_handlers);
	libp2p_utils_vector_add(protocol_handlers, handler);
	// set up basic streams
	struct Stream* mock_stream = mock_stream_new();
	struct SessionContext* session_context = ((struct ConnectionContext*)mock_stream->stream_context)->session_context;
	mock_message = build_message("/yamux/1.0.0\n");
	struct StreamMessage* result_message = NULL;
	if (!session_context->default_stream->read(session_context->default_stream->stream_context, &result_message, 10)) {
		libp2p_logger_error("test_yamux", "Unable to read Yamux protocol from mock stream.\n");
		goto exit;
	}
	if (libp2p_protocol_marshal(result_message, session_context->default_stream, protocol_handlers) < 0) {
		libp2p_logger_error("test_yamux", "Upgrade to Yamux protocol unsuccessful.\n");
		goto exit;
	}
	// now we should have upgraded to the yamux protocol
	libp2p_stream_message_free(result_message);
	result_message = NULL;
	if (session_context->default_stream->parent_stream == NULL) {
		libp2p_logger_error("test_yamux", "Upgrade to Yamux protocol appeared susccessful, but was not.\n");
		goto exit;
	}
	// Someone is requesting the multistream protocol
	libp2p_stream_message_free(mock_message);
	mock_message = libp2p_yamux_prepare_to_send(libp2p_net_multistream_prepare_to_send(build_message("/multistream/1.0.0\n")));
	// act like this is new
	struct yamux_frame* frame = (struct yamux_frame*)mock_message->data;
	frame->streamid = (uint32_t)1;
	frame->flags = yamux_frame_syn;
	encode_frame(frame);
	mock_stream->read = mock_stream_read;
	if (!session_context->default_stream->read(session_context->default_stream->stream_context, &result_message, 10)) {
		libp2p_logger_error("test_yamux", "Unable to read multistream protocol.\n");
		goto exit;
	}
	// handle the marshaling of the multistream protocol
	libp2p_protocol_marshal(result_message, session_context->default_stream, protocol_handlers);
	libp2p_stream_message_free(result_message);
	result_message = NULL;
	// now verify the results
	if (session_context->default_stream->stream_type != STREAM_TYPE_YAMUX) {
		libp2p_logger_error("test_yamux", "Expected stream type of %d, but received %d.\n", STREAM_TYPE_YAMUX, session_context->default_stream->stream_type);
		goto exit;
	}
	struct YamuxContext* yamux_context = (struct YamuxContext*)session_context->default_stream->stream_context;
	if (yamux_context->channels->total != 2) {
		libp2p_logger_error("test_yamux", "Identify protocol was not found.\n");
		goto exit;
	}

	// tear down
	retVal = 1;
	exit:
	if (session_context->default_stream != NULL)
		session_context->default_stream->close(session_context->default_stream);
	libp2p_protocol_handlers_shutdown(protocol_handlers);
	return retVal;
}

/**
 * Attempt to negotiate the identity protocol, then use it.
 * This makes sure the framing is working correctly betwee identity
 * and yamux
 */
int test_yamux_identity_frame() {
	int retVal = 0;

	// setup
	// build the protocol handler that can handle yamux and identify protocol
	struct Libp2pVector* protocol_handlers = libp2p_utils_vector_new(1);
	struct Libp2pProtocolHandler* handler = libp2p_identify_build_protocol_handler(protocol_handlers);
	libp2p_utils_vector_add(protocol_handlers, handler);
	handler = libp2p_yamux_build_protocol_handler(protocol_handlers);
	libp2p_utils_vector_add(protocol_handlers, handler);
	struct Stream* mock_stream = mock_stream_new();
	struct SessionContext* session_context = ((struct ConnectionContext*)mock_stream->stream_context)->session_context;
	mock_stream->read = mock_yamux_read_protocol;
	struct StreamMessage* result_message = NULL;
	if (!session_context->default_stream->read(session_context->default_stream->stream_context, &result_message, 10)) {
		libp2p_logger_error("test_yamux", "Unable to read Yamux protocol from mock stream.\n");
		goto exit;
	}
	if (libp2p_protocol_marshal(result_message, session_context->default_stream, protocol_handlers) < 0) {
		libp2p_logger_error("test_yamux", "Upgrade to Yamux protocol unsuccessful.\n");
		goto exit;
	}
	// now we should have upgraded to the yamux protocol
	libp2p_stream_message_free(result_message);
	result_message = NULL;
	if (session_context->default_stream->parent_stream == NULL) {
		libp2p_logger_error("test_yamux", "Upgrade to Yamux protocol appeared susccessful, but was not.\n");
		goto exit;
	}
	// Someone is requesting the identity protocol
	mock_stream->read = mock_multistream_then_identify_read_protocol;
	if (!session_context->default_stream->read(session_context->default_stream->stream_context, &result_message, 10)) {
		libp2p_logger_error("test_yamux", "Unable to read identify protocol.\n");
		goto exit;
	}
	// handle the marshaling of the protocol
	libp2p_protocol_marshal(result_message, session_context->default_stream, protocol_handlers);
	libp2p_stream_message_free(result_message);
	result_message = NULL;
	// now verify the results
	struct YamuxContext* yamux_context = (struct YamuxContext*)session_context->default_stream->stream_context;
	if (yamux_context->channels->total != 2) {
		libp2p_logger_error("test_yamux", "Identify protocol was not found.\n");
		goto exit;
	}

	// prepare a yamux frame that is an identity message

	// send the message

	// tear down
	retVal = 1;
	exit:
	if (session_context->default_stream != NULL)
		session_context->default_stream->close(session_context->default_stream);
	libp2p_protocol_handlers_shutdown(protocol_handlers);
	return retVal;

}

int test_yamux_client_server_connect() {
	int retVal = 0;
	struct Libp2pVector* protocol_handlers = NULL;
	struct StreamMessage* resultMessage = NULL;

	//libp2p_logger_add_class("connectionstream");

	// setup
	// build the protocol handler that can handle yamux
	protocol_handlers = libp2p_utils_vector_new(1);
	struct Libp2pProtocolHandler* handler = libp2p_yamux_build_protocol_handler(protocol_handlers);
	libp2p_utils_vector_add(protocol_handlers, handler);
	// set up server
	libp2p_net_server_start("127.0.0.1", 1234, protocol_handlers);
	sleep(1);
	// set up client (easiest to use transport dialers)
	struct Dialer* dialer = libp2p_conn_dialer_new(NULL, NULL, NULL, NULL);
	struct MultiAddress* server_ma = multiaddress_new_from_string("/ip4/127.0.0.1/tcp/1234");
	struct Stream* stream = libp2p_conn_dialer_get_connection(dialer, server_ma);
	if (stream == NULL) {
		fprintf(stderr, "Unable to get stream.\n");
		goto exit;
	}
	// have client attempt to connect to server and negotiate yamux
	struct Stream* yamux_stream  = libp2p_yamux_stream_new(stream, 0, protocol_handlers);
	if (yamux_stream == NULL) {
		fprintf(stderr, "Was supposed to get yamux protocol id, but instead received nothing.\n");
		goto exit;
	}
	//TODO: make sure everything is negotiated and yamux is in a happy state
	// hangup
	yamux_stream->close(yamux_stream);
	// for debugging
	// sleep(30);
	retVal = 1;
	exit:
	libp2p_net_server_stop();
	if (protocol_handlers != NULL) {

	}
	return retVal;

}

int test_yamux_client_server_multistream() {
	int retVal = 0;
	struct Libp2pVector* protocol_handlers = NULL;
	struct StreamMessage* resultMessage = NULL;

	libp2p_logger_add_class("connectionstream");
	libp2p_logger_add_class("multistream");
	libp2p_logger_add_class("yamux");

	// setup
	// build the protocol handler that can handle yamux
	protocol_handlers = libp2p_utils_vector_new(1);
	struct Libp2pProtocolHandler* handler = libp2p_yamux_build_protocol_handler(protocol_handlers);
	libp2p_utils_vector_add(protocol_handlers, handler);
	handler = libp2p_net_multistream_build_protocol_handler(protocol_handlers);
	libp2p_utils_vector_add(protocol_handlers, handler);
	// set up server
	libp2p_net_server_start("127.0.0.1", 1234, protocol_handlers);
	sleep(1);
	// set up client (easiest to use transport dialers)
	struct Dialer* dialer = libp2p_conn_dialer_new(NULL, NULL, NULL, NULL);
	struct MultiAddress* server_ma = multiaddress_new_from_string("/ip4/127.0.0.1/tcp/1234");
	struct Stream* stream = libp2p_conn_dialer_get_connection(dialer, server_ma);
	if (stream == NULL) {
		fprintf(stderr, "Unable to get stream.\n");
		goto exit;
	}
	// have client attempt to connect to server and negotiate yamux
	struct Stream* yamux_stream  = libp2p_yamux_stream_new(stream, 0, protocol_handlers);
	if (yamux_stream == NULL) {
		fprintf(stderr, "Was supposed to get yamux protocol id, but instead received nothing.\n");
		goto exit;
	}
	// now attempt multistream
	struct Stream* multistream = libp2p_net_multistream_stream_new(yamux_stream, 0);
	if (multistream == NULL) {
		fprintf(stderr, "Was supposed to get a multistream, but instead got NULL.\n");
		goto exit;
	}
	// shut down nicely
	multistream->close(multistream);
	retVal = 1;
	exit:
	libp2p_net_server_stop();
	if (protocol_handlers != NULL) {

	}
	return retVal;

}

int test_yamux_multistream_server() {
	int retVal = 0;
	struct Libp2pVector* protocol_handlers = NULL;
	struct StreamMessage* resultMessage = NULL;

	libp2p_logger_add_class("connectionstream");
	libp2p_logger_add_class("multistream");
	libp2p_logger_add_class("yamux");

	// setup
	// build the protocol handler that can handle yamux
	protocol_handlers = libp2p_utils_vector_new(1);
	struct Libp2pProtocolHandler* handler = libp2p_yamux_build_protocol_handler(protocol_handlers);
	libp2p_utils_vector_add(protocol_handlers, handler);
	handler = libp2p_net_multistream_build_protocol_handler(protocol_handlers);
	libp2p_utils_vector_add(protocol_handlers, handler);
	// set up server
	libp2p_net_server_start("127.0.0.1", 1234, protocol_handlers);
	// debugging
	sleep(120);
	retVal = 1;
	exit:
	libp2p_net_server_stop();
	if (protocol_handlers != NULL) {

	}
	return retVal;

}
int test_yamux_multistream_client() {
	int retVal = 0;
	struct Libp2pVector* protocol_handlers = NULL;
	struct StreamMessage* resultMessage = NULL;

	libp2p_logger_add_class("connectionstream");
	libp2p_logger_add_class("multistream");
	libp2p_logger_add_class("yamux");

	// setup
	// build the protocol handler that can handle yamux
	protocol_handlers = libp2p_utils_vector_new(1);
	struct Libp2pProtocolHandler* handler = libp2p_yamux_build_protocol_handler(protocol_handlers);
	libp2p_utils_vector_add(protocol_handlers, handler);
	handler = libp2p_net_multistream_build_protocol_handler(protocol_handlers);
	libp2p_utils_vector_add(protocol_handlers, handler);
	// set up client (easiest to use transport dialers)
	struct Dialer* dialer = libp2p_conn_dialer_new(NULL, NULL, NULL, NULL);
	struct MultiAddress* server_ma = multiaddress_new_from_string("/ip4/127.0.0.1/tcp/1234");
	struct Stream* stream = libp2p_conn_dialer_get_connection(dialer, server_ma);
	if (stream == NULL) {
		fprintf(stderr, "Unable to get stream.\n");
		goto exit;
	}
	// have client attempt to connect to server and negotiate yamux
	struct Stream* yamux_stream  = libp2p_yamux_stream_new(stream, 0, protocol_handlers);
	if (yamux_stream == NULL) {
		fprintf(stderr, "Was supposed to get yamux protocol id, but instead received nothing.\n");
		goto exit;
	}
	// now attempt multistream
	struct Stream* multistream = libp2p_net_multistream_stream_new(yamux_stream, 0);
	if (multistream == NULL) {
		fprintf(stderr, "Was supposed to get a multistream, but instead got NULL.\n");
		goto exit;
	}
	// shut down nicely
	multistream->close(multistream);
	// debugging
	sleep(30);
	retVal = 1;
	exit:
	if (protocol_handlers != NULL) {

	}
	return retVal;

}
