#include <string.h>

#include "varint.h"
#include "libp2p/net/protocol.h"
#include "libp2p/net/protocol.h"
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
int libp2p_identify_send_protocol(struct SessionContext *context) {
	char *protocol = "/ipfs/id/1.0.0\n";
	struct StreamMessage msg;
	msg.data = (uint8_t*) protocol;
	msg.data_size = strlen(protocol);
	if (!context->default_stream->write(context, &msg)) {
		libp2p_logger_error("identify", "send_protocol: Unable to send identify protocol header.\n");
		return 0;
	}
	return 1;
}

/***
 * Check to see if the reply is the identify header we expect
 * NOTE: if we initiate the connection, we should expect the same back
 * @param context the SessionContext
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_identify_receive_protocol(struct SessionContext* context) {
	const char *protocol = "/ipfs/id/1.0.0\n";
	struct StreamMessage* results = NULL;
	if (!context->default_stream->read(context, &results, 30)) {
		libp2p_logger_error("identify", "receive_protocol: Unable to read results.\n");
		return 0;
	}
	// the first byte is the size, so skip it
	char* ptr = strstr((char*)&results[1], protocol);
	if (ptr == NULL || ptr - (char*)results > 1) {
		return 0;
	}
	return 1;
}

int libp2p_identify_handle_message(const struct StreamMessage* msg, struct SessionContext* context, void* protocol_context) {
	//TODO: Implement
	return 0;
}

/**
 * Shutting down. Clean up any memory allocations
 * @param protocol_context the context
 * @returns true(1)
 */
int libp2p_identify_shutdown(void* protocol_context) {
        return 0;
}

struct Libp2pProtocolHandler* libp2p_identify_build_protocol_handler(struct Libp2pVector* handlers) {
	struct Libp2pProtocolHandler* handler = libp2p_protocol_handler_new();
	if (handler != NULL) {
		handler->context = handlers;
		handler->CanHandle = libp2p_identify_can_handle;
		handler->HandleMessage = libp2p_identify_handle_message;
		handler->Shutdown = libp2p_identify_shutdown;
	}
	return handler;
}
