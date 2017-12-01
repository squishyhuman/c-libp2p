#include <stdlib.h>
#include <string.h>
#include "libp2p/utils/logger.h"
#include "libp2p/net/protocol.h"

/*
 * Handle the different protocols
 */


/***
 * Compare incoming to see if they are requesting a protocol upgrade
 * @param incoming the incoming string
 * @param incoming_size the size of the incoming string
 * @param test the protocol string to compare it with (i.e. "/secio" or "/nodeio"
 * @returns true(1) if there was a match, false(0) otherwise
 */
const struct Libp2pProtocolHandler* protocol_compare(struct StreamMessage* msg, struct Libp2pVector* protocol_handlers) {
	if (protocol_handlers != NULL) {
		for(int i = 0; i < protocol_handlers->total; i++) {
			const struct Libp2pProtocolHandler* handler = (const struct Libp2pProtocolHandler*) libp2p_utils_vector_get(protocol_handlers, i);
			if (handler->CanHandle(msg)) {
				return handler;
			}
		}
	}
	return NULL;
}

/***
 * Retrieve the correct protocol handlder for a particular protocol id
 * @param protocol_handlers the collection of protocol handlers
 * @param id the protocol id
 * @returns a protocol handler that can handle id (or NULL if none found)
 */
const struct Libp2pProtocolHandler* libp2p_protocol_get_handler(struct Libp2pVector* protocol_handlers, const char* id) {
	struct StreamMessage message;
	message.data_size = strlen(id);
	message.data = (uint8_t*)id;
	return protocol_compare(&message, protocol_handlers);
}

/**
 * Allocate resources for a new Libp2pProtocolHandler
 * @returns an allocated struct
 */
struct Libp2pProtocolHandler* libp2p_protocol_handler_new() {
	struct Libp2pProtocolHandler* h = (struct Libp2pProtocolHandler*) malloc(sizeof(struct Libp2pProtocolHandler));
	if (h != NULL) {
		h->CanHandle = NULL;
		h->HandleMessage = NULL;
		h->Shutdown = NULL;
		h->context = NULL;
	}
	return h;
}

/***
 * Release resources of a protocol handler
 * @param handler the handler to free
 */
void libp2p_protocol_handler_free(struct Libp2pProtocolHandler* handler) {
	if (handler != NULL)
		free(handler);
}

int appears_to_be_a_protocol(struct StreamMessage* msg) {
	if (msg == NULL)
		return 0;
	if (msg->data_size < 2)
		return 0;
	if (memchr(&msg->data[1], '\n', msg->data_size-1) != NULL)
		return 1;
	return 0;
}

/***
 * Handle an incoming message
 * @param message the incoming message
 * @param stream the stream the message came in on
 * @param handlers a Vector of protocol handlers
 * @returns -1 on error, 0 if everything was okay, but the daemon should no longer handle this connection, 1 on success
 */
int libp2p_protocol_marshal(struct StreamMessage* msg, struct Stream* stream, struct Libp2pVector* handlers) {
	const struct Libp2pProtocolHandler* handler = protocol_compare(msg, handlers);

	if (handler == NULL) {
		if (appears_to_be_a_protocol(msg)) {
			struct StreamMessage na_message;
			na_message.data = (uint8_t*)"na\n";
			na_message.data_size = 3;
			stream->write(stream->stream_context, &na_message);
		}
		// set the msg->error code
		msg->error_number = 100;
		return -1;
	}

	return handler->HandleMessage(msg, stream, handler->context);
}

/***
 * Check to see if this is a valid protocol
 * @param msg the message
 * @param handlers the vector of handlers
 */
int libp2p_protocol_is_valid_protocol(struct StreamMessage* msg, struct Libp2pVector* handlers) {
	if (protocol_compare(msg, handlers) == NULL)
		return 0;
	return 1;
}

/***
 * Shut down all protocol handlers and free vector
 * @param handlers vector of Libp2pProtocolHandler
 * @returns true(1)
 */
int libp2p_protocol_handlers_shutdown(struct Libp2pVector* handlers) {
	for(int i = 0; i < handlers->total; i++) {
		struct Libp2pProtocolHandler* handler = (struct Libp2pProtocolHandler*)libp2p_utils_vector_get(handlers, i);
		handler->Shutdown(handler->context);
	}
	libp2p_utils_vector_free(handlers);
	return 1;
}
