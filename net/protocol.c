#include <stdlib.h>
#include "libp2p/net/protocol.h"

/***
 * Compare incoming to see if they are requesting a protocol upgrade
 * @param incoming the incoming string
 * @param incoming_size the size of the incoming string
 * @param test the protocol string to compare it with (i.e. "/secio" or "/nodeio"
 * @returns true(1) if there was a match, false(0) otherwise
 */
const struct Libp2pProtocolHandler* protocol_compare(const unsigned char* incoming, size_t incoming_size, struct Libp2pVector* protocol_handlers) {
	for(int i = 0; i < protocol_handlers->total; i++) {
		const struct Libp2pProtocolHandler* handler = (const struct Libp2pProtocolHandler*) libp2p_utils_vector_get(protocol_handlers, i);
		if (handler->CanHandle(incoming, incoming_size)) {
			return handler;
		}
	}
	return NULL;
}

int libp2p_protocol_marshal(const unsigned char* incoming, size_t incoming_size, struct SessionContext* session, struct Libp2pVector* handlers) {
	const struct Libp2pProtocolHandler* handler = protocol_compare(incoming, incoming_size, handlers);
	if (handler != NULL) {
		return handler->HandleMessage(incoming, incoming_size, session, handler->context);
	}
	return 0;
}
