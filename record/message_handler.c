#include "libp2p/record/message.h"
#include "libp2p/peer/peer.h"

/**
 * A generic handler for different types of messages
 */


int libp2p_record_handler_ping(struct Libp2pPeer* peer, struct Libp2pMessage* message) {
	return 0;
}

int libp2p_record_message_handle(struct Libp2pPeer* peer, struct Libp2pMessage* message) {
	switch (message->message_type) {
	case (MESSAGE_TYPE_PING):
			return libp2p_record_handler_ping(peer, message);
	}
	return 0;
}
