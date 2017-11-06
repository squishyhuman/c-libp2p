#pragma once

#include "libp2p/utils/vector.h"

typedef struct {
        // publicKey is this node's public key (which also gives its node.ID)
        // - may not need to be sent, as secure channel implies it has been sent.
        // - then again, if we change / disable secure channel, may still want it.
        char *PublicKey;
        // listenAddrs are the multiaddrs the sender node listens for open connections on
        char **ListenAddrs;
        // protocols are the services this node is running
        char **Protocols;
        // oservedAddr is the multiaddr of the remote endpoint that the sender node perceives
        // this is useful information to convey to the other side, as it helps the remote endpoint
        // determine whether its connection to the local peer goes through NAT.
        char *ObservedAddr;
        // protocolVersion determines compatibility between peers
        char *ProtocolVersion;
        // agentVersion is like a UserAgent string in browsers, or client version in bittorrent
        // includes the client name and client.
        char *AgentVersion;
        char *XXX_unrecognized;
} Identify;

struct IdentifyContext {
	struct Stream* parent_stream;
	struct Stream* stream;
};

int libp2p_identify_can_handle(const struct StreamMessage* msg);
int libp2p_identify_send_protocol(struct IdentifyContext *context);
int libp2p_identify_receive_protocol(struct IdentifyContext* context);
int libp2p_identify_handle_message(const struct StreamMessage* msg, struct SessionContext* context, void* protocol_context);
int libp2p_identify_shutdown(void* protocol_context);
struct Libp2pProtocolHandler* libp2p_identify_build_protocol_handler(struct Libp2pVector* handlers);

/***
 * Create a new stream that negotiates the identify protocol
 *
 * NOTE: This will be sent by our side (us asking them).
 * Incoming "Identify" requests should be handled by the
 * external protocol handler, not this function.
 *
 * @param parent_stream the parent stream
 * @returns a new Stream that can talk "identify"
 */
struct Stream* libp2p_identify_stream_new(struct Stream* parent_stream);

