#pragma once

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

int libp2p_identify_can_handle(const struct StreamMessage* msg);
int libp2p_identify_send_protocol(struct SessionContext *context);
int libp2p_identify_receive_protocol(struct SessionContext* context);
int libp2p_identify_handle_message(const struct StreamMessage* msg, struct SessionContext* context, void* protocol_context);
int libp2p_identify_shutdown(void* protocol_context);
struct Libp2pProtocolHandler* libp2p_identify_build_protocol_handler(struct Libp2pVector* handlers);
