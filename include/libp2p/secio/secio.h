#pragma once

#include "libp2p/crypto/key.h"
#include "libp2p/crypto/rsa.h"
#include "libp2p/conn/session.h"
#include "libp2p/peer/peerstore.h"
#include "libp2p/net/protocol.h"

/**
 * Handling of a secure connection
 */

struct SecioContext {
	struct Stream* stream;
	struct SessionContext* session_context;
	struct RsaPrivateKey* private_key;
	struct Peerstore* peer_store;
};

struct Libp2pProtocolHandler* libp2p_secio_build_protocol_handler(struct RsaPrivateKey* private_key, struct Peerstore* peer_store);

/***
 * performs initial communication over an insecure channel to share
 * keys, IDs, and initiate connection. This is a framed messaging system
 * @param ctx the SecioContext
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_secio_handshake(struct SecioContext* ctx);

/***
 * Initiates a secio handshake. Use this method when you want to initiate a secio
 * session. This should not be used to respond to incoming secio requests
 * @param ctx the SecioContext
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_secio_initiate_handshake(struct SecioContext* ctx);

/***
 * Send the protocol string to the remote stream
 * @param session the context
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_secio_send_protocol(struct SecioContext* session);
/***
 * Attempt to read the secio protocol as a reply from the remote
 * @param session the context
 * @returns true(1) if we received what we think we should have, false(0) otherwise
 */
int libp2p_secio_receive_protocol(struct SecioContext* session);
