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
 * Initiates a secio handshake. Use this method when you want to initiate a secio
 * session. This should not be used to respond to incoming secio requests
 * @param parent_stream the parent stream
 * @param remote_peer the remote peer
 * @param peerstore the peerstore
 * @param rsa_private_key the local private key
 * @returns a Secio Stream
 */
struct Stream* libp2p_secio_stream_new(struct Stream* parent_stream, struct Libp2pPeer* remote_peer, struct Peerstore* peerstore, struct RsaPrivateKey* rsa_private_key);

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

/***
 * performs initial communication over an insecure channel to share
 * keys, IDs, and initiate connection. This is a framed messaging system
 * NOTE: session must contain a valid socket_descriptor that is a multistream.
 * @param local_session the secure session to be filled
 * @param private_key our private key to use
 * @param peerstore the collection of peers
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_secio_handshake(struct SecioContext* secio_context);

