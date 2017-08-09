#pragma once

#include "libp2p/crypto/key.h"
#include "libp2p/crypto/rsa.h"
#include "libp2p/conn/session.h"
#include "libp2p/peer/peerstore.h"
#include "libp2p/net/protocol.h"

/**
 * Handling of a secure connection
 */


struct Libp2pProtocolHandler* libp2p_secio_build_protocol_handler(struct RsaPrivateKey* private_key, struct Peerstore* peer_store);

/***
 * performs initial communication over an insecure channel to share
 * keys, IDs, and initiate connection. This is a framed messaging system
 * @param session the secure session to be filled
 * @param private_key the local private key to use
 * @param remote_requested the other side is who asked for the upgrade
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_secio_handshake(struct SessionContext* session, struct RsaPrivateKey* private_key, struct Peerstore* peerstore);

/***
 * Initiates a secio handshake. Use this method when you want to initiate a secio
 * session. This should not be used to respond to incoming secio requests
 * @param session_context the session context
 * @param private_key the RSA private key to use
 * @param peer_store the peer store
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_secio_initiate_handshake(struct SessionContext* session_context, struct RsaPrivateKey* private_key, struct Peerstore* peer_store);
