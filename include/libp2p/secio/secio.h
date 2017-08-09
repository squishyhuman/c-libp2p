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
int libp2p_secio_handshake(struct SessionContext* session, struct RsaPrivateKey* private_key, struct Peerstore* peerstore, int remote_requested);
