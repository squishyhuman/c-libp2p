#pragma once

#include "libp2p/crypto/key.h"
#include "libp2p/crypto/rsa.h"
#include "libp2p/conn/session.h"

/**
 * Handling of a secure connection
 */


/***
 * performs initial communication over an insecure channel to share
 * keys, IDs, and initiate connection. This is a framed messaging system
 * @param session the secure session to be filled
 * @param private_key the local private key to use
 * @param remote_requested the other side is who asked for the upgrade
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_secio_handshake(struct SessionContext* session, struct RsaPrivateKey* private_key, int remote_requested);
