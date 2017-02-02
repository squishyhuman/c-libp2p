#pragma once

#include "libp2p/crypto/key.h"
#include "libp2p/crypto/rsa.h"

/**
 * A secure connection
 */

enum IPTrafficType { TCP, UDP };

struct SecureSession {
	// to get the connection started
	char* host;
	int port;
	enum IPTrafficType traffic_type;
	// once the connection is established
	int socket_descriptor;
	struct PublicKey remote_key;
	char* remote_peer_id;
};

/***
 * performs initial communication over an insecure channel to share
 * keys, IDs, and initiate connection. This is a framed messaging system
 * @param session the secure session to be filled
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_secio_handshake(struct SecureSession* session, struct RsaPrivateKey* private_key);
