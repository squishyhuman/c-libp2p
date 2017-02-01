#pragma once

#include "libp2p/crypto/key.h"

/**
 * A secure connection
 */

struct SecureSession {
	int socket_descriptor;
	struct PublicKey remote_key;
	int remote_peer_id;
};
