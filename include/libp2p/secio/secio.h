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
	// filled in during negotiations
	char* chosen_curve;
	char* chosen_cipher;
	char* chosen_hash;
	unsigned char* ephemeral_public_key; // bytes of x and y
	size_t ephemeral_public_key_size;
	unsigned char* shared_key; // a shared key based off of the ephemeral private key
	size_t shared_key_size;
	char nonce[16];
	struct StretchedKey* stretched_key;
};

/***
 * performs initial communication over an insecure channel to share
 * keys, IDs, and initiate connection. This is a framed messaging system
 * @param session the secure session to be filled
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_secio_handshake(struct SecureSession* session, struct RsaPrivateKey* private_key);
