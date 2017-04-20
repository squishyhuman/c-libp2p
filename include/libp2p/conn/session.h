#pragma once

#include "libp2p/crypto/key.h"
#include "libp2p/db/datastore.h"
#include "libp2p/db/filestore.h"

/***
 * Holds the details of communication between two hosts
 */

enum IPTrafficType { TCP, UDP };

struct SessionContext {
	// to get the connection started
	char* host;
	int port;
	enum IPTrafficType traffic_type;
	// once the connection is established
	struct Stream* insecure_stream;
	struct Stream* secure_stream;
	struct Stream* default_stream;
	struct Datastore* datastore;
	struct Filestore* filestore;
	// filled in during negotiations
	char* chosen_curve;
	char* chosen_cipher;
	char* chosen_hash;
	unsigned char* shared_key; // a shared key based off of the ephemeral private key
	size_t shared_key_size;
	unsigned char* mac;
	size_t mac_size;
	/**
	 * The mac function to use
	 * @param 1 the incoming data bytes
	 * @param 2 the size of the incoming array
	 * @param 3 the results. Must be allocated to correct size (or larger)
	 * @returns true(1) on success, false(0) otherwise
	 */
	int (*mac_function)(const unsigned char*, size_t, unsigned char*);
	// local only stuff
	char local_nonce[16];
	struct EphemeralPrivateKey* ephemeral_private_key;
	struct StretchedKey* local_stretched_key;
	// remote stuff
	char remote_nonce[16];
	struct PublicKey remote_key;
	char* remote_peer_id;
	struct StretchedKey* remote_stretched_key;
	unsigned char* remote_ephemeral_public_key;
	size_t remote_ephemeral_public_key_size;
};
