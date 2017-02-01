#pragma once

/**
 * Utilities for public keys
 */

enum KeyType { KEYTYPE_RSA, KEYTYPE_ED25519, KEYTYPE_INVALID };

struct PublicKey {
	enum KeyType type;
	unsigned char* data;
	size_t data_size;
};

struct PrivateKey {
	enum KeyType type;
	unsigned char* data;
	size_t data_size;
};

struct PublicKey* libp2p_crypto_public_key_new();

void libp2p_crypto_public_key_free(struct PublicKey* in);

/**
 * Unmarshal a public key from a protobuf
 */
int libp2p_crypto_public_key_protobuf_decode(unsigned char* buffer, size_t buffer_length, struct PublicKey** out);
int libp2p_crypto_private_key_protobuf_decode(unsigned char* buffer, size_t buffer_length, struct PublicKey** out);
