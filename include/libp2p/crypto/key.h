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

struct PrivateKey* libp2p_crypto_private_key_new();
void libp2p_crypto_private_key_free(struct PrivateKey* in);
int libp2p_crypto_private_key_copy(const struct PrivateKey* source, struct PrivateKey* destination);

/**
 * Unmarshal a public key from a protobuf
 */
int libp2p_crypto_public_key_protobuf_decode(unsigned char* buffer, size_t buffer_length, struct PublicKey** out);
size_t libp2p_crypto_public_key_protobuf_encode_size(const struct PublicKey* in);
int libp2p_crypto_public_key_protobuf_encode(const struct PublicKey* in, unsigned char* buffer, size_t max_buffer_length, size_t* bytes_written);
// private key
int libp2p_crypto_private_key_protobuf_decode(unsigned char* buffer, size_t buffer_length, struct PrivateKey** out);
size_t libp2p_crypto_private_key_protobuf_encode_size(const struct PrivateKey* in);
int libp2p_crypto_private_key_protobuf_encode(const struct PrivateKey* in, unsigned char* buffer, size_t max_buffer_length, size_t* bytes_written);

/**
 * convert a public key into a peer id
 * @param public_key the public key struct
 * @param peer_id the results, in a null-terminated string
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_public_key_to_peer_id(struct PublicKey* public_key, char** peer_id);
