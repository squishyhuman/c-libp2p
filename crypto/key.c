#include <stdlib.h>
#include <string.h>

#include "libp2p/crypto/key.h"
#include "libp2p/crypto/sha256.h"
#include "libp2p/crypto/peerutils.h"
#include "protobuf.h"

/**
 * Utilities for public and private keys
 */

struct PublicKey* libp2p_crypto_public_key_new() {
	struct PublicKey* retVal = malloc(sizeof(struct PublicKey));
	if (retVal == NULL)
		return NULL;
	retVal->type = KEYTYPE_INVALID;
	retVal->data = NULL;
	retVal->data_size = 0;
	return retVal;
}

void libp2p_crypto_public_key_free(struct PublicKey* in) {
	if (in != NULL) {
		if (in->data != NULL)
			free(in->data);
		free(in);
		in = NULL;
	}
}

/**
 * Unmarshal a public key from a protobuf
 * @param buffer the protobuf
 * @param buffer_length the length of the protobuf
 * @param out the pointer to the struct PublicKey that will be allocated
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_public_key_protobuf_decode(unsigned char* buffer, size_t buffer_length, struct PublicKey** out) {

	// first field is type (RSA vs ED25519)
	// second field is the public key

	size_t pos = 0;
	int retVal = 0;

	if ( (*out = libp2p_crypto_public_key_new()) == NULL)
		goto exit;

	while(pos < buffer_length) {
		size_t bytes_read = 0;
		int field_no;
		enum WireType field_type;
		if (protobuf_decode_field_and_type(&buffer[pos], buffer_length, &field_no, &field_type, &bytes_read) == 0) {
			goto exit;
		}
		pos += bytes_read;
		switch(field_no) {
			case (1): // type
				if (protobuf_decode_varint(&buffer[pos], buffer_length - pos, (long long unsigned int*)&((*out)->type), &bytes_read) == 0)
					goto exit;
				pos += bytes_read;
				break;
			case (2): // key
				if (protobuf_decode_length_delimited(&buffer[pos], buffer_length - pos, (char**)&((*out)->data), &((*out)->data_size), &bytes_read) == 0)
					goto exit;
				pos += bytes_read;
				break;
		}
	}

	retVal = 1;

exit:
	if (retVal == 0) {
		libp2p_crypto_public_key_free(*out);
	}
	return retVal;
}

struct PrivateKey* libp2p_crypto_private_key_new() {
	struct PrivateKey* retVal = malloc(sizeof(struct PrivateKey));
	if (retVal == NULL)
		return NULL;
	retVal->type = KEYTYPE_INVALID;
	retVal->data = NULL;
	retVal->data_size = 0;
	return retVal;
}

void libp2p_crypto_private_key_free(struct PrivateKey* in) {
	if (in != NULL) {
		if (in->data != NULL)
			free(in->data);
		free(in);
		in = NULL;
	}
}

/**
 * Unmarshal a private key from a protobuf
 * @param buffer the protobuf
 * @param buffer_length the length of the protobuf
 * @param out the pointer to the struct PrivateKey that will be allocated
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_private_key_protobuf_decode(unsigned char* buffer, size_t buffer_length, struct PrivateKey** out) {

	// first field is type (RSA vs ED25519)
	// second field is the public key

	size_t pos = 0;
	int retVal = 0;

	if ( (*out = libp2p_crypto_private_key_new()) == NULL)
		goto exit;

	while(pos < buffer_length) {
		size_t bytes_read = 0;
		int field_no;
		enum WireType field_type;
		if (protobuf_decode_field_and_type(&buffer[pos], buffer_length, &field_no, &field_type, &bytes_read) == 0) {
			goto exit;
		}
		pos += bytes_read;
		switch(field_no) {
			case (1): // type
				if (protobuf_decode_varint(&buffer[pos], buffer_length - pos, (long long unsigned int*)&((*out)->type), &bytes_read) == 0)
					goto exit;
				pos += bytes_read;
				break;
			case (2): // key
				if (protobuf_decode_length_delimited(&buffer[pos], buffer_length - pos, (char**)&((*out)->data), &((*out)->data_size), &bytes_read) == 0)
					goto exit;
				pos += bytes_read;
				break;
		}
	}

	retVal = 1;

exit:
	if (retVal == 0) {
		libp2p_crypto_private_key_free(*out);
	}
	return retVal;
}

/**
 * convert a public key into a peer id
 * @param public_key the public key struct
 * @param peer_id the results, in a null-terminated string
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_public_key_to_peer_id(struct PublicKey* public_key, char** peer_id) {
	unsigned char hashed[32];
	libp2p_crypto_hashing_sha256(public_key->data, public_key->data_size, hashed);
	size_t final_id_size = 100;
	unsigned char final_id[final_id_size];
	memset(final_id, 0, final_id_size);
	if (!PrettyID(final_id, &final_id_size, hashed, 32))
		return 0;
	*peer_id = (char*)malloc(final_id_size + 1);
	if (*peer_id == NULL)
		return 0;
	memset(*peer_id, 0, final_id_size + 1);
	memcpy(*peer_id, final_id, final_id_size);
	return 1;
}

