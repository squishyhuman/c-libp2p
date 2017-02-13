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

/***
 * Calculates an approximate required size of a buffer for protobuf encoding a public key
 * @param in the public key to examine
 * @returns the size in bytes
 */
size_t libp2p_crypto_public_key_protobuf_encode_size(const struct PublicKey* in) {
	return 11 + 11 + in->data_size;
}

/***
 * Encode a PublicKey into a protobuf
 * @param in the struct PublicKey
 * @param buffer where to put the results
 * @param max_buffer_length the size of the buffer
 * @param bytes_written how many bytes were used in the buffer
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_public_key_protobuf_encode(const struct PublicKey* in, unsigned char* buffer, size_t max_buffer_length, size_t* bytes_written) {
	// data & data_size
	size_t bytes_used = 0;
	*bytes_written = 0;
	int retVal = 0;
	// key type (RSA vs ...)
	retVal = protobuf_encode_varint(1, WIRETYPE_VARINT, in->type, &buffer[*bytes_written], max_buffer_length - *bytes_written, &bytes_used);
	*bytes_written += bytes_used;
	// public key
	retVal = protobuf_encode_length_delimited(2, WIRETYPE_LENGTH_DELIMITED, in->data, in->data_size, &buffer[*bytes_written], max_buffer_length - *bytes_written, &bytes_used);
	if (retVal == 0)
		return 0;
	*bytes_written += bytes_used;
	return 1;
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

int libp2p_crypto_private_key_copy(const struct PrivateKey* source, struct PrivateKey* destination) {
	if (source != NULL && destination != NULL) {
		destination->type = source->type;
		destination->data = (unsigned char*)malloc(source->data_size);
		if (destination->data != NULL) {
			memcpy(destination->data, source->data, source->data_size);
			destination->data_size = source->data_size;
			return 1;
		}
		libp2p_crypto_private_key_free(destination);
	}
	return 0;
}

size_t libp2p_crypto_private_key_protobuf_encode_size(const struct PrivateKey* in) {
	return 22 + in->data_size;
}

int libp2p_crypto_private_key_protobuf_encode(const struct PrivateKey* in, unsigned char* buffer, size_t max_buffer_length, size_t* bytes_written) {
	*bytes_written = 0;
	size_t bytes_used;
	// type (RSA vs ED25519)
	if (!protobuf_encode_varint(1, WIRETYPE_VARINT, in->type, &buffer[*bytes_written], max_buffer_length - *bytes_written, &bytes_used))
		return 0;
	*bytes_written += bytes_used;
	// private key
	if (!protobuf_encode_length_delimited(2, WIRETYPE_LENGTH_DELIMITED, in->data, in->data_size, &buffer[*bytes_written], max_buffer_length - *bytes_written, &bytes_used))
		return 0;
	*bytes_written += bytes_used;
	return 1;
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

	/**
	 * Converting to a peer id involves protobufing the struct PublicKey, SHA256 it, turn it into a MultiHash and base58 it
	 */
	size_t protobuf_len = libp2p_crypto_public_key_protobuf_encode_size(public_key);
	unsigned char protobuf[protobuf_len];

	libp2p_crypto_public_key_protobuf_encode(public_key, protobuf, protobuf_len, &protobuf_len);

	unsigned char hashed[32];
	//libp2p_crypto_hashing_sha256(public_key->data, public_key->data_size, hashed);
	libp2p_crypto_hashing_sha256(protobuf, protobuf_len, hashed);
	size_t final_id_size = 100;
	unsigned char final_id[final_id_size];
	memset(final_id, 0, final_id_size);
	// turn it into a multihash and base58 it
	if (!PrettyID(final_id, &final_id_size, hashed, 32))
		return 0;
	*peer_id = (char*)malloc(final_id_size + 1);
	if (*peer_id == NULL)
		return 0;
	memset(*peer_id, 0, final_id_size + 1);
	memcpy(*peer_id, final_id, final_id_size);
	return 1;
}

