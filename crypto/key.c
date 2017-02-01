#include <stdio.h>

/**
 * Utilities for public keys
 */

enum KeyType { KEYTYPE_RSA, KEYTYPE_ED25519, KEYTYPE_INVALID };

struct PublicKey {
	enum KeyType key_type;
	char* raw_key;
	size_t raw_key_size;
};

struct PublicKey* libp2p_crypto_public_key_new() {
	struct PublicKey* retVal = malloc(sizeof(struct PublicKey));
	if (retVal == NULL)
		return NULL;
	retVal->key_type = KEYTYPE_INVALID;
	retVal->raw_key = NULL;
	retVal->raw_key_size = 0;
	return retVal;
}

void libp2p_crypto_public_key_free(struct PublicKey* in) {
	if (in != NULL) {
		if (in->raw_key != NULL)
			free(in->raw_key);
		free(in);
		in = NULL;
	}
}

/**
 * Unmarshal a public key from a protobuf
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
				if (protobuf_decode_varint(&buffer[pos], buffer_length - pos, &((*out)->key_type), &bytes_read) == 0)
					goto exit;
				pos += bytes_read;
				break;
			case (2): // key
				if (protobuf_decode_length_delimited(&buffer[pos], buffer_length - pos, (char**)&((*out)->raw_key), &((*out)->raw_key_size), &bytes_read) == 0)
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
