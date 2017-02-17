#include <string.h>
#include <stdlib.h>

#include "libp2p/crypto/rsa.h"
#include "libp2p/crypto/sha256.h"
#include "libp2p/record/record.h"
#include "protobuf.h"
#include "mh/hashes.h"
#include "mh/multihash.h"

/**
 * Convert a Libp2pRecord into protobuf format
 * @param in the Libp2pRecord to convert
 * @param buffer where to store the protobuf
 * @param max_buffer_size the size of the allocated buffer
 * @param bytes_written the size written into buffer
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_record_protobuf_encode(const struct Libp2pRecord* in, unsigned char* buffer, size_t max_buffer_size, size_t* bytes_written) {
	// data & data_size
	size_t bytes_used = 0;
	*bytes_written = 0;
	int retVal = 0;
	// field 1
	retVal = protobuf_encode_length_delimited(1, WIRETYPE_LENGTH_DELIMITED, in->key, in->key_size, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
	if (retVal == 0)
		return 0;
	*bytes_written += bytes_used;
	// field 2
	retVal = protobuf_encode_length_delimited(2, WIRETYPE_LENGTH_DELIMITED, in->value, in->value_size, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
	if (retVal == 0)
		return 0;
	*bytes_written += bytes_used;
	// field 3
	retVal = protobuf_encode_length_delimited(3, WIRETYPE_LENGTH_DELIMITED, in->author, in->author_size, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
	if (retVal == 0)
		return 0;
	*bytes_written += bytes_used;
	// field 4
	retVal = protobuf_encode_length_delimited(4, WIRETYPE_LENGTH_DELIMITED, in->signature, in->signature_size, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
	if (retVal == 0)
		return 0;
	*bytes_written += bytes_used;
	// field 5
	retVal = protobuf_encode_length_delimited(5, WIRETYPE_LENGTH_DELIMITED, in->time_received, in->time_received_size, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
	if (retVal == 0)
		return 0;
	*bytes_written += bytes_used;
	return 1;
}

/**
 * Generates an estimate of the buffer size needed to encode the struct
 * @param in the Libp2pRecord that you want to encode
 * @returns the approximate number of bytes required
 */
size_t libp2p_record_protobuf_encode_size(const struct Libp2pRecord* in) {
	size_t retVal = 11 + in->key_size;
	retVal += 11 + in->value_size;
	retVal += 11 + in->author_size;
	retVal += 11 + in->signature_size;
	retVal += 11 + in->time_received_size;
	return retVal;
}

/**
 * Convert a protobuf byte array into a Libp2pRecord
 * @param in the byte array
 * @param in_size the size of the byte array
 * @param out a pointer to the new Libp2pRecord
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_record_protobuf_decode(const unsigned char* in, size_t in_size, struct Libp2pRecord** out) {
	size_t pos = 0;
	int retVal = 0;

	if ( (*out = (struct Libp2pRecord*)malloc(sizeof(struct Libp2pRecord))) == NULL)
		goto exit;

	while(pos < in_size) {
		size_t bytes_read = 0;
		int field_no;
		enum WireType field_type;
		if (protobuf_decode_field_and_type(&in[pos], in_size, &field_no, &field_type, &bytes_read) == 0) {
			goto exit;
		}
		pos += bytes_read;
		switch(field_no) {
			case (1): // key
				if (protobuf_decode_length_delimited(&in[pos], in_size - pos, (char**)&((*out)->key),&((*out)->key_size), &bytes_read) == 0)
					goto exit;
				pos += bytes_read;
				break;
			case (2): // value
				if (protobuf_decode_length_delimited(&in[pos], in_size - pos, (char**)&((*out)->value), &((*out)->value_size), &bytes_read) == 0)
					goto exit;
				pos += bytes_read;
				break;
			case (3): // author
				if (protobuf_decode_length_delimited(&in[pos], in_size - pos, (char**)&((*out)->author), &((*out)->author_size), &bytes_read) == 0)
					goto exit;
				pos += bytes_read;
				break;
			case (4): // signature
				if (protobuf_decode_length_delimited(&in[pos], in_size - pos, (char**)&((*out)->signature), &((*out)->signature_size), &bytes_read) == 0)
					goto exit;
				pos += bytes_read;
				break;
			case (5): // time
				if (protobuf_decode_length_delimited(&in[pos], in_size - pos, (char**)&((*out)->time_received), &((*out)->time_received_size), &bytes_read) == 0)
					goto exit;
				pos += bytes_read;
				break;
		}
	}

	retVal = 1;

exit:
	if (retVal == 0) {
		free(*out);
		*out = NULL;
	}
	return retVal;
}



/**
 * This method does all the hard stuff in one step. It fills a Libp2pRecord struct, and converts it into a protobuf
 * @param record a pointer to the protobuf results
 * @param rec_size the number of bytes used in the area pointed to by record
 * @param sk the private key used to sign
 * @param key the key in the Libp2pRecord
 * @param value the value in the Libp2pRecord
 * @param vlen the length of value
 * @param sign true(1) if you want to sign the data
 * @returns 0 on success, otherwise -1
 */
int libp2p_record_make_put_record (char** record_buf, size_t *rec_size, const struct RsaPrivateKey* sk, const char* key, const char* value, size_t vlen, int sign)
{
	int retVal = -1;
	size_t bytes_size = 0;
	unsigned char* bytes = NULL;
	unsigned char* sign_buf = NULL;
	unsigned char hash[32];

    // build the struct
    struct Libp2pRecord record;
    record.key = (char*)key;
    record.key_size = strlen(key);
    record.value = (char*)value;
    record.value_size = vlen;

    // clear the rest of the fields
    record.signature = NULL;
    record.signature_size = 0;
    //TODO: what should we put in the time field?
    record.time_received = NULL;
    record.time_received_size = 0;

    // build a hash of the author's public key
    libp2p_crypto_hashing_sha256(sk->public_key_der, sk->public_key_length, &hash[0]);
    record.author = &hash[0];
    record.author_size = 32;

	bytes_size = record.key_size + record.value_size + record.author_size;
	bytes = malloc(bytes_size);
	if (bytes == NULL)
		goto exit;

    // build the signature
    if (sign) {
    	memcpy(&bytes[0], record.key, record.key_size);
    	memcpy(&bytes[record.key_size], record.value, record.value_size);
    	memcpy(&bytes[record.key_size + record.value_size], record.author, record.author_size);
        size_t sign_length = 0;
        if (!libp2p_crypto_rsa_sign ((struct RsaPrivateKey*)sk, bytes, bytes_size, &sign_buf, &sign_length))
        	goto exit;
        record.signature = bytes;
        record.signature_size = bytes_size;
    }

    // now protobuf the struct
    size_t protobuf_size = libp2p_record_protobuf_encode_size(&record);
    *record_buf = malloc(protobuf_size);
    if (*record_buf == NULL)
    	goto exit;

    if (!libp2p_record_protobuf_encode(&record, *record_buf, protobuf_size, &protobuf_size))
    	goto exit;

    // we're done here. Cleanup time.
    retVal = 0;

    exit:

	if (bytes != NULL)
		free(bytes);
	if (sign_buf != NULL)
		free(sign_buf);
	if (retVal = -1) {
		free(*record_buf);
		*record_buf = NULL;
	}

    return retVal;
}
