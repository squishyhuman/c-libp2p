#pragma once

#include "libp2p/record/record.h"
#include "libp2p/crypto/rsa.h"

struct Libp2pRecord {
	// the key that references this record
	char* key;
	size_t key_size;
	// the actual value this record is storing
	unsigned char* value;
	size_t value_size;
	// hash of the author's public key
	char* author;
	size_t author_size;
	// a PKI signature for the key + value + author
	unsigned char* signature;
	size_t signature_size;
	// time the record was received, set by receiver
	char* time_received;
	size_t time_received_size;
};

/**
 * Create a record with default settings
 * @returns the newly allocated record struct
 */
struct Libp2pRecord* libp2p_record_new();

/**
 * Free the resources from a record struct
 * @param in the struct to free
 */
void libp2p_record_free(struct Libp2pRecord* in);

/**
 * Convert a Libp2pRecord into protobuf format
 * @param in the Libp2pRecord to convert
 * @param buffer where to store the protobuf
 * @param max_buffer_size the size of the allocated buffer
 * @param bytes_written the size written into buffer
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_record_protobuf_encode(const struct Libp2pRecord* in, unsigned char* buffer, size_t max_buffer_size, size_t* bytes_written);

/**
 * Convert a Libp2pRecord into protobuf format, allocating
 * memory as needed
 * @param in the Libp2pRecord to convert
 * @param buffer where to store the protobuf
 * @param buffer_size the size of the allocated buffer
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_record_protobuf_allocate_and_encode(const struct Libp2pRecord* in, unsigned char **buffer, size_t *buffer_size);

/**
 * Generates an estimate of the buffer size needed to encode the struct
 * @param in the Libp2pRecord that you want to encode
 * @returns the approximate number of bytes required
 */
size_t libp2p_record_protobuf_encode_size(const struct Libp2pRecord* in);

/**
 * Convert a protobuf byte array into a Libp2pRecord
 * @param in the byte array
 * @param in_size the size of the byte array
 * @param out a pointer to the new Libp2pRecord
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_record_protobuf_decode(const unsigned char* in, size_t in_size, struct Libp2pRecord** out);

/**
 * This method does all the hard stuff in one step. It fills a Libp2pRecord struct, and converts it into a protobuf
 * @param record a pointer to the protobuf results
 * @param rec_size the number of bytes used in the area pointed to by record
 * @param sk the private key used to sign
 * @param key the key in the Libp2pRecord
 * @param value the value in the Libp2pRecord
 * @param vlen the length of value
 * @param sign true if you want to sign the record
 * @returns 0 on success, -1 on error
 */
int libp2p_record_make_put_record (char** record, size_t *rec_size, const struct RsaPrivateKey* sk, const char* key, const char* value, size_t vlen, int sign);
