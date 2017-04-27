#include <stdlib.h>
#include <stdio.h> // for debugging, can remove
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <arpa/inet.h>
#include <endian.h>
#include <stdarg.h>

#include "libp2p/secio/secio.h"
#include "libp2p/secio/propose.h"
#include "libp2p/secio/exchange.h"
#include "libp2p/net/multistream.h"
#include "libp2p/net/p2pnet.h"
#include "libp2p/crypto/ephemeral.h"
#include "libp2p/crypto/sha1.h"
#include "libp2p/crypto/sha256.h"
#include "libp2p/crypto/sha512.h"
#include "libp2p/utils/string_list.h"
#include "libp2p/utils/vector.h"
#include "libp2p/utils/logger.h"
#include "mbedtls/md.h"
#include "mbedtls/cipher.h"
#include "mbedtls/md_internal.h"

const char* SupportedExchanges = "P-256,P-384,P-521";
const char* SupportedCiphers = "AES-256,AES-128,Blowfish";
const char* SupportedHashes = "SHA256,SHA512";

/***
 * Create a new SecureSession struct
 * @returns a pointer to a new SecureSession object
 */
struct SessionContext* libp2p_secio_secure_session_new() {
	struct SessionContext* ss = (struct SessionContext*) malloc(sizeof(struct SessionContext));
	if (ss == NULL)
		return NULL;
	ss->insecure_stream = NULL;
	ss->secure_stream = NULL;
	return ss;
}

/***
 * Clean up resources from a SecureSession struct
 * @param in the SecureSession to be deallocated
 */
void libp2p_secio_secure_session_free(struct SessionContext* in) {
	//TODO:  should we close the socket?
	free(in);
}

/**
 * Generate a random nonce
 * @param results where to put the results
 * @param length the length of the nonce
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_secio_generate_nonce(char* results, int length) {
	FILE* fd = fopen("/dev/urandom", "r");
	fread(results, 1, length, fd);
	fclose(fd);
	return 1;
}

/**
 * Compute a hash based on a Propose struct
 * @param in the struct Propose
 * @param result where to put the result (should be char[32])
 * @returns true(1) on success
 */
int libp2p_secio_hash(unsigned char* key, size_t key_size, unsigned char* nonce, size_t nonce_size, unsigned char result[32]) {
	// append public key and nonce
	mbedtls_sha256_context ctx;
	libp2p_crypto_hashing_sha256_init(&ctx);
	libp2p_crypto_hashing_sha256_update(&ctx, key, key_size);
	libp2p_crypto_hashing_sha256_update(&ctx, nonce, nonce_size);
	libp2p_crypto_hashing_sha256_finish(&ctx, result);
	libp2p_crypto_hashing_sha256_free(&ctx);
	return 1;
}

/***
 * Compare 2 hashes lexicographically
 * @param a the a side
 * @param b the b side
 * @param length the length of a and b
 * @returns a -1, 0, or 1
 */
int libp2p_secio_bytes_compare(const char* a, const char* b, int length) {
	for(int i = 0; i < length; i++) {
		if (b[i] > a[i])
			return -1;
		if (a[i] > b[i])
			return 1;
	}
	return 0;
}

int libp2p_secio_string_allocate(char* in, char** out) {
	*out = (char*)malloc(strlen(in) + 1);
	strcpy(*out, in);
	return 1;
}

struct StringList* libp2p_secio_split_list(const char* list, int list_size) {
	struct StringList* head = NULL;
	struct StringList* last = NULL;
	struct StringList* current = NULL;
	char* curr_tok = NULL;

	// make a copy
	char copy[list_size+1];
	memcpy(&copy[0], list, list_size);
	copy[list_size] = 0;

	curr_tok = strtok(copy, ",");
	while (curr_tok != NULL) {
		current = libp2p_utils_string_list_new();
		libp2p_secio_string_allocate(curr_tok, &current->string);
		if ( head == NULL) {
			head = current;
			last = current;
		} else {
			last->next = current;
		}
		last = current;
		curr_tok = strtok(NULL, ",");
	}
	return head;
}

/**
 * Compare 2 lists, and pick the best one
 * @param order which carries more weight
 * @param local_list the list to compare
 * @param local_list_size the size of the list
 * @param remote_list the list to compare
 * @param remote_list_size the size of the list
 * @param results where to put the results (NOTE: Allocate memory for this)
 * @returns true(1) on success, otherwise, false(0)
 */
int libp2p_secio_select_best(int order, const char* local_list, int local_list_size, const char* remote_list, int remote_list_size, char** results) {
	struct StringList* lead_head = libp2p_secio_split_list(local_list, local_list_size);
	struct StringList* follower_head = NULL;
	struct StringList* lead = NULL;
	struct StringList* follower = NULL;
	int match = 0;

	//shortcut
	if (order == 0)
	{
		libp2p_secio_string_allocate(lead_head->string, results);
		match = 1;
		goto exit;
	}

	// this list doesn't match. Do further investigation
	if (order > 0) { // lead is local
		follower_head = libp2p_secio_split_list(remote_list, remote_list_size);
	} else {
		follower_head = lead_head;
		lead_head = libp2p_secio_split_list(remote_list, remote_list_size);
	}

	lead = lead_head;
	follower = follower_head;
	// now work through the list, looking for a match
	while ( lead != NULL ) {
		while (follower != NULL) {
			if (strcmp(lead->string, follower->string) == 0) {
				libp2p_secio_string_allocate(lead->string, results);
				match = 1;
				break;
			}
			follower = follower->next;
		}
		if (match)
			break;
		follower = follower_head;
		lead = lead->next;
	}
	exit:
	if (lead_head != NULL)
		libp2p_utils_string_list_free(lead_head);
	if (follower_head != NULL)
		libp2p_utils_string_list_free(follower_head);
	return match;
}

/**
 * Check to see if the signature is correct based on the given bytes in "in"
 * @param public_key the public key to use
 * @param in the bytes that were signed
 * @param in_length the number of bytes
 * @param signature the signature that was given to us
 * @param signature_length the length of the signature
 * @returns true(1) if the signature is correct, false(0) otherwise
 */
int libp2p_secio_verify_signature(struct PublicKey* public_key, const unsigned char* in, size_t in_length, unsigned char* signature) {
	if (public_key->type == KEYTYPE_RSA) {
		struct RsaPublicKey rsa_key = {0};
		rsa_key.der = (char*)public_key->data;
		rsa_key.der_length = public_key->data_size;
		return libp2p_crypto_rsa_verify(&rsa_key, in, in_length, signature);
	}
	// TODO: Implement this method for non-RSA
	return 0;
}

/**
 * Sign data
 * @param private_key the key to use
 * @param in the bytes to sign
 * @param in_length the number of bytes
 * @param signature the result
 * @param signature_size the size of the result
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_secio_sign(struct PrivateKey* private_key, const char* in, size_t in_length, unsigned char** signature, size_t* signature_size) {
	if (private_key->type == KEYTYPE_RSA) {
		struct RsaPrivateKey rsa_key = {0};
		rsa_key.der = (char*)private_key->data;
		rsa_key.der_length = private_key->data_size;
		return libp2p_crypto_rsa_sign(&rsa_key, in, in_length, signature, signature_size);
	}
	// TODO: Implement this method for non-RSA
	return 0;
}

/**
 * Generate 2 keys by stretching the secret key
 * @param cipherType the cipher type (i.e. "AES-128")
 * @param hashType the hash type (i.e. "SHA256")
 * @param secret the secret key
 * @param secret_size the length of the secret key
 * @param k1 one of the resultant keys
 * @param k2 one of the resultant keys
 * @returns true(1) on success, otherwise 0 (false)
 */
int libp2p_secio_stretch_keys(char* cipherType, char* hashType, unsigned char* secret, size_t secret_size, struct StretchedKey** k1_ptr, struct StretchedKey** k2_ptr) {
	int retVal = 0, num_filled = 0, hmac_size = 20;
	struct StretchedKey* k1;
	struct StretchedKey* k2;
	unsigned char* result = NULL;;
	size_t result_size = 0;
	char* seed = "key expansion";
	unsigned char* temp = NULL;
	unsigned char a_hash[32];
	unsigned char b_hash[32];

	k1 = libp2p_crypto_ephemeral_stretched_key_new();
	if (k1 == NULL)
		goto exit;
	k2 = libp2p_crypto_ephemeral_stretched_key_new();
	if (k2_ptr == NULL)
		goto exit;

	// pick the right cipher
	if (strcmp(cipherType, "AES-128") == 0) {
		k1->iv_size = 16;
		k2->iv_size = 16;
		k1->cipher_size = 16;
		k2->cipher_size = 16;
	} else if (strcmp(cipherType, "AES-256") == 0) {
		k1->iv_size = 16;
		k2->iv_size = 16;
		k1->cipher_size = 32;
		k2->cipher_size = 32;
	} else if (strcmp(cipherType, "Blowfish") == 0) {
		k1->iv_size = 8;
		k2->iv_size = 8;
		k1->cipher_size = 32;
		k2->cipher_size = 32;
	} else {
		goto exit;
	}
	// pick the right hash
	// TODO: this
	/*
	if (strcmp(hashType, "SHA1") == 0) {
		hash_func = libp2p_crypto_hashing_sha1;
		hash_size = 40;
	} else if (strcmp(hashType, "SHA256") == 0) {
		hash_func = libp2p_crypto_hashing_sha256;
		hash_size = 32;
	} else if (strcmp(hashType, "SHA512") == 0) {
		hash_func = libp2p_crypto_hashing_sha512;
		hash_size = 64;
	} else {
		goto exit;
	}
	*/

	//TODO: make this work for all hashes, not just SHA256

	result_size = 2 * (k1->iv_size + k1->cipher_size * hmac_size);
	result = malloc(result_size);
	if (result == NULL)
		goto exit;

	mbedtls_md_context_t ctx;
	mbedtls_md_setup(&ctx, &mbedtls_sha256_info, 1);
	mbedtls_md_hmac_starts(&ctx, secret, secret_size);
	mbedtls_md_hmac_update(&ctx, (unsigned char*)seed, strlen(seed));
	mbedtls_md_hmac_finish(&ctx, a_hash);

	// now we have our first hash. Begin to fill the result buffer
	while (num_filled < result_size) {
		mbedtls_md_hmac_reset(&ctx);
		mbedtls_md_hmac_update(&ctx, a_hash, 32);
		mbedtls_md_hmac_update(&ctx, (unsigned char*)seed, strlen(seed));
		mbedtls_md_hmac_finish(&ctx, b_hash);

		int todo = 32;

		if (todo + num_filled > result_size)
			todo = result_size - num_filled;

		memcpy(&result[num_filled], b_hash, todo);
		num_filled += todo;

		mbedtls_md_hmac_reset(&ctx);
		mbedtls_md_hmac_update(&ctx, a_hash, 32);
		mbedtls_md_hmac_finish(&ctx, a_hash);
	}
	mbedtls_md_free(&ctx);

	// now we have a big result. Cut it up into pieces
	if (temp != NULL)
		free(temp);
	temp = result;
	k1->mac_size = hmac_size;
	k1->iv = malloc(k1->iv_size);
	memcpy(k1->iv, temp, k1->iv_size);
	temp += k1->iv_size;
	k1->cipher_key = malloc(k1->cipher_size);
	memcpy(k1->cipher_key, temp, k1->cipher_size);
	temp += k1->cipher_size;
	k1->mac_key = malloc(k1->mac_size);
	memcpy(k1->mac_key, temp, k1->mac_size);
	temp += k1->mac_size;

	k2->mac_size = hmac_size;
	k2->iv = malloc(k2->iv_size);
	memcpy(k2->iv, temp, k2->iv_size);
	temp += k2->iv_size;
	k2->cipher_key = malloc(k2->cipher_size);
	memcpy(k2->cipher_key, temp, k2->cipher_size);
	temp += k2->cipher_size;
	k2->mac_key = malloc(k2->mac_size);
	memcpy(k2->mac_key, temp, k2->mac_size);
	temp += k2->mac_size;

	temp = NULL;

	retVal = 1;

	// cleanup
	exit:
	*k1_ptr = k1;
	*k2_ptr = k2;
	if (retVal != 1) {
		if (*k1_ptr != NULL)
			libp2p_crypto_ephemeral_stretched_key_free(*k1_ptr);
		if (*k2_ptr != NULL)
			libp2p_crypto_ephemeral_stretched_key_free(*k2_ptr);
		*k1_ptr = NULL;
		*k2_ptr = NULL;
	}
	if (temp != NULL)
		free(temp);
	if (result != NULL)
		free(result);
	return retVal;
}

int libp2p_secio_make_mac_and_cipher(struct SessionContext* session, struct StretchedKey* stretched_key) {
	// mac
	if (strcmp(session->chosen_hash, "SHA1") == 0) {
		stretched_key->mac_size = 40;
	} else if (strcmp(session->chosen_hash, "SHA512") == 0) {
		stretched_key->mac_size = 64;
	} else if (strcmp(session->chosen_hash, "SHA256") == 0) {
		//stretched_key->mac_size = 32;
	} else {
		return 0;
	}
	//TODO: Research this question..
	// this was already made during the key stretch. Why make it again?
	/*
	stretched_key->mac_key = malloc(stretched_key->mac_size);
	session->mac_function(stretched_key->cipher_key, stretched_key->cipher_size, stretched_key->mac_key);
	*/

	// block cipher
	if (strcmp(session->chosen_cipher, "AES-128") || strcmp(session->chosen_cipher, "AES-256") == 0) {
		//we already have the key
	} else if (strcmp(session->chosen_cipher, "Blowfish") == 0) {
		//TODO: Implement blowfish
		return 0;
	} else {
		return 0;
	}

	//TODO: set up the encrypted streams
	return 1;
}

/***
 * Write bytes to an unencrypted stream
 * @param session the session information
 * @param bytes the bytes to write
 * @param data_length the number of bytes to write
 * @returns the number of bytes written
 */
int libp2p_secio_unencrypted_write(struct SessionContext* session, unsigned char* bytes, size_t data_length) {
	int num_bytes = 0;

	if (data_length > 0) { // only do this is if there is something to send
		// first send the size
		uint32_t size = htonl(data_length);
		char* size_as_char = (char*)&size;
		int left = 4;
		int written = 0;
		int written_this_time = 0;
		do {
			written_this_time = socket_write(*((int*)session->insecure_stream->socket_descriptor), &size_as_char[written], left, 0);
			if (written_this_time < 0) {
				written_this_time = 0;
				if ( (errno == EAGAIN) || (errno == EWOULDBLOCK)) {
					// TODO: use epoll or select to wait for socket to be writable
				} else {
					return 0;
				}
			}
			left = left - written_this_time;
		} while (left > 0);
		// then send the actual data
		left = data_length;
		written = 0;
		do {
			written_this_time = socket_write(*((int*)session->insecure_stream->socket_descriptor), (char*)&bytes[written], left, 0);
			if (written_this_time < 0) {
				written_this_time = 0;
				if ( (errno == EAGAIN) || (errno == EWOULDBLOCK)) {
					// TODO: use epoll or select to wait for socket to be writable
				} else {
					return 0;
				}
			}
			left = left - written_this_time;
			written += written_this_time;
		} while (left > 0);
		num_bytes = written;
	} // there was something to send

	return num_bytes;
}

/***
 * Read bytes from the incoming stream
 * @param session the session information
 * @param results where to put the bytes read
 * @param results_size the size of the results
 * @returns the number of bytes read
 */
int libp2p_secio_unencrypted_read(struct SessionContext* session, unsigned char** results, size_t* results_size, int timeout_secs) {
	uint32_t buffer_size;

	// first read the 4 byte integer
	char* size = (char*)&buffer_size;
	int left = 4;
	int read = 0;
	int read_this_time = 0;
	do {
		read_this_time = socket_read(*((int*)session->insecure_stream->socket_descriptor), &size[read], 1, 0, timeout_secs);
		if (read_this_time < 0) {
			read_this_time = 0;
			if ( (errno == EAGAIN) || (errno == EWOULDBLOCK)) {
				// TODO: use epoll or select to wait for socket to be writable
			} else {
				fprintf(stderr, "Error in libp2p_secio_unencrypted_read: %s\n", strerror(errno));
				return 0;
			}
		}
		if (read == 0 && size[0] == 10) {
			// a spurious \n
			// write over this value by not adding it
		} else {
			left = left - read_this_time;
			read += read_this_time;
		}
	} while (left > 0);
	buffer_size = ntohl(buffer_size);
	if (buffer_size == 0)
		return 0;

	// now read the number of bytes we've found, minus the 4 that we just read
	left = buffer_size;
	read = 0;
	read_this_time = 0;
	*results = malloc(left);
	unsigned char* ptr = *results;
	do {
		read_this_time = socket_read(*((int*)session->insecure_stream->socket_descriptor), (char*)&ptr[read], left, 0, timeout_secs);
		if (read_this_time < 0) {
			read_this_time = 0;
			if ( (errno == EAGAIN) || (errno == EWOULDBLOCK)) {
				// TODO: use epoll or select to wait for socket to be writable
			} else {
				return 0;
			}
		}
		left = left - read_this_time;
	} while (left > 0);

	*results_size = buffer_size;
	return buffer_size;
}

/**
 * Encrypt data before being sent out an insecure stream
 * @param session the session information
 * @param incoming the incoming data
 * @param incoming_size the size of the incoming data
 * @param outgoing where to put the results
 * @param outgoing_size the amount of memory allocated
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_secio_encrypt(const struct SessionContext* session, const unsigned char* incoming, size_t incoming_size, unsigned char** outgoing, size_t* outgoing_size) {
	unsigned char* buffer = NULL;
	size_t buffer_size = 0, original_buffer_size = 0;

	//TODO switch between ciphers
	mbedtls_cipher_context_t cipher_ctx;
	mbedtls_cipher_init(&cipher_ctx);
	mbedtls_cipher_setup(&cipher_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CTR));
	mbedtls_cipher_setkey(&cipher_ctx, session->local_stretched_key->cipher_key, session->local_stretched_key->cipher_size * 8, MBEDTLS_ENCRYPT);
	original_buffer_size = incoming_size;
	original_buffer_size += 32;
	buffer_size = original_buffer_size;
	buffer = malloc(original_buffer_size);
	memset(buffer, 0, original_buffer_size);
	mbedtls_cipher_crypt(&cipher_ctx, session->local_stretched_key->iv, session->local_stretched_key->iv_size, incoming, incoming_size, buffer, &buffer_size);
	// Now, buffer size may be set differently than original_buffer_size
	// The "incoming" is now encrypted, and is in the first part of the buffer
	mbedtls_cipher_free(&cipher_ctx);

	// mac the data
	mbedtls_md_context_t ctx;
	mbedtls_md_setup(&ctx, &mbedtls_sha256_info, 1);
	mbedtls_md_hmac_starts(&ctx, session->local_stretched_key->mac_key, session->local_stretched_key->mac_size);
	mbedtls_md_hmac_update(&ctx, buffer, buffer_size);
	// this will tack the mac onto the end of the buffer
	mbedtls_md_hmac_finish(&ctx, &buffer[buffer_size]);
	mbedtls_md_free(&ctx);

	// put it all in outgoing
	*outgoing_size = original_buffer_size;
	*outgoing = malloc(*outgoing_size);
	memset(*outgoing, 0, *outgoing_size);
	memcpy(*outgoing, buffer, original_buffer_size);

	free(buffer);
	return 1;
}

/**
 * Write to an encrypted stream
 * @param session the session parameters
 * @param bytes the bytes to write
 * @param num_bytes the number of bytes to write
 * @returns the number of bytes written
 */
int libp2p_secio_encrypted_write(void* stream_context, const unsigned char* bytes, size_t num_bytes) {
	struct SessionContext* session = (struct SessionContext*) stream_context;
	// writer uses the local cipher and mac
	unsigned char* buffer = NULL;
	size_t buffer_size = 0;
	if (!libp2p_secio_encrypt(session, bytes, num_bytes, &buffer, &buffer_size))
		return 0;
	int retVal = libp2p_secio_unencrypted_write(session, buffer, buffer_size);
	free(buffer);
	return retVal;
}

/**
 * Unencrypt data that was read from the stream
 * @param session the session information
 * @param incoming the incoming bytes
 * @param incoming_size the number of incoming bytes
 * @param outgoing where to put the results
 * @param outgoing_size the amount of memory allocated for the results
 * @returns number of unencrypted bytes
 */
int libp2p_secio_decrypt(const struct SessionContext* session, const unsigned char* incoming, size_t incoming_size, unsigned char** outgoing, size_t* outgoing_size) {
	size_t data_section_size = incoming_size - 32;
	*outgoing_size = 0;
	unsigned char* buffer;
	size_t buffer_size;

	// verify MAC
	//TODO make this more generic to use more than SHA256
	mbedtls_md_context_t ctx;
	mbedtls_md_setup(&ctx, &mbedtls_sha256_info, 1);
	mbedtls_md_hmac_starts(&ctx, session->remote_stretched_key->mac_key, session->remote_stretched_key->mac_size);
	mbedtls_md_hmac_update(&ctx, incoming, data_section_size);
	unsigned char generated_mac[32];
	mbedtls_md_hmac_finish(&ctx, generated_mac);
	mbedtls_md_free(&ctx);
	// 2. check the mac to see if it is the same
	int retVal = memcmp(&incoming[data_section_size], generated_mac, 32);
	// TODO: This MAC verification is failing.
	if (retVal != 0)
		return 0;

	mbedtls_cipher_context_t cipher_ctx;
	mbedtls_cipher_init(&cipher_ctx);
	mbedtls_cipher_setup(&cipher_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CTR));
	mbedtls_cipher_setkey(&cipher_ctx, session->remote_stretched_key->cipher_key, session->remote_stretched_key->cipher_size * 8, MBEDTLS_DECRYPT);
	mbedtls_cipher_set_iv(&cipher_ctx, session->remote_stretched_key->iv, session->remote_stretched_key->iv_size);
	buffer_size = data_section_size + mbedtls_cipher_get_block_size(&cipher_ctx);
	buffer = malloc(buffer_size);
	mbedtls_cipher_update(&cipher_ctx, incoming, data_section_size, buffer, &buffer_size);
	mbedtls_cipher_free(&cipher_ctx);
	*outgoing = malloc(buffer_size);
	*outgoing_size = buffer_size;
	memcpy(*outgoing, buffer, buffer_size);
	free(buffer);
	return *outgoing_size;
}

/**
 * Read from an encrypted stream
 * @param session the session parameters
 * @param bytes where the bytes will be stored
 * @param num_bytes the number of bytes read from the stream
 * @returns the number of bytes read
 */
int libp2p_secio_encrypted_read(void* stream_context, unsigned char** bytes, size_t* num_bytes, int timeout_secs) {
	int retVal = 0;
	struct SessionContext* session = (struct SessionContext*)stream_context;
	// reader uses the remote cipher and mac
	// read the data
	unsigned char* incoming = NULL;
	size_t incoming_size = 0;
	if (libp2p_secio_unencrypted_read(session, &incoming, &incoming_size, timeout_secs) <= 0)
		goto exit;
	retVal = libp2p_secio_decrypt(session, incoming, incoming_size, bytes, num_bytes);
	exit:
	if (incoming != NULL)
		free(incoming);
	return retVal;
}

/***
 * performs initial communication over an insecure channel to share
 * keys, IDs, and initiate connection. This is a framed messaging system
 * NOTE: session must contain a valid socket_descriptor that is a multistream.
 * @param local_session the secure session to be filled
 * @param private_key our private key to use
 * @param remote_requested it is the other side that requested the upgrade to secio
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_secio_handshake(struct SessionContext* local_session, struct RsaPrivateKey* private_key, int remote_requested) {
	int retVal = 0;
	size_t results_size = 0, bytes_written = 0;
	unsigned char* propose_in_bytes = NULL; // the remote protobuf
	size_t propose_in_size = 0;
	unsigned char* propose_out_bytes = NULL; // the local protobuf
	size_t propose_out_size = 0;
	unsigned char* results = NULL;
	struct Propose* propose_out = NULL;
	struct Propose* propose_in = NULL;
	struct PublicKey* public_key = NULL;
	unsigned char order_hash_in[32] = {0};
	unsigned char order_hash_out[32] = {0};
	int order = 0;;
	struct Exchange* exchange_in = NULL;
	struct Exchange* exchange_out = NULL;
	unsigned char* exchange_out_protobuf = NULL;
	size_t exchange_out_protobuf_size = 0;
	char* char_buffer = NULL;
	size_t char_buffer_length = 0;
	struct StretchedKey* k1 = NULL, *k2 = NULL;
	struct PrivateKey* priv = NULL;
	struct PublicKey pub_key = {0};
	char* remote_peer_id = NULL;

	//TODO: make sure we're not talking to ourself

	// prepare the multistream send of the protocol ID
	const unsigned char* protocol = (unsigned char*)"/secio/1.0.0\n";
	int protocol_len = strlen((char*)protocol);
	unsigned char* total = malloc(protocol_len + propose_out_size);
	memcpy(total, protocol, protocol_len);
	memcpy(&total[protocol_len], propose_out_bytes, propose_out_size);

	libp2p_logger_log("secio", LOGLEVEL_DEBUG, "Writing protocol");
	bytes_written = libp2p_net_multistream_write(local_session, total, protocol_len + propose_out_size);
	free(total);
	if (bytes_written <= 0)
		goto exit;

	if (!remote_requested) {
		// we should get back the secio confirmation
		libp2p_logger_log("secio", LOGLEVEL_DEBUG, "Reading protocol response");
		bytes_written = libp2p_net_multistream_read(local_session, &results, &results_size, 20);
		if (bytes_written < 5 || strstr((char*)results, "secio") == NULL)
			goto exit;

		free(results);
		results = NULL;
		results_size = 0;
	}

	// generate 16 byte nonce
	if (!libp2p_secio_generate_nonce(&local_session->local_nonce[0], 16)) {
		goto exit;
	}

	// Build the proposal to be sent to the new connection:
	propose_out = libp2p_secio_propose_new();
	libp2p_secio_propose_set_property((void**)&propose_out->rand, &propose_out->rand_size, local_session->local_nonce, 16);

	// public key - protobuf it and stick it in propose_out
	pub_key.type = KEYTYPE_RSA;
	pub_key.data_size = private_key->public_key_length;
	pub_key.data = malloc(pub_key.data_size);
	memcpy(pub_key.data, private_key->public_key_der, private_key->public_key_length);
	results_size = libp2p_crypto_public_key_protobuf_encode_size(&pub_key);
	results = malloc(results_size);
	if (results == NULL) {
		free(pub_key.data);
		goto exit;
	}
	if (libp2p_crypto_public_key_protobuf_encode(&pub_key, results, results_size, &results_size) == 0) {
		free(pub_key.data);
		goto exit;
	}
	free(pub_key.data);

	propose_out->public_key_size = results_size;
	propose_out->public_key = malloc(results_size);
	memcpy(propose_out->public_key, results, results_size);
	free(results);
	results = NULL;
	results_size = 0;
	// supported exchanges
	libp2p_secio_propose_set_property((void**)&propose_out->exchanges, &propose_out->exchanges_size, SupportedExchanges, strlen(SupportedExchanges));
	// supported ciphers
	libp2p_secio_propose_set_property((void**)&propose_out->ciphers, &propose_out->ciphers_size, SupportedCiphers, strlen(SupportedCiphers));
	// supported hashes
	libp2p_secio_propose_set_property((void**)&propose_out->hashes, &propose_out->hashes_size, SupportedHashes, strlen(SupportedHashes));

	// send proposal
	propose_out_size = libp2p_secio_propose_protobuf_encode_size(propose_out);
	propose_out_bytes = (unsigned char*)malloc(propose_out_size);
	if (libp2p_secio_propose_protobuf_encode(propose_out, propose_out_bytes, propose_out_size, &propose_out_size) == 0)
		goto exit;


	libp2p_logger_log("secio", LOGLEVEL_DEBUG, "Writing propose_out");
	bytes_written = libp2p_secio_unencrypted_write(local_session, propose_out_bytes, propose_out_size);
	if (bytes_written < propose_out_size)
		goto exit;

	// now receive the proposal from the new connection
	libp2p_logger_log("secio", LOGLEVEL_DEBUG, "receiving propose_in");
	bytes_written = libp2p_secio_unencrypted_read(local_session, &propose_in_bytes, &propose_in_size, 10);
	if (bytes_written <= 0)
			goto exit;

	if (!libp2p_secio_propose_protobuf_decode(propose_in_bytes, propose_in_size, &propose_in))
		goto exit;

	// get their nonce
	if (propose_in->rand_size != 16)
		goto exit;
	memcpy(local_session->remote_nonce, propose_in->rand, 16);
	// get public key and put it in a struct PublicKey
	if (!libp2p_crypto_public_key_protobuf_decode(propose_in->public_key, propose_in->public_key_size, &public_key))
		goto exit;
	// generate their peer id
	libp2p_crypto_public_key_to_peer_id(public_key, &remote_peer_id);

	// negotiate encryption parameters NOTE: SelectBest must match, otherwise this won't work
	// first determine order
	libp2p_secio_hash(propose_in->public_key, propose_in->public_key_size, propose_out->rand, propose_out->rand_size, order_hash_in);
	libp2p_secio_hash(propose_out->public_key, propose_out->public_key_size, propose_in->rand, propose_in->rand_size, order_hash_out);
	order = libp2p_secio_bytes_compare((char*)order_hash_in, (char*)order_hash_out, 32);
	// curve
	if (libp2p_secio_select_best(order, propose_out->exchanges, propose_out->exchanges_size, propose_in->exchanges, propose_in->exchanges_size, &local_session->chosen_curve) == 0)
		goto exit;
	// cipher
	if (libp2p_secio_select_best(order, propose_out->ciphers, propose_out->ciphers_size, propose_in->ciphers, propose_in->ciphers_size, &local_session->chosen_cipher) == 0)
		goto exit;
	// hash
	if (libp2p_secio_select_best(order, propose_out->hashes, propose_out->hashes_size, propose_in->hashes, propose_in->hashes_size, &local_session->chosen_hash) == 0)
		goto exit;

	// generate EphemeralPubKey
	if (libp2p_crypto_ephemeral_keypair_generate(local_session->chosen_curve, &local_session->ephemeral_private_key) == 0)
		goto exit;

	// build buffer to sign
	char_buffer_length = propose_in_size + propose_out_size + local_session->ephemeral_private_key->public_key->bytes_size - 1;
	char_buffer = malloc(char_buffer_length);
	if (char_buffer == NULL)
		goto exit;
	memcpy(&char_buffer[0], propose_out_bytes, propose_out_size);
	memcpy(&char_buffer[propose_out_size], propose_in_bytes, propose_in_size);
	memcpy(&char_buffer[propose_in_size + propose_out_size], &local_session->ephemeral_private_key->public_key->bytes[1], local_session->ephemeral_private_key->public_key->bytes_size-1);

	// send Exchange packet
	exchange_out = libp2p_secio_exchange_new();
	if (exchange_out == NULL)
		goto exit;
	// don't send the first byte (to stay compatible with GO version)
	exchange_out->epubkey = (unsigned char*)malloc(local_session->ephemeral_private_key->public_key->bytes_size - 1);
	if (exchange_out->epubkey == NULL)
		goto exit;
	memcpy(exchange_out->epubkey, &local_session->ephemeral_private_key->public_key->bytes[1], local_session->ephemeral_private_key->public_key->bytes_size - 1);
	exchange_out->epubkey_size = local_session->ephemeral_private_key->public_key->bytes_size - 1;

	priv = libp2p_crypto_private_key_new();
	priv->type = KEYTYPE_RSA;
	priv->data = (unsigned char*)private_key->der;
	priv->data_size = private_key->der_length;
	libp2p_secio_sign(priv, char_buffer, char_buffer_length, &exchange_out->signature, &exchange_out->signature_size);
	free(char_buffer);
	char_buffer = NULL;
	// yes, this is an improper disposal, but it gets the job done without fuss
	free(priv);

	exchange_out_protobuf_size = libp2p_secio_exchange_protobuf_encode_size(exchange_out);
	exchange_out_protobuf = (unsigned char*)malloc(exchange_out_protobuf_size);
	if (exchange_out_protobuf == NULL)
		goto exit;
	libp2p_secio_exchange_protobuf_encode(exchange_out, exchange_out_protobuf, exchange_out_protobuf_size, &bytes_written);
	exchange_out_protobuf_size = bytes_written;

	libp2p_logger_log("secio", LOGLEVEL_DEBUG, "Writing exchange_out");
	bytes_written = libp2p_secio_unencrypted_write(local_session, exchange_out_protobuf, exchange_out_protobuf_size);
	if (exchange_out_protobuf_size != bytes_written)
		goto exit;
	free(exchange_out_protobuf);
	exchange_out_protobuf = NULL;
	// end of send Exchange packet

	// receive Exchange packet
	libp2p_logger_log("secio", LOGLEVEL_DEBUG, "Reading exchagne packet");
	bytes_written = libp2p_secio_unencrypted_read(local_session, &results, &results_size, 10);
	if (bytes_written == 0)
		goto exit;
	libp2p_secio_exchange_protobuf_decode(results, results_size, &exchange_in);
	free(results);
	results = NULL;
	// end of receive Exchange packet

	// parse and verify
	local_session->remote_ephemeral_public_key_size = exchange_in->epubkey_size + 1;
	local_session->remote_ephemeral_public_key = malloc(local_session->remote_ephemeral_public_key_size);
	local_session->remote_ephemeral_public_key[0] = exchange_in->epubkey_size;
	memcpy(&local_session->remote_ephemeral_public_key[1], exchange_in->epubkey, exchange_in->epubkey_size);

	// signature verification
	char_buffer_length = propose_in_size + propose_out_size + local_session->remote_ephemeral_public_key_size - 1;
	char_buffer = malloc(char_buffer_length);
	if (char_buffer == NULL)
		goto exit;
	memcpy(&char_buffer[0], propose_in_bytes, propose_in_size);
	memcpy(&char_buffer[propose_in_size], propose_out_bytes, propose_out_size);
	memcpy(&char_buffer[propose_in_size + propose_out_size], &local_session->remote_ephemeral_public_key[1], local_session->remote_ephemeral_public_key_size - 1);
	if (!libp2p_secio_verify_signature(public_key, (unsigned char*)char_buffer, char_buffer_length, exchange_in->signature))
		goto exit;
	free(char_buffer);
	char_buffer = NULL;

	// 2.2 generate shared key
	if (!libp2p_crypto_ephemeral_generate_shared_secret(local_session->ephemeral_private_key, local_session->remote_ephemeral_public_key, local_session->remote_ephemeral_public_key_size))
		goto exit;

	local_session->shared_key_size = local_session->ephemeral_private_key->public_key->shared_key_size;
	local_session->shared_key = malloc(local_session->shared_key_size);
	memcpy(local_session->shared_key, local_session->ephemeral_private_key->public_key->shared_key, local_session->shared_key_size);

	// generate 2 sets of keys (stretching)
	if (!libp2p_secio_stretch_keys(local_session->chosen_cipher, local_session->chosen_hash, local_session->shared_key, local_session->shared_key_size, &k1, &k2))
		goto exit;

	if (order > 1) {
		local_session->local_stretched_key = k1;
		local_session->remote_stretched_key = k2;
	} else {
		local_session->local_stretched_key = k2;
		local_session->remote_stretched_key = k1;
	}

	// prepare MAC + cipher
	if (strcmp(local_session->chosen_hash, "SHA1") == 0) {
		local_session->mac_function = libp2p_crypto_hashing_sha1;
	} else if (strcmp(local_session->chosen_hash, "SHA512") == 0) {
		local_session->mac_function = libp2p_crypto_hashing_sha512;
	} else if (strcmp(local_session->chosen_hash, "SHA256") == 0) {
		local_session->mac_function = libp2p_crypto_hashing_sha256;
	} else {
		return 0;
	}

	libp2p_secio_make_mac_and_cipher(local_session, local_session->local_stretched_key);
	libp2p_secio_make_mac_and_cipher(local_session, local_session->remote_stretched_key);

	// send expected message (their nonce) to verify encryption works
	libp2p_logger_log("secio", LOGLEVEL_DEBUG, "Sending their nonce");
	if (libp2p_secio_encrypted_write(local_session, (unsigned char*)local_session->remote_nonce, 16) <= 0)
		goto exit;

	// receive our nonce to verify encryption works
	libp2p_logger_log("secio", LOGLEVEL_DEBUG, "Receiving our nonce");
	int bytes_read = libp2p_secio_encrypted_read(local_session, &results, &results_size, 10);
	if (bytes_read <= 0) {
		libp2p_logger_log("secio", LOGLEVEL_DEBUG, "Encrypted read returned %d", bytes_read);
		goto exit;
	}
	if (results_size != 16) {
		libp2p_logger_log("secio", LOGLEVEL_DEBUG, "Results_size should be 16 but was %d", results_size);
		goto exit;
	}
	if (libp2p_secio_bytes_compare((char*)results, local_session->local_nonce, 16) != 0) {
		libp2p_logger_log("secio", LOGLEVEL_DEBUG, "Bytes of nonce did not match");
		goto exit;
	}

	// set up the secure stream in the struct
	local_session->secure_stream = local_session->insecure_stream;
	local_session->secure_stream->read = libp2p_secio_encrypted_read;
	local_session->secure_stream->write = libp2p_secio_encrypted_write;
	// set secure as default
	local_session->default_stream = local_session->secure_stream;

	retVal = 1;

	libp2p_logger_log("secio", LOGLEVEL_DEBUG, "Handshake complete");
	exit:

	if (propose_in_bytes != NULL)
		free(propose_in_bytes);
	if (propose_out_bytes != NULL)
		free(propose_out_bytes);
	if (results != NULL)
		free(results);
	if (char_buffer != NULL)
		free(char_buffer);
	if (public_key != NULL)
		libp2p_crypto_public_key_free(public_key);
	if (remote_peer_id != NULL)
		free(remote_peer_id);
	if (exchange_out != NULL)
		libp2p_secio_exchange_free(exchange_out);
	if (exchange_out_protobuf != NULL)
		free(exchange_out_protobuf);
	if (exchange_in != NULL)
		libp2p_secio_exchange_free(exchange_in);

	libp2p_secio_propose_free(propose_out);
	libp2p_secio_propose_free(propose_in);

	if (retVal == 1) {
		libp2p_logger_log("secio", LOGLEVEL_DEBUG, "Handshake success!");
	} else {
		libp2p_logger_log("secio", LOGLEVEL_DEBUG, "Handshake returning false");
	}
	return retVal;
}
