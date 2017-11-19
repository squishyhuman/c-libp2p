#include <stdlib.h>
#include <stdio.h> // for debugging, can remove
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <arpa/inet.h>
#if defined(__APPLE__) || defined(__MACH__)
#include <machine/endian.h>
#else
#include <endian.h>
#endif
#include <stdarg.h>

#include "libp2p/secio/secio.h"
#include "libp2p/secio/propose.h"
#include "libp2p/secio/exchange.h"
#include "libp2p/net/multistream.h"
#include "libp2p/net/p2pnet.h"
#include "libp2p/net/connectionstream.h"
#include "libp2p/os/utils.h"
#include "libp2p/crypto/ephemeral.h"
#include "libp2p/crypto/sha1.h"
#include "libp2p/crypto/sha256.h"
#include "libp2p/crypto/sha512.h"
#include "libp2p/utils/string_list.h"
#include "libp2p/utils/vector.h"
#include "libp2p/utils/logger.h"
#include "libp2p/net/protocol.h"
#include "mbedtls/md.h"
#include "mbedtls/cipher.h"
#include "mbedtls/md_internal.h"
#include "mbedtls/aes.h"

const char* SupportedExchanges = "P-256,P-384,P-521";
const char* SupportedCiphers = "AES-256,AES-128,Blowfish";
const char* SupportedHashes = "SHA256,SHA512";

int libp2p_secio_can_handle(const struct StreamMessage* msg) {
	const char* protocol = "/secio/1.0.0";
	// sanity checks
	if (msg->data_size < 12)
		return 0;
	char* result = strnstr((char*)msg->data, protocol, msg->data_size);
	if (result != NULL && result == (char*)msg->data)
		return 1;
	return 0;
}

/***
 * Handle a secio message
 * @param msg the incoming message
 * @param session_context who is attempting to connect
 * @param protocol_context a SecioContext that contains the needed information
 * @returns <0 on error, 0 if okay (does not allow daemon to continue looping)
 */
int libp2p_secio_handle_message(const struct StreamMessage* msg, struct Stream* stream, void* protocol_context) {
	libp2p_logger_debug("secio", "Handling incoming secio message.\n");
	struct SecioContext* ctx = (struct SecioContext*)protocol_context;
	// send them the protocol
	if (!libp2p_secio_send_protocol(stream))
		return -1;
	int retVal = libp2p_secio_handshake(ctx);
	if (retVal)
		return 0;
	return -1;
}

int libp2p_secio_shutdown(void* context) {
	free(context);
	return 1;
}

struct Libp2pProtocolHandler* libp2p_secio_build_protocol_handler(struct RsaPrivateKey* private_key, struct Peerstore* peer_store) {
	struct Libp2pProtocolHandler* handler = (struct Libp2pProtocolHandler*) malloc(sizeof(struct Libp2pProtocolHandler));
	if (handler != NULL) {
		struct SecioContext* context = (struct SecioContext*) malloc(sizeof(struct SecioContext));
		context->buffered_message = NULL;
		context->buffered_message_pos = -1;
		context->private_key = private_key;
		context->peer_store = peer_store;
		handler->context = context;
		handler->CanHandle = libp2p_secio_can_handle;
		handler->HandleMessage = libp2p_secio_handle_message;
		handler->Shutdown = libp2p_secio_shutdown;
	}
	return handler;
}

/**
 * Generate a random nonce
 * @param results where to put the results
 * @param length the length of the nonce
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_secio_generate_nonce(unsigned char* results, int length) {
	FILE* fd = fopen("/dev/urandom", "r");
	fread(results, 1, length, fd);
	fclose(fd);
	return 1;
}

/***
 * Used for debugging. Turns an incoming byte array into a decimal string
 * @param incoming the incoming byte array
 * @param incoming_size the size of the byte array
 * @returns the string
 */
char* secio_to_hex(unsigned char* incoming, size_t incoming_size) {
	static char str[3000];
	memset(str, 0, 3000);
	for(int i = 0; i < incoming_size; i++) {
		sprintf(&str[i * 4], "%03d ", incoming[i]);
	}
	return str;
}

/**
 * Compute a hash based on a Propose struct
 * @param in the struct Propose
 * @param result where to put the result (should be char[32])
 * @returns true(1) on success
 */
int libp2p_secio_hash(unsigned char* key, size_t key_size, unsigned char* nonce, size_t nonce_size, unsigned char result[32]) {
	// append public key and nonce
	unsigned char* appended = malloc(key_size + nonce_size);
	memcpy(appended, key, key_size);
	memcpy(&appended[key_size], nonce, nonce_size);
	// hash it
	libp2p_crypto_hashing_sha256(appended, key_size+nonce_size, result);
	free(appended);
	return 1;
}

/***
 * Compare 2 hashes lexicographically
 * @param a the a side
 * @param b the b side
 * @param length the length of a and b
 * @returns a -1, 0, or 1
 */
int libp2p_secio_bytes_compare(const unsigned char* a, const unsigned char* b, int length) {
	for(int i = 0; i < length; i++) {
		if (b[i] > a[i])
			return -1;
		if (a[i] > b[i])
			return 1;
	}
	return 0;
}

/**
 * Used for debugging keys
 */
/*
int libp2p_secio_log_keys(struct SessionContext* session) {
	if (libp2p_logger_watching_class("secio")) {
		libp2p_logger_debug("secio", "Shared: %s\n", secio_to_hex(session->shared_key, session->shared_key_size));
		libp2p_logger_debug("secio", "k1 IV: %s\n", secio_to_hex(session->local_stretched_key->iv, session->local_stretched_key->iv_size));
		libp2p_logger_debug("secio", "k1 MAC: %s\n", secio_to_hex(session->local_stretched_key->cipher_key, session->local_stretched_key->cipher_size));
		libp2p_logger_debug("secio", "k1 CIPHER: %s\n", secio_to_hex(session->local_stretched_key->mac_key, session->local_stretched_key->mac_size));
		libp2p_logger_debug("secio", "k2 IV: %s\n", secio_to_hex(session->remote_stretched_key->iv, session->remote_stretched_key->iv_size));
		libp2p_logger_debug("secio", "k2 MAC: %s\n", secio_to_hex(session->remote_stretched_key->cipher_key, session->remote_stretched_key->cipher_size));
		libp2p_logger_debug("secio", "k2 CIPHER: %s\n", secio_to_hex(session->remote_stretched_key->mac_key, session->remote_stretched_key->mac_size));
	}
	return 1;
}
*/

/***
 * Using values in the Propose struct, determine the order that will be used for the MACs
 * @param remote the struct from the remote side
 * @param local the struct from this side
 * @returns -1 or 1 that will be used to determine who is first
 */
int libp2p_secio_determine_order(struct Propose* remote, struct Propose* local) {
	unsigned char hash1[32];
	unsigned char hash2[32];
	libp2p_secio_hash(remote->public_key, remote->public_key_size, local->rand, local->rand_size, hash1);
	libp2p_secio_hash(local->public_key, local->public_key_size, remote->rand, remote->rand_size, hash2);

	return libp2p_secio_bytes_compare(hash1, hash2, 32);
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
 * @returns true(1) if the signature is correct, false(0) otherwise
 */
int libp2p_secio_verify_signature(struct PublicKey* public_key, const unsigned char* in, size_t in_length, unsigned char* signature) {

	// debugging:
	if (libp2p_logger_watching_class("secio")) {
		fprintf(stdout, "Verifying signature of %d bytes:", (int)in_length);
		for(int i = 0; i < 32; i++) {
			fprintf(stdout, " %02x", signature[i]);
		}
		fprintf(stdout, "\n");
	}

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
		int retVal = libp2p_crypto_rsa_sign(&rsa_key, in, in_length, signature, signature_size);
		// debugging
		if (retVal && libp2p_logger_watching_class("secio")) {
			unsigned char* ptr = *signature;
			fprintf(stdout, "Signature generated from %d bytes:", (int)in_length);
			for(int i = 0; i < *signature_size; i++) {
				fprintf(stdout, " %02x", ptr[i]);
			}
			fprintf(stdout, "\n");
		}
		return retVal;
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
int libp2p_secio_stretch_keys(char* cipherType, char* hashType, unsigned char* secret, size_t secret_size,
		struct StretchedKey** k1_ptr, struct StretchedKey** k2_ptr) {
	int retVal = 0, num_filled = 0, hmac_size = 20;
	struct StretchedKey* k1 = NULL;
	struct StretchedKey* k2 = NULL;
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
 * Send the protocol string to the remote stream
 * @param ctx the context
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_secio_send_protocol(struct Stream* stream) {
	char* protocol = "/secio/1.0.0\n";
	struct StreamMessage outgoing;
	outgoing.data = (uint8_t*)protocol;
	outgoing.data_size = strlen(protocol);
	return stream->write(stream->stream_context, &outgoing);
}

/***
 * Attempt to read the secio protocol as a reply from the remote
 * @param ctx the context
 * @returns true(1) if we received what we think we should have, false(0) otherwise
 */
int libp2p_secio_receive_protocol(struct Stream* stream) {
	char* protocol = "/secio/1.0.0\n";
	int numSecs = 30;
	int retVal = 0;
	struct StreamMessage* buffer = NULL;
	stream->read(stream->stream_context, &buffer, numSecs);
	if (buffer == NULL) {
		libp2p_logger_error("secio", "Expected the secio protocol header, but received NULL.\n");
	} else {
		// see if they sent the correct response
		if (strncmp(protocol, (char*)buffer->data, strlen(protocol)) == 0) {
			retVal = 1;
		}
		else {
			libp2p_logger_error("secio", "Expected the secio protocol header, but received %s.\n", buffer);
		}
	}
	libp2p_stream_message_free(buffer);
	return retVal;
}

/**
 * Navigate down the tree of streams to get the raw socket descriptor
 * @param stream the stream
 * @returns the raw socket descriptor
 */
int libp2p_secio_get_socket_descriptor(struct Stream* stream) {
	struct Stream* current = stream;
	while (current->parent_stream != NULL)
		current = current->parent_stream;
	struct ConnectionContext* ctx = current->stream_context;
	return ctx->socket_descriptor;
}

/***
 * Write bytes to an unencrypted stream
 * @param session the session information
 * @param bytes the bytes to write
 * @param data_length the number of bytes to write
 * @returns the number of bytes written
 */
int libp2p_secio_unencrypted_write(struct Stream* secio_stream, struct StreamMessage* msg) {
	int num_bytes = 0;

	int socket_descriptor = libp2p_secio_get_socket_descriptor(secio_stream);

	if (msg != NULL && msg->data_size > 0) { // only do this is if there is something to send
		// first send the size
		uint32_t size = htonl(msg->data_size);
		char* size_as_char = (char*)&size;
		int left = 4;
		int written = 0;
		int written_this_time = 0;
		do {
			written_this_time = socket_write(socket_descriptor, &size_as_char[written], left, 0);
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
		left = msg->data_size;
		written = 0;
		do {
			written_this_time = socket_write(socket_descriptor, (char*)&msg->data[written], left, 0);
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
int libp2p_secio_unencrypted_read(struct Stream* secio_stream, struct StreamMessage** msg, int timeout_secs) {
	uint32_t buffer_size = 0;

	if (secio_stream == NULL) {
		libp2p_logger_error("secio", "Attempted unencrypted read on invalid session.\n");
		return 0;
	}

	int socket_descriptor = libp2p_secio_get_socket_descriptor(secio_stream);

	// first read the 4 byte integer
	char* size = (char*)&buffer_size;
	int left = 4;
	int read = 0;
	int read_this_time = 0;
	int time_left = timeout_secs;
	do {
		read_this_time = socket_read(socket_descriptor, &size[read], 1, 0, timeout_secs);
		if (read_this_time <= 0) {
			if ( errno == EINPROGRESS ) {
				time_left--;
				sleep(1);
				if (time_left == 0)
					break;
				continue;
			}
			if ( errno == EAGAIN || errno == EWOULDBLOCK ) {
				// TODO: use epoll or select to wait for socket to be writable
				libp2p_logger_debug("secio", "Attempted read, but got EAGAIN or EWOULDBLOCK. Code %d.\n", errno);
				return 0;
			} else {
				// is this really an error?
				if (errno != 0) {
					libp2p_logger_error("secio", "Error in libp2p_secio_unencrypted_read: %s\n", strerror(errno));
					return 0;
				}
				else
					libp2p_logger_error("secio", "Error in libp2p_secio_unencrypted_read: 0 bytes read, but errno shows no error. Trying again.\n");
			}
		} else {
			left = left - read_this_time;
			read += read_this_time;
		}
	} while (left > 0);
	buffer_size = ntohl(buffer_size);
	if (buffer_size == 0) {
		libp2p_logger_error("secio", "unencrypted read buffer size is 0.\n");
		return 0;
	}

	// now read the number of bytes we've found, minus the 4 that we just read
	left = buffer_size;
	read = 0;
	read_this_time = 0;
	*msg = libp2p_stream_message_new();
	struct StreamMessage* m = *msg;
	if (m == NULL) {
		libp2p_logger_error("secio", "Unable to allocate memory for the incoming message. Size: %ulld", left);
		return 0;
	}
	m->data_size = left;
	m->data = (uint8_t*) malloc(left);
	unsigned char* ptr = m->data;
	time_left = timeout_secs;
	do {
		read_this_time = socket_read(socket_descriptor, (char*)&ptr[read], left, 0, timeout_secs);
		if (read_this_time < 0) {
			if (errno == EINPROGRESS) {
				sleep(1);
				time_left--;
				if (time_left == 0)
					break;
				continue;
			}
			read_this_time = 0;
			if ( (errno == EAGAIN) || (errno == EWOULDBLOCK)) {
				// TODO: use epoll or select to wait for socket to be writable
			} else {
				libp2p_logger_error("secio", "read from socket returned %d.\n", errno);
				return 0;
			}
		} else if (read_this_time == 0) {
			// socket_read returned 0, which it shouldn't
			libp2p_logger_error("secio", "socket_read returned 0 trying to read from stream %d.\n", socket_descriptor);
			return 0;
		}
		left = left - read_this_time;
		read += read_this_time;
	} while (left > 0);

	m->data_size = buffer_size;
	return buffer_size;
}


/**
 * Initialize state for the sha256 stream cipher
 * @param session the SessionContext struct that contains the variables to initialize
 * @returns 1
 */
int libp2p_secio_initialize_crypto(struct SessionContext* session) {
	session->aes_decode_nonce_offset = 0;
	session->aes_encode_nonce_offset = 0;
	memset(session->aes_decode_stream_block, 0, 16);
	memset(session->aes_encode_stream_block, 0, 16);
	return 1;
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
int libp2p_secio_encrypt(struct SessionContext* session, const unsigned char* incoming, size_t incoming_size, unsigned char** outgoing, size_t* outgoing_size) {
	unsigned char* buffer = NULL;
	size_t buffer_size = 0, original_buffer_size = 0;

	//TODO switch between ciphers
	mbedtls_aes_context cipher_ctx;
	mbedtls_aes_init(&cipher_ctx);
	if (mbedtls_aes_setkey_enc(&cipher_ctx, session->local_stretched_key->cipher_key, session->local_stretched_key->cipher_size * 8)) {
		fprintf(stderr, "Unable to set key for cipher\n");
		return 0;
	}

	original_buffer_size = incoming_size;
	original_buffer_size += 32;
	buffer_size = original_buffer_size;
	buffer = malloc(original_buffer_size);
	memset(buffer, 0, original_buffer_size);

	if (mbedtls_aes_crypt_ctr(&cipher_ctx, incoming_size, &session->aes_encode_nonce_offset, session->local_stretched_key->iv, session->aes_encode_stream_block, incoming, buffer)) {
		fprintf(stderr, "Unable to update cipher\n");
		return 0;
	}
	buffer_size = incoming_size;

	// Now, buffer size may be set differently than original_buffer_size
	// The "incoming" is now encrypted, and is in the first part of the buffer
	mbedtls_aes_free(&cipher_ctx);

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
 * @returns the number of bytes written
 */
int libp2p_secio_encrypted_write(void* stream_context, struct StreamMessage* bytes) {
	struct SecioContext* ctx = (struct SecioContext*) stream_context;
	struct Stream* parent_stream = ctx->stream->parent_stream;
	struct SessionContext* session_context = ctx->session_context;

	// writer uses the local cipher and mac
	struct StreamMessage outgoing;
	if (!libp2p_secio_encrypt(session_context, bytes->data, bytes->data_size, &outgoing.data, &outgoing.data_size)) {
		libp2p_logger_error("secio", "secio_encrypt returned false.\n");
		return 0;
	}

	libp2p_logger_debug("secio", "About to write %d bytes.\n", (int)outgoing.data_size);
	int retVal = libp2p_secio_unencrypted_write(parent_stream, &outgoing);
	if (!retVal) {
		libp2p_logger_error("secio", "secio_unencrypted_write returned false\n");
	}
	free(outgoing.data);
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
int libp2p_secio_decrypt(struct SessionContext* session, const unsigned char* incoming, size_t incoming_size, struct StreamMessage** outgoing) {
	size_t data_section_size = incoming_size - 32;
	unsigned char* buffer;

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
	if (retVal != 0) {
		// MAC verification failed
		libp2p_logger_error("secio", "libp2p_secio_decrypt: MAC verification failed.\n");
		// copy the raw bytes into outgoing for further analysis
		*outgoing = libp2p_stream_message_new();
		struct StreamMessage* message = *outgoing;
		if (message != NULL) {
			message->data_size = incoming_size;
			message->data = (uint8_t*) malloc(incoming_size);
			memcpy(message->data, incoming, incoming_size);
		}
		return 0;
	}

	// The MAC checks out. Now decipher the data section

	mbedtls_aes_context cipher_ctx;
	mbedtls_aes_init(&cipher_ctx);
	if (mbedtls_aes_setkey_enc(&cipher_ctx, session->remote_stretched_key->cipher_key, session->remote_stretched_key->cipher_size * 8)) {
		libp2p_logger_error("secio", "Unable to set key for cipher.\n");
		return 0;
	}

	buffer = malloc(data_section_size);
	if (mbedtls_aes_crypt_ctr(&cipher_ctx, data_section_size, &session->aes_decode_nonce_offset, session->remote_stretched_key->iv, session->aes_decode_stream_block, incoming, buffer)) {
		libp2p_logger_error("secio", "Unable to update cipher.\n");
		return 0;
	}

	mbedtls_aes_free(&cipher_ctx);
	*outgoing = libp2p_stream_message_new();
	struct StreamMessage* message = *outgoing;
	message->data_size = data_section_size;
	message->data = (uint8_t*) malloc(data_section_size);
	if (message->data == NULL) {
		libp2p_stream_message_free(message);
		*outgoing = NULL;
		return 0;
	}
	memcpy(message->data, buffer, data_section_size);
	free(buffer);

	return message->data_size;
}

/**
 * Read from an encrypted stream
 * @param session the session parameters
 * @param bytes where the bytes will be stored
 * @returns the number of bytes read
 */
int libp2p_secio_encrypted_read(void* stream_context, struct StreamMessage** bytes, int timeout_secs) {
	int retVal = 0;
	struct SecioContext* ctx = (struct SecioContext*)stream_context;
	struct Stream* parent_stream = ctx->stream->parent_stream;
	// reader uses the remote cipher and mac
	// read the data
	struct StreamMessage* msg = NULL;
	if (!libp2p_secio_unencrypted_read(parent_stream, &msg, 10)) {
		libp2p_logger_error("secio", "Unencrypted_read returned false.\n");
		goto exit;
	}
	retVal = libp2p_secio_decrypt(ctx->session_context, msg->data, msg->data_size, bytes);
	if (!retVal)
		libp2p_logger_error("secio", "Decrypting incoming stream returned false.\n");
	exit:
	libp2p_stream_message_free(msg);
	return retVal;
}

struct Libp2pPeer* libp2p_secio_get_peer_or_add(struct Peerstore* peerstore, struct SessionContext* local_session) {
	struct Libp2pPeer* remote_peer = NULL;

	// see if we already have this peer
	if (peerstore != NULL)
		remote_peer = libp2p_peerstore_get_peer(peerstore, (unsigned char*)local_session->remote_peer_id, strlen(local_session->remote_peer_id));
	if (remote_peer == NULL) {
		remote_peer = libp2p_peer_new();
		// put peer information in Libp2pPeer struct
		remote_peer->id_size = strlen(local_session->remote_peer_id);
		if (remote_peer->id_size > 0) {
			remote_peer->id = malloc(remote_peer->id_size + 1);
			if (remote_peer->id != NULL) {
				memcpy(remote_peer->id, local_session->remote_peer_id, remote_peer->id_size);
				remote_peer->id[remote_peer->id_size] = 0;
			}
		}
		remote_peer->sessionContext = local_session;
		// add a multiaddress to the peer (if we have what we need)
		char url[100];
		sprintf(url, "/ip4/%s/tcp/%d/ipfs/%s", local_session->host, local_session->port, libp2p_peer_id_to_string(remote_peer));
		struct MultiAddress* ma = multiaddress_new_from_string(url);
		if (ma == NULL) {
			libp2p_logger_error("secio", "Unable to generate MultiAddress from [%s].\n", url);
			libp2p_peer_free(remote_peer);
			return NULL;
		} else {
			libp2p_logger_debug("secio", "Adding %s to peer %s.\n", url, libp2p_peer_id_to_string(remote_peer));
			struct Libp2pLinkedList* ma_ll = libp2p_utils_linked_list_new();
			ma_ll->item = ma;
			remote_peer->addr_head = ma_ll;
		}
		if (peerstore != NULL) {
			libp2p_logger_debug("secio", "New connection. Adding Peer to Peerstore.\n");
			libp2p_peerstore_add_peer(peerstore, remote_peer);
		}
	} else {
		// we already had one in the peerstore
		if (remote_peer->sessionContext != local_session) {
			// clean up old session context
			libp2p_logger_debug("secio", "Same remote connected. Replacing SessionContext.\n");
			libp2p_session_context_free(remote_peer->sessionContext);
			remote_peer->sessionContext = local_session;
		}
	}
	remote_peer->connection_type = CONNECTION_TYPE_CONNECTED;
	return remote_peer;
}

/***
 * performs initial communication over an insecure channel to share
 * keys, IDs, and initiate connection. This is a framed messaging system
 * NOTE: session must contain a valid socket_descriptor that is a multistream.
 * @param local_session the secure session to be filled
 * @param private_key our private key to use
 * @param peerstore the collection of peers
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_secio_handshake(struct SecioContext* secio_context) {
	int retVal = 0;
	size_t bytes_written = 0;
	struct StreamMessage* incoming = NULL;
	struct StreamMessage outgoing; // used for outgoing messages
	unsigned char* propose_in_bytes = NULL; // the remote protobuf
	size_t propose_in_size = 0;
	unsigned char* propose_out_bytes = NULL; // the local protobuf
	size_t propose_out_size = 0;
	unsigned char* results = NULL;
	struct Propose* propose_out = NULL;
	struct Propose* propose_in = NULL;
	struct PublicKey* public_key = NULL;
	int order = 0;;
	struct Exchange* exchange_in = NULL;
	struct Exchange* exchange_out = NULL;
	unsigned char* exchange_out_protobuf = NULL;
	size_t exchange_out_protobuf_size = 0;
	char* char_buffer = NULL;
	size_t char_buffer_length = 0;
	struct StretchedKey* k1 = NULL, *k2 = NULL;
	struct Libp2pPeer* remote_peer = NULL;

	struct SessionContext* local_session = secio_context->session_context;
	struct RsaPrivateKey* private_key = secio_context->private_key;
	struct Peerstore* peerstore = secio_context->peer_store;

	//TODO: make sure we're not talking to ourself

	// send the protocol id and the outgoing Propose struct

	// generate 16 byte nonce
	if (!libp2p_secio_generate_nonce(&local_session->local_nonce[0], 16)) {
		goto exit;
	}

	// Build the proposal to be sent to the new connection:
	propose_out = libp2p_secio_propose_build(local_session->local_nonce, private_key,
			SupportedExchanges, SupportedCiphers, SupportedHashes);

	if (libp2p_logger_watching_class("secio")) {
		fprintf(stdout, "Our public key: ");
		for(int i = 0; i < propose_out->public_key_size; i++) {
			fprintf(stdout, " %02x", propose_out->public_key[i]);
		}
		fprintf(stdout, "\n");
	}

	// protobuf the proposal
	propose_out_size = libp2p_secio_propose_protobuf_encode_size(propose_out);
	propose_out_bytes = (unsigned char*)malloc(propose_out_size);
	if (libp2p_secio_propose_protobuf_encode(propose_out, propose_out_bytes, propose_out_size, &propose_out_size) == 0)
		goto exit;

	// now send the Propose struct
	outgoing.data = propose_out_bytes;
	outgoing.data_size = propose_out_size;
	bytes_written = libp2p_secio_unencrypted_write(secio_context->stream, &outgoing);

	if (bytes_written != propose_out_size) {
		libp2p_logger_error("secio", "Sent propose_out, but did not write the correct number of bytes. Should be %d but was %d.\n", propose_out_size, bytes_written);
		goto exit;
	}

	// try to get the Propose struct from the remote peer
	bytes_written = libp2p_secio_unencrypted_read(secio_context->stream, &incoming, 10);
	if (bytes_written <= 0) {
		libp2p_logger_error("secio", "Unable to get the remote's Propose struct.\n");
		goto exit;
	} else {
		libp2p_logger_debug("secio","Received their propose struct.\n");
	}

	// we need the propose bytes for later, so saving them off
	propose_in_bytes = malloc(incoming->data_size);
	memcpy(propose_in_bytes, incoming->data, incoming->data_size);
	propose_in_size = incoming->data_size;

	libp2p_stream_message_free(incoming);
	incoming = NULL;

	if (!libp2p_secio_propose_protobuf_decode(propose_in_bytes, propose_in_size, &propose_in)) {
		libp2p_logger_error("secio", "Unable to un-protobuf the remote's Propose struct\n");
		goto exit;
	}

	// get their nonce
	if (propose_in->rand_size != 16) {
		libp2p_logger_error("secio", "Their nonce is not 16 bytes!\n");
		goto exit;
	}
	memcpy(local_session->remote_nonce, propose_in->rand, 16);

	// debugging
	if (libp2p_logger_watching_class("secio")) {
		fprintf(stdout, "Our nonce:");
		for (int i = 0; i < 16; i++) {
			fprintf(stdout, " %02x", local_session->local_nonce[i]);
		}
		fprintf(stdout, "\nTheir nonce:");
		for (int i = 0; i < 16; i++) {
			fprintf(stdout, " %02x", local_session->remote_nonce[i]);
		}
		fprintf(stdout, "\n");
	}

	if (libp2p_logger_watching_class("secio")) {
		fprintf(stdout, "Their public key (length %d):", (int)propose_in->public_key_size);
		for(int i = 0; i < propose_in->public_key_size; i++) {
			fprintf(stdout, " %02x", propose_in->public_key[i]);
		}
		fprintf(stdout, "\n");
	}

	if (!libp2p_crypto_public_key_protobuf_decode(propose_in->public_key, propose_in->public_key_size, &public_key))
		goto exit;

	// generate their peer id
	libp2p_crypto_public_key_to_peer_id(public_key, &local_session->remote_peer_id);

	libp2p_logger_debug("secio", "Their Peer ID: %s.\n", local_session->remote_peer_id);

	// pull the peer from the peerstore if it is there
	remote_peer = libp2p_secio_get_peer_or_add(peerstore, local_session);

	// negotiate encryption parameters NOTE: SelectBest must match, otherwise this won't work
	// first determine order
	order = libp2p_secio_determine_order(propose_in, propose_out);
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
	if (libp2p_logger_watching_class("secio")) {
		fprintf(stdout, "Building buffer to sign.\n");
		fprintf(stdout, "Propose in size  : %d\n", (int)propose_in_size);
		fprintf(stdout, "Propose out size : %d\n", (int)propose_out_size);
		fprintf(stdout, "Epemeral key size: %d\n", (int)local_session->ephemeral_private_key->public_key->bytes_size);
	}
	char_buffer = malloc(char_buffer_length);
	if (char_buffer == NULL)
		goto exit;
	memcpy(&char_buffer[0], propose_out_bytes, propose_out_size);
	memcpy(&char_buffer[propose_out_size], propose_in_bytes, propose_in_size);
	memcpy(&char_buffer[propose_in_size + propose_out_size], &local_session->ephemeral_private_key->public_key->bytes[1], local_session->ephemeral_private_key->public_key->bytes_size-1);

	// send Exchange packet
	exchange_out = libp2p_secio_exchange_build(local_session, private_key, char_buffer, char_buffer_length);
	if (exchange_out == NULL)
		goto exit;

	exchange_out_protobuf_size = libp2p_secio_exchange_protobuf_encode_size(exchange_out);
	exchange_out_protobuf = (unsigned char*)malloc(exchange_out_protobuf_size);
	if (exchange_out_protobuf == NULL)
		goto exit;
	libp2p_secio_exchange_protobuf_encode(exchange_out, exchange_out_protobuf, exchange_out_protobuf_size, &bytes_written);
	exchange_out_protobuf_size = bytes_written;

	outgoing.data = exchange_out_protobuf;
	outgoing.data_size = exchange_out_protobuf_size;
	bytes_written = libp2p_secio_unencrypted_write(secio_context->stream, &outgoing);
	if (exchange_out_protobuf_size != bytes_written) {
		libp2p_logger_error("secio", "Unable to write exchange_out\n");
		goto exit;
	} else {
		libp2p_logger_debug("secio", "Sent exchange_out. Size: %d.\n", bytes_written);
	}
	free(exchange_out_protobuf);
	exchange_out_protobuf = NULL;
	// end of send Exchange packet

	// receive Exchange packet
	libp2p_logger_log("secio", LOGLEVEL_DEBUG, "Reading exchange packet\n");
	bytes_written = libp2p_secio_unencrypted_read(secio_context->stream, &incoming, 10);
	if (bytes_written == 0) {
		libp2p_logger_error("secio", "unable to read exchange packet.\n");
		libp2p_peer_handle_connection_error(remote_peer);
		goto exit;
	} else {
		libp2p_logger_debug("secio", "Read exchange packet. Size: %d.\n", bytes_written);
	}
	libp2p_secio_exchange_protobuf_decode(incoming->data, incoming->data_size, &exchange_in);
	libp2p_stream_message_free(incoming);
	incoming = NULL;
	// end of receive Exchange packet

	// parse and verify
	local_session->remote_ephemeral_public_key_size = exchange_in->epubkey_size + 1;
	local_session->remote_ephemeral_public_key = malloc(local_session->remote_ephemeral_public_key_size);
	local_session->remote_ephemeral_public_key[0] = exchange_in->epubkey_size;
	memcpy(&local_session->remote_ephemeral_public_key[1], exchange_in->epubkey, exchange_in->epubkey_size);

	// signature verification
	char_buffer_length = propose_in_size + propose_out_size + local_session->remote_ephemeral_public_key_size - 1;
	char_buffer = malloc(char_buffer_length);
	if (char_buffer == NULL) {
		libp2p_logger_error("secio", "Unable to allocate memory for signature verification.\n");
		goto exit;
	}
	memcpy(&char_buffer[0], propose_in_bytes, propose_in_size);
	memcpy(&char_buffer[propose_in_size], propose_out_bytes, propose_out_size);
	memcpy(&char_buffer[propose_in_size + propose_out_size], &local_session->remote_ephemeral_public_key[1], local_session->remote_ephemeral_public_key_size - 1);
	if (!libp2p_secio_verify_signature(public_key, (unsigned char*)char_buffer, char_buffer_length, exchange_in->signature)) {
		libp2p_logger_error("secio", "Unable to verify signature.\n");
		goto exit;
	}
	free(char_buffer);
	char_buffer = NULL;

	// 2.2 generate shared key
	if (!libp2p_crypto_ephemeral_generate_shared_secret(local_session->ephemeral_private_key, local_session->remote_ephemeral_public_key, local_session->remote_ephemeral_public_key_size)) {
		libp2p_logger_error("secio", "Unable to generte shared secret.\n");
		goto exit;
	}

	local_session->shared_key_size = local_session->ephemeral_private_key->public_key->shared_key_size;
	local_session->shared_key = malloc(local_session->shared_key_size);
	memcpy(local_session->shared_key, local_session->ephemeral_private_key->public_key->shared_key, local_session->shared_key_size);

	// generate 2 sets of keys (stretching)
	if (!libp2p_secio_stretch_keys(local_session->chosen_cipher, local_session->chosen_hash, local_session->shared_key, local_session->shared_key_size, &k1, &k2)) {
		libp2p_logger_error("secio", "Unable to stretch keys.\n");
		goto exit;
	}

	//libp2p_logger_debug("secio", "Order value is %d.\n", order);
	if (order > 0) {
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
		libp2p_logger_error("secio", "Unable to pick a hash function.\n");
		goto exit;
	}

	// this doesn't do much. It is here to match the GO code and maybe eventually remind us
	// that there is more work to do for compatibility to GO
	libp2p_secio_make_mac_and_cipher(local_session, local_session->local_stretched_key);
	libp2p_secio_make_mac_and_cipher(local_session, local_session->remote_stretched_key);

	// now we actually start encrypting things...

	libp2p_secio_initialize_crypto(local_session);

	// send their nonce to verify encryption works
	outgoing.data = (uint8_t*)local_session->remote_nonce;
	outgoing.data_size = 16;
	if (libp2p_secio_encrypted_write(secio_context, &outgoing) <= 0) {
		libp2p_logger_error("secio", "Encrytped write returned 0 or less.\n");
		goto exit;
	}

	// receive our nonce to verify encryption works
	libp2p_logger_log("secio", LOGLEVEL_DEBUG, "Receiving our nonce\n");
	results = NULL;
	int bytes_read = libp2p_secio_encrypted_read(secio_context, &incoming, 10);
	if (bytes_read <= 0 || incoming == NULL) {
		libp2p_logger_error("secio", "Encrypted read returned %d\n", bytes_read);
		goto exit;
	}
	if (incoming->data_size != 16) {
		libp2p_logger_error("secio", "Results_size should be 16 but was %d\n", incoming->data_size);
		goto exit;
	}
	if (libp2p_secio_bytes_compare(incoming->data, (unsigned char*)local_session->local_nonce, 16) != 0) {
		libp2p_logger_error("secio", "Bytes of nonce did not match\n");
		goto exit;
	}

	libp2p_stream_message_free(incoming);
	incoming = NULL;

	// set up the secure stream in the struct
	local_session->secure_stream = local_session->insecure_stream;
	local_session->secure_stream->read = libp2p_secio_encrypted_read;
	local_session->secure_stream->write = libp2p_secio_encrypted_write;
	// set secure as default
	local_session->default_stream = local_session->secure_stream;

	retVal = 1;

	//libp2p_logger_log("secio", LOGLEVEL_DEBUG, "Handshake complete\n");
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
	if (exchange_out != NULL)
		libp2p_secio_exchange_free(exchange_out);
	if (exchange_out_protobuf != NULL)
		free(exchange_out_protobuf);
	if (exchange_in != NULL)
		libp2p_secio_exchange_free(exchange_in);

	libp2p_secio_propose_free(propose_out);
	libp2p_secio_propose_free(propose_in);
	libp2p_stream_message_free(incoming);

	if (retVal != 1) {
		libp2p_logger_log("secio", LOGLEVEL_DEBUG, "Handshake returning false\n");
	}
	return retVal;
}

int libp2p_secio_peek(void* stream_context) {
	if (stream_context == NULL) {
		return -1;
	}
	struct SecioContext* ctx = (struct SecioContext*)stream_context;
	return ctx->stream->parent_stream->peek(ctx->stream->parent_stream->stream_context);
}

int libp2p_secio_read_raw(void* stream_context, uint8_t* buffer, int buffer_size, int timeout_secs) {
	if (stream_context == NULL) {
		return -1;
	}
	struct SecioContext* ctx = (struct SecioContext*)stream_context;
	if (ctx->buffered_message_pos == -1) {
		// we need to get info from the network
		if (!ctx->stream->read(ctx->stream->stream_context, &ctx->buffered_message, timeout_secs)) {
			return -1;
		}
		ctx->buffered_message_pos = 0;
	}
	int max_to_read = (buffer_size > ctx->buffered_message->data_size ? ctx->buffered_message->data_size : buffer_size);
	memcpy(buffer, &ctx->buffered_message->data[ctx->buffered_message_pos], max_to_read);
	ctx->buffered_message_pos += max_to_read;
	if (ctx->buffered_message_pos == ctx->buffered_message->data_size) {
		// we read everything
		libp2p_stream_message_free(ctx->buffered_message);
		ctx->buffered_message = NULL;
		ctx->buffered_message_pos = -1;
	} else {
		// we didn't read everything.
		ctx->buffered_message_pos = max_to_read;
	}
	return max_to_read;
}

int libp2p_secio_close(struct Stream* stream) {
	if (stream != NULL && stream->stream_context != NULL)
		free(stream->stream_context);
	return 1;
}

/***
 * Initiates a secio handshake. Use this method when you want to initiate a secio
 * session. This should not be used to respond to incoming secio requests
 * @param parent_stream the parent stream
 * @param remote_peer the remote peer
 * @param peerstore the peerstore
 * @param rsa_private_key the local private key
 * @returns a Secio Stream
 */
struct Stream* libp2p_secio_stream_new(struct Stream* parent_stream, struct Libp2pPeer* remote_peer, struct Peerstore* peerstore, struct RsaPrivateKey* rsa_private_key) {
	struct Stream* new_stream = libp2p_stream_new();
	if (new_stream != NULL) {
		new_stream->stream_type = STREAM_TYPE_SECIO;
		struct SecioContext* ctx = (struct SecioContext*) malloc(sizeof(struct SecioContext));
		if (ctx == NULL) {
			libp2p_stream_free(new_stream);
			new_stream = NULL;
			return NULL;
		}
		ctx->buffered_message = NULL;
		ctx->buffered_message_pos = -1;
		new_stream->stream_context = ctx;
		ctx->stream = new_stream;
		ctx->session_context = remote_peer->sessionContext;
		ctx->peer_store = peerstore;
		ctx->private_key = rsa_private_key;
		new_stream->parent_stream = parent_stream;
		new_stream->close = libp2p_secio_close;
		new_stream->peek = libp2p_secio_peek;
		new_stream->read = libp2p_secio_encrypted_read;
		new_stream->read_raw = libp2p_secio_read_raw;
		new_stream->write = libp2p_secio_encrypted_write;
		if (!libp2p_secio_send_protocol(parent_stream)
				|| !libp2p_secio_receive_protocol(parent_stream)
				|| !libp2p_secio_handshake(ctx)) {
			libp2p_stream_free(new_stream);
			new_stream = NULL;
		}
	}
	return new_stream;
}

