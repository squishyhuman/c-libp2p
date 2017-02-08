#include <stdlib.h>
#include <stdio.h> // for debugging, can remove
#include <string.h>
#include <stdint.h>

#include "libp2p/secio/secio.h"
#include "libp2p/secio/propose.h"
#include "libp2p/secio/exchange.h"
#include "libp2p/net/multistream.h"
#include "libp2p/crypto/ephemeral.h"
#include "libp2p/crypto/sha1.h"
#include "libp2p/crypto/sha256.h"
#include "libp2p/crypto/sha512.h"
#include "libp2p/utils/string_list.h"
#include "libp2p/utils/vector.h"

const char* SupportedExchanges = "P-256,P-384,P-521";
const char* SupportedCiphers = "AES-256,AES-128,Blowfish";
const char* SupportedHashes = "SHA256,SHA512";

/***
 * Create a new SecureSession struct
 * @returns a pointer to a new SecureSession object
 */
struct SecureSession* libp2p_secio_secure_session_new() {
	struct SecureSession* ss = (struct SecureSession*) malloc(sizeof(struct SecureSession));
	if (ss == NULL)
		return NULL;
	ss->socket_descriptor = -1;
	return ss;
}

/***
 * Clean up resources from a SecureSession struct
 * @param in the SecureSession to be deallocated
 */
void libp2p_secio_secure_session_free(struct SecureSession* in) {
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
int libp2p_secio_hash(struct Propose* in, unsigned char result[32]) {
	// append public key and nonce
	char buffer[in->public_key_size + in->rand_size];
	memcpy(buffer, in->public_key, in->public_key_size);
	memcpy(&buffer[in->public_key_size], in->rand, in->rand_size);
	return libp2p_crypto_hashing_sha256(buffer, in->public_key_size + in->rand_size, result);
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
		libp2p_utils_string_list_free(lead_head);
		return 1;
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
	if (!match)
		return 0;
	return 1;
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
		struct RsaPublicKey rsa_key;
		rsa_key.der = (char*)public_key->data;
		rsa_key.der_length = public_key->data_size;
		return libp2p_crypto_rsa_verify(&rsa_key, in, in_length, signature);
	}
	// TODO: Implement this method for non-RSA
	return 0;
}

int libp2p_secio_sign(struct PrivateKey* private_key, unsigned char* in, size_t in_length, unsigned char** signature, size_t* signature_size) {
	if (private_key->type == KEYTYPE_RSA) {
		struct RsaPrivateKey rsa_key;
		rsa_key.der = (char*)private_key->data;
		rsa_key.der_length = private_key->data_size;
		// SHA2-256 signatures are 32 bytes
		*signature = (unsigned char*)malloc(32);
		return libp2p_crypto_rsa_sign(&rsa_key, in, in_length, *signature);
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
	int retVal = 0, hash_size = 0, num_filled = 0, num_needed = 0, hmac_size = 20;
	struct StretchedKey* k1;
	struct StretchedKey* k2;
	unsigned char* result = NULL;;
	size_t result_size = 0;
	int (*hash_func)(const char* input, size_t input_length, unsigned char* results); // pointer to hash function
	char* first_seed = "key_expansion";
	char* second_seed = NULL;
	char* temp = NULL;
	int seed_size = strlen(first_seed);
	unsigned char* current_hash = NULL;

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

	result_size = 2 * (k1->iv_size + k1->cipher_size * hmac_size);
	result = malloc(result_size);
	if (result == NULL)
		goto exit;

	seed_size += secret_size;
	second_seed = malloc(seed_size);
	memcpy(second_seed, secret, secret_size);
	memcpy(&second_seed[secret_size], first_seed, strlen(first_seed));

	current_hash = malloc(hash_size);
	hash_func(second_seed, seed_size, current_hash);

	num_needed = hash_size;
	// now we have our first hash. Begin to fill the result buffer
	while (num_filled < result_size) {
		num_needed = result_size - num_filled;
		if (num_needed > hash_size)
			num_needed = hash_size;
		// combine current_hash with first_seed
		if (temp != NULL)
			free(temp);
		seed_size = secret_size + strlen(first_seed) + hash_size;
		temp = malloc(seed_size);
		memcpy(temp, secret, secret_size);
		memcpy(&temp[secret_size], current_hash, hash_size);
		memcpy(&temp[secret_size + hash_size], first_seed, strlen(first_seed));
		// make a new hash
		hash_func(temp, seed_size, current_hash);
		// copy the hash to results
		memcpy(&result[num_filled], current_hash, num_needed);
		num_filled += num_needed;
		// redo the hashes by adding the secret to the current hash
		free(temp);
		seed_size = secret_size + hash_size;
		temp = malloc(seed_size);
		memcpy(temp, secret, secret_size);
		memcpy(&temp[secret_size], current_hash, hash_size);
		hash_func(temp, seed_size, current_hash);
	}

	// now we have a big result. Cut it up into pieces
	if (temp != NULL)
		free(temp);
	temp = (char*)result;
	k1->iv = malloc(k1->iv_size);
	memcpy(k1->iv, temp, k1->iv_size);
	temp += k1->iv_size;
	k1->cipher_key = malloc(k1->cipher_size);
	memcpy(k1->cipher_key, temp, k1->cipher_size);
	temp += k1->cipher_size;
	k1->mac_key = malloc(k1->mac_size);
	memcpy(k1->mac_key, temp, k1->mac_size);
	temp += k1->mac_size;

	k2->iv = malloc(k2->iv_size);
	memcpy(k2->iv, temp, k2->iv_size);
	temp += k2->iv_size;
	k2->cipher_key = malloc(k2->cipher_size);
	memcpy(k2->cipher_key, temp, k2->cipher_size);
	temp += k2->cipher_size;
	k2->mac_key = malloc(k2->mac_size);
	memcpy(k2->mac_key, temp, k2->mac_size);
	temp += k2->mac_size;

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
	if (current_hash != NULL)
		free(current_hash);
	if (temp != NULL)
		free(temp);
	if (second_seed != NULL)
		free(second_seed);
	if (result != NULL)
		free(result);
	return retVal;
}

int libp2p_secio_make_mac_and_cipher(struct SecureSession* session) {
	// TODO: Implement this method
	return 0;
}

int libp2p_secio_write(struct SecureSession* session, unsigned char* bytes, size_t length) {
	// TODO: Implement this method
	return 0;
}

int libp2p_secio_read(struct SecureSession* session, unsigned char** bytes, size_t* bytes_read) {
	// TODO: Implement this method
	return 0;
}

/***
 * performs initial communication over an insecure channel to share
 * keys, IDs, and initiate connection. This is a framed messaging system
 * NOTE: session must contain a valid socket_descriptor that is a multistream.
 * @param session the secure session to be filled
 * @param private_key our private key to use
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_secio_handshake(struct SecureSession* local_session, struct RsaPrivateKey* private_key) {
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
	unsigned char order_hash_in[32];
	unsigned char order_hash_out[32];
	int order;
	struct Exchange* exchange_out;
	unsigned char* exchange_out_protobuf;
	size_t exchange_out_protobuf_size;
	struct Exchange* exchange_in;
	struct Libp2pVector* char_buffer;
	struct StretchedKey* k1 = NULL, *k2 = NULL;

	const unsigned char* protocol = (unsigned char*)"/secio/1.0.0\n";

	bytes_written = libp2p_net_multistream_send(local_session->socket_descriptor, protocol, strlen((char*)protocol));
	if (bytes_written <= 0)
		goto exit;

	// we should get back the protocol to signify it was accepted, as well as the protobuf of the Propose struct
	bytes_written = libp2p_net_multistream_receive(local_session->socket_descriptor, (char**)&results, &results_size);
	if (bytes_written < 1 || strstr((char*)results, "secio") == NULL)
		goto exit;

	// skip to the protobuf section
	propose_in_bytes = (unsigned char*)strchr((char*)results, '\n');
	if (propose_in_bytes == NULL)
		goto exit;
	propose_in_bytes++;
	propose_in_size  = results_size - (propose_in_bytes - results);

	if (!libp2p_secio_propose_protobuf_decode(propose_in_bytes, propose_in_size, &propose_in))
		goto exit;

	// clear results
	free(results);
	results = NULL;
	results_size = 0;

	// get public key and put it in a struct PublicKey
	if (!libp2p_crypto_public_key_protobuf_decode(propose_in->public_key, propose_in->public_key_size, &public_key))
		goto exit;
	// generate their peer id
	char* remote_peer_id;
	libp2p_crypto_public_key_to_peer_id(public_key, &remote_peer_id);

	//TODO: make sure we're not talking to ourself

	// generate 16 byte nonce
	if (!libp2p_secio_generate_nonce(&local_session->nonce[0], 16)) {
		goto exit;
	}

	propose_out = libp2p_secio_propose_new();
	libp2p_secio_propose_set_property((void**)&propose_out->rand, &propose_out->rand_size, local_session->nonce, 16);

	// we have their information, now we need to gather ours.
	// public key
	propose_out->public_key_size = public_key->data_size;
	propose_out->public_key = (unsigned char*)malloc(public_key->data_size);
	memcpy(propose_out->public_key, public_key->data, public_key->data_size);
	// supported exchanges
	libp2p_secio_propose_set_property((void**)&propose_out->exchanges, &propose_out->exchanges_size, SupportedExchanges, strlen(SupportedExchanges));
	// supported ciphers
	libp2p_secio_propose_set_property((void**)&propose_out->ciphers, &propose_out->ciphers_size, SupportedCiphers, strlen(SupportedCiphers));
	// supported hashes
	libp2p_secio_propose_set_property((void**)&propose_out->hashes, &propose_out->hashes_size, SupportedHashes, strlen(SupportedHashes));
	// negotiate encryption parameters NOTE: SelectBest must match, otherwise this won't work
	// first determine order
	libp2p_secio_hash(propose_in, order_hash_in);
	libp2p_secio_hash(propose_out, order_hash_out);
	order = libp2p_secio_bytes_compare((char*)order_hash_in, (char*)order_hash_out, 32);
	// curve
	libp2p_secio_select_best(order, propose_out->exchanges, propose_out->exchanges_size, propose_in->exchanges, propose_in->exchanges_size, &local_session->chosen_curve);
	// cipher
	libp2p_secio_select_best(order, propose_out->ciphers, propose_out->ciphers_size, propose_in->ciphers, propose_in->ciphers_size, &local_session->chosen_cipher);
	// hash
	libp2p_secio_select_best(order, propose_out->hashes, propose_out->hashes_size, propose_in->hashes, propose_in->hashes_size, &local_session->chosen_hash);

	// prepare exchange of encryption parameters
	struct SecureSession remote_session;
	remote_session.chosen_cipher = local_session->chosen_cipher;
	remote_session.chosen_curve = local_session->chosen_curve;
	remote_session.chosen_hash = local_session->chosen_hash;

	// generate EphemeralPubKey
	struct EphemeralPrivateKey* e_private_key;
	libp2p_crypto_ephemeral_keypair_generate(local_session->chosen_curve, &e_private_key);

	// build buffer to sign
	char_buffer = libp2p_utils_vector_new();
	if (char_buffer == NULL)
		goto exit;
	libp2p_utils_vector_add(char_buffer, propose_in_bytes, propose_in_size);
	libp2p_utils_vector_add(char_buffer, propose_out_bytes, propose_out_size);
	libp2p_utils_vector_add(char_buffer, local_session->ephemeral_public_key, local_session->ephemeral_public_key_size);

	// send Exchange packet
	exchange_out = libp2p_secio_exchange_new();
	exchange_out->epubkey = (unsigned char*)malloc(local_session->ephemeral_public_key_size);
	memcpy(exchange_out->epubkey, local_session->ephemeral_public_key, local_session->ephemeral_public_key_size);
	exchange_out->epubkey_size = local_session->ephemeral_public_key_size;
	struct PrivateKey priv;
	priv.data = (unsigned char*)private_key->der;
	priv.data_size = private_key->der_length;
	libp2p_secio_sign(&priv, char_buffer->buffer, char_buffer->buffer_size, &exchange_out->signature, &exchange_out->signature_size);
	libp2p_utils_vector_free(char_buffer);

	exchange_out_protobuf_size = libp2p_secio_exchange_protobuf_encode_size(exchange_out);
	exchange_out_protobuf = (unsigned char*)malloc(exchange_out_protobuf_size);
	if (exchange_out_protobuf == NULL)
		goto exit;
	libp2p_secio_exchange_protobuf_encode(exchange_out, exchange_out_protobuf, exchange_out_protobuf_size, &bytes_written);
	bytes_written = libp2p_net_multistream_send(local_session->socket_descriptor, exchange_out_protobuf, exchange_out_protobuf_size);
	free(exchange_out_protobuf);

	// receive Exchange packet
	bytes_written = libp2p_net_multistream_receive(local_session->socket_descriptor, (char**)&results, &results_size);
	libp2p_secio_exchange_protobuf_decode(results, results_size, &exchange_in);

	// parse and verify
	remote_session.ephemeral_public_key = exchange_in->epubkey;
	remote_session.ephemeral_public_key_size = exchange_in->epubkey_size;

	char_buffer = libp2p_utils_vector_new();
	if (char_buffer == NULL)
		goto exit;
	libp2p_utils_vector_add(char_buffer, propose_in_bytes, propose_in_size);
	libp2p_utils_vector_add(char_buffer, propose_out_bytes, propose_out_size);
	libp2p_utils_vector_add(char_buffer, remote_session.ephemeral_public_key, remote_session.ephemeral_public_key_size);
	if (!libp2p_secio_verify_signature(public_key, char_buffer->buffer, char_buffer->buffer_size, exchange_in->signature))
		goto exit;
	libp2p_utils_vector_free(char_buffer);

	// 2.2 generate shared key NOTE: this was done above

	// generate 2 sets of keys (stretching)
	libp2p_secio_stretch_keys(local_session->chosen_cipher, local_session->chosen_hash, local_session->shared_key, local_session->shared_key_size, &k1, &k2);

	if (order > 1) {
		local_session->stretched_key = k1;
		remote_session.stretched_key = k2;
	} else {
		local_session->stretched_key = k2;
		remote_session.stretched_key = k1;
	}
	// prepare MAC + cipher

	libp2p_secio_make_mac_and_cipher(local_session);
	libp2p_secio_make_mac_and_cipher(&remote_session);

	// send expected message (local nonce) to verify encryption works
	libp2p_secio_write(local_session, (unsigned char*)local_session->nonce, 16);
	libp2p_secio_read(local_session, &results, &results_size);

	if (results_size != 16)
		goto exit;
	if (libp2p_secio_bytes_compare((char*)results, local_session->nonce, 16) != 0)
		goto exit;

	retVal = 1;

	exit:

	libp2p_secio_propose_free(propose_out);
	libp2p_secio_propose_free(propose_in);

	return retVal;

}
