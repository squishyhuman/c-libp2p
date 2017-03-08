#include <stdlib.h>
#include <string.h>

#include "mbedtls/config.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "libp2p/crypto/ephemeral.h"

struct StretchedKey* libp2p_crypto_ephemeral_stretched_key_new() {
	struct StretchedKey* key = (struct StretchedKey*)malloc(sizeof(struct StretchedKey));
	if (key != NULL) {
		key->cipher_key = NULL;
		key->cipher_size = 0;
		key->iv = NULL;
		key->iv_size = 0;
		key->mac_key = NULL;
		key->mac_size = 0;
	}
	return key;
}

void libp2p_crypto_ephemeral_stretched_key_free(struct StretchedKey* key) {
	if (key != NULL) {
		if (key->cipher_key != NULL)
			free(key->cipher_key);
		if (key->iv != NULL)
			free(key->iv);
		if (key->mac_key != NULL)
			free(key->mac_key);
		free(key);
	}
}

struct EphemeralPrivateKey* libp2p_crypto_ephemeral_key_new() {
	struct EphemeralPrivateKey* results = (struct EphemeralPrivateKey*)malloc(sizeof(struct EphemeralPrivateKey));
	if (results != NULL) {
		results->num_bits = 0;
		results->secret_key = 0;
		results->public_key = (struct EphemeralPublicKey*)malloc(sizeof(struct EphemeralPublicKey));
		if (results->public_key == NULL) {
			free(results);
			results = NULL;
		} else {
			results->public_key->bytes = NULL;
			results->public_key->bytes_size = 0;
			results->public_key->shared_key = NULL;
			results->public_key->shared_key_size = 0;
		}
	}
	return results;
}

void libp2p_crypto_ephemeral_key_free(struct EphemeralPrivateKey* in) {
	if (in != NULL) {
		mbedtls_ecdh_free(&in->ctx);
		if (in->public_key != NULL) {
			if (in->public_key->bytes != NULL)
				free(in->public_key->bytes);
			if (in->public_key->shared_key != NULL)
				free(in->public_key->shared_key);
			free(in->public_key);
		}
		free(in);
	}
}

void serialize_uint64(const uint64_t in, unsigned char out[8]) {
	out[0] = in >> 56;
	out[1] = in >> 48;
	out[2] = in >> 40;
	out[3] = in >> 32;
	out[4] = in >> 24;
	out[5] = in >> 16;
	out[6] = in >> 8;
	out[7] = in;
}

uint64_t unserialize_uint64(unsigned char in[8]) {
	uint64_t out = 0;

	out = (out << 8) | in[0];
	out = (out << 8) | in[1];
	out = (out << 8) | in[2];
	out = (out << 8) | in[3];
	out = (out << 8) | in[4];
	out = (out << 8) | in[5];
	out = (out << 8) | in[6];
	out = (out << 8) | in[7];
	return out;
}

/***
 * Take the public pieces of an ephemeral key and turn them into a byte stream
 * @param bit_size the curve bit size
 * @param x the x parameter of the ephemeral key
 * @param y the y parameter of the ephemeral key
 * @param results where to put the bytes
 * @param bytes_written how many bytes were written to results
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_ephemeral_point_marshal(int bit_size, uint64_t x, uint64_t y, unsigned char** results, size_t* bytes_written) {
	int byteLen = (bit_size + 7) >> 3;

	// bytelen is 32, and we never fill in from 1 to 33. hmmm....
	*results = (unsigned char*)malloc(2*byteLen+1);
	memset(*results, 0, 2*byteLen+1);
	*results[0] = 4; // uncompressed point
	int uint64_len = 8;
	unsigned char buffer[8];
	serialize_uint64(x, &buffer[0]);
	int pos = 1 + byteLen - uint64_len;
	memcpy(&(*results)[pos], &buffer[0], 8);
	serialize_uint64(y, &buffer[0]);
	pos = 1 + 2*byteLen - uint64_len;
	memcpy(&(*results)[pos], &buffer[0], 8);
	*bytes_written = 2 * byteLen + 1;
	return 1;
}

int libp2p_crypto_ephemeral_point_unmarshal(int bit_size, unsigned char* buffer, size_t buffer_length, uint64_t* x, uint64_t* y) {
	int byteLen = (bit_size + 7) >> 3;

	if (buffer_length != 2 * byteLen + 1)
		return 0;
	if (buffer[0] != 4)
		return 0;
	unsigned char temp[8];
	memcpy((char*)temp, &buffer[1], 8);
	*x = unserialize_uint64(temp);
	memcpy((char*)temp, &buffer[9], 8);
	*y = unserialize_uint64(temp);
	return 1;
}

/**
 * Generate a Ephemeral keypair
 * @param curve the curve to use (P-256, P-384, or P-521)
 * @param private_key the struct to store the generated key
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_ephemeral_keypair_generate(char* curve, struct EphemeralPrivateKey** private_key_ptr) {
	int retVal = 0;
	//mbedtls_ecdh_context ctx;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	struct EphemeralPrivateKey* private_key = NULL;
	struct EphemeralPublicKey* public_key = NULL;
	int selected_curve = 0;
	char* pers = "bitShares"; // data for seeding random number generator

	if (strcmp(curve, "P-256") == 0)
		selected_curve = MBEDTLS_ECP_DP_SECP256R1;
	else if (strcmp(curve, "P-384") == 0)
		selected_curve = MBEDTLS_ECP_DP_SECP384R1;
	else
		selected_curve = MBEDTLS_ECP_DP_SECP521R1;

	// allocate memory for result storage
	*private_key_ptr = libp2p_crypto_ephemeral_key_new();
	private_key = *private_key_ptr;
	public_key = private_key->public_key;

	mbedtls_ecdh_init(&private_key->ctx);

	// seed random number generator
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers)) != 0)
		goto exit;

	// Prepare to generate the public key
	if (mbedtls_ecp_group_load(&private_key->ctx.grp, selected_curve) != 0)
		goto exit;

	// create and marshal public key
	public_key->bytes_size = 66;
	public_key->bytes = (unsigned char*)malloc(public_key->bytes_size);
	if (mbedtls_ecdh_make_public(&private_key->ctx, &public_key->bytes_size, (char*)public_key->bytes, public_key->bytes_size, mbedtls_ctr_drbg_random, &ctr_drbg) != 0)
		goto exit;

	// ship all this stuff back to the caller
	retVal = 1;
	exit:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return retVal;
}

/**
 * Generate a public key from a private key
 * @param public key
 * @param results the results
 * @param bytes_written the number of bytes written
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_ephemeral_keypair_to_public_bytes(struct EphemeralPublicKey* public_key, unsigned char** results, size_t* bytes_written) {
	return libp2p_crypto_ephemeral_point_marshal(public_key->num_bits, public_key->x, public_key->y, results, bytes_written);
}

/**
 * Generate a shared secret
 * @param private_key the context, also where it puts the shared secret
 * @param remote_public_key the key the remote gave us
 * @param remote_public_key_size the size of the remote public key
 * @reutrns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_ephemeral_generate_shared_secret(struct EphemeralPrivateKey* private_key, const unsigned char* remote_public_key, size_t remote_public_key_size) {
	int retVal = 0;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	char* pers = "bitShares"; // data for seeding random number generator

	// seed random number generator
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers)) != 0)
		goto exit;

	// read the remote key
	if (mbedtls_ecdh_read_public(&private_key->ctx, remote_public_key, remote_public_key_size) < 0)
		goto exit;

	// generate the shared key
	// reserve some memory for the shared key
	//TODO: set this to something reasonable
	private_key->public_key->shared_key_size = 100;
	private_key->public_key->shared_key = malloc(private_key->public_key->shared_key_size);
	if (mbedtls_ecdh_calc_secret(&private_key->ctx,
			&private_key->public_key->shared_key_size, private_key->public_key->shared_key, private_key->public_key->shared_key_size,
			mbedtls_ctr_drbg_random, &ctr_drbg) != 0)
		goto exit;

	retVal = 1;
	exit:
	return retVal;

}

