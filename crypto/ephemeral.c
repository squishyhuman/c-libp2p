#include <stdlib.h>
#include <string.h>

#include "mbedtls/config.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "libp2p/crypto/ephemeral.h"

struct EphemeralPrivateKey* libp2p_crypto_ephemeral_key_new(uint64_t priv, uint64_t x, uint64_t y, size_t num_bits) {
	struct EphemeralPrivateKey* results = (struct EphemeralPrivateKey*)malloc(sizeof(struct EphemeralPrivateKey));
	if (results != NULL) {
		results->secret_key = priv;
		results->num_bits = num_bits;
		results->public_key = (struct EphemeralPublicKey*)malloc(sizeof(struct EphemeralPublicKey));
		if (results->public_key == NULL) {
			free(results);
			results = NULL;
		} else {
			results->public_key->x = x;
			results->public_key->y = y;
			results->public_key->num_bits = num_bits;
		}
	}
	return results;
}

void libp2p_crypto_ephemeral_key_free(struct EphemeralPrivateKey* in) {
	if (in != NULL) {
		if (in->public_key != NULL)
			free(in->public_key);
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

	*results = (unsigned char*)malloc(2*byteLen+1);
	*results[0] = 4; // uncompressed point
	int uint64_len = 8;
	unsigned char buffer[8];
	serialize_uint64(x, &buffer[0]);
	memcpy(&(*results)[1 + byteLen - uint64_len], &buffer[0], 8);
	serialize_uint64(y, &buffer[0]);
	memcpy(&(*results)[1 + 2*byteLen - uint64_len], &buffer[0], 8);
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
int libp2p_crypto_ephemeral_keypair_generate(char* curve, struct EphemeralPrivateKey** private_key) {
	int retVal = 0;
	mbedtls_ecdsa_context ctx;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	int selected_curve = 0;
	if (strcmp(curve, "P-256") == 0)
		selected_curve = MBEDTLS_ECP_DP_SECP256R1;
	else if (strcmp(curve, "P-384") == 0)
		selected_curve = MBEDTLS_ECP_DP_SECP384R1;
	else
		selected_curve = MBEDTLS_ECP_DP_SECP521R1;

	char* pers = "bitShares";

	mbedtls_ecdsa_init(&ctx);

	// seed random number generator
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers)) != 0)
		goto exit;

	if (mbedtls_ecdsa_genkey(&ctx, selected_curve, mbedtls_ctr_drbg_random, &ctr_drbg) != 0)
		goto exit;

	*private_key = libp2p_crypto_ephemeral_key_new(*ctx.d.p, *ctx.Q.X.p, *ctx.Q.Y.p, ctx.grp.nbits);
	retVal = 1;

	exit:

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

/***
 * Generate a shared secret from a private key
 * @param private key
 * @param results
 */
int libp2p_crypto_ephemeral_keypair_to_shared_secret(struct EphemeralPrivateKey* private_key, unsigned char** results, size_t* bytes_written) {
	// grab a scalar mult

	// in GO, ScalarMult turns the bytes of the private key into a multiplier
	// for the points
	/*
	 * Multiplication R = m * P
	 */
	/*
	int mbedtls_ecp_mul( mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
            const mbedtls_mpi *m, const mbedtls_ecp_point *P,
            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
    */
	// turn it into bytes

	//TODO: implement
	return 0;
}
