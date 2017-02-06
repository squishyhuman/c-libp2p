#include <stdlib.h>
#include <string.h>

#include "mbedtls/config.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "libp2p/crypto/ephemeral.h"

struct EphemeralPrivateKey* libp2p_crypto_ephemeral_key_new(uint64_t priv, uint64_t x, uint64_t y) {
	struct EphemeralPrivateKey* results = (struct EphemeralPrivateKey*)malloc(sizeof(struct EphemeralPrivateKey));
	if (results != NULL) {
		results->secret_key = priv;
		results->public_key = (struct EphemeralPublicKey*)malloc(sizeof(struct EphemeralPublicKey));
		if (results->public_key == NULL) {
			free(results);
			results = NULL;
		} else {
			results->public_key->x = x;
			results->public_key->y = y;
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

/**
 * Generate a Ephemeral Public Key as well as a shared key
 * @param curve the curve to use (P-256, P-384, or P-521)
 * @param private_key the struct to store the generated key
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_ephemeral_key_generate(char* curve, struct EphemeralPrivateKey** private_key) {
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

	*private_key = libp2p_crypto_ephemeral_key_new(*ctx.d.p, *ctx.Q.X.p, *ctx.Q.Y.p);
	retVal = 1;

	exit:

	return retVal;
}
