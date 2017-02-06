#pragma once

/**
 * General helpers for ephemeral keys
 */

struct EphemeralPublicKey {
	uint64_t x;
	uint64_t y;
};

struct EphemeralPrivateKey {
	uint64_t secret_key;
	struct EphemeralPublicKey* public_key;
};

/**
 * Generate a Ephemeral Public Key as well as a shared key
 * @param curve the curve to use (P-256, P-384, or P-521)
 * @param private_key where to store the private key
 * @reutrns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_ephemeral_key_generate(char* curve, struct EphemeralPrivateKey* private_key);
