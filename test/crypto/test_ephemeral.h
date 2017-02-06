#include <stdlib.h>

#include "libp2p/crypto/ephemeral.h"
/**
 * Try to generate an ephemeral private key
 */
int test_ephemeral_key_generate() {
	struct EphemeralPrivateKey* private_key;
	int retVal = libp2p_crypto_ephemeral_key_generate("P-256", &private_key);
	if (retVal && private_key->secret_key > 0 && private_key->public_key->x > 0 && private_key->public_key->y > 0)
		return 1;
	return 0;
}
