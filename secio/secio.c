#include <stdio.h>
#include "libp2p/secio/secio.h"

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

/***
 * performs initial communication over an insecure channel to share
 * keys, IDs, and initiate connection. This is a framed messaging system
 * @param session the secure session to be filled
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_secio_secure_session_handshake(struct SecureSession* session, struct RsaPrivateKey* private_key) {

	// generate 16 byte nonce
	char nonceOut[16];
	if (!generateNonce(nonceOut, 16))
		return 0;

	// will need:
	// public key
	// supported exchanges
	// supported ciphers
	// supported hashes

	// send request
	// receive response

	// get public key
	// generate their peer id

	// negotiate encryption parameters NOTE: SelectBest must match, otherwise this won't work
	// curve
	// cipher
	// hash

	// prepare exchange of encryption parameters

	// send

	// receive

	// parse and verify

	// generate keys for mac and encryption

	// send expected message (local nonce) to verify encryption works

}
