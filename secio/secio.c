#include <stdlib.h>
#include <string.h>

#include "libp2p/secio/secio.h"
#include "libp2p/secio/propose.h"

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
	int retVal = 0, protobuf_size = 0, results_size = 0;
	unsigned char* protobuf = 0;;
	unsigned char* results;
	struct Propose* propose = NULL;
	struct SocketMuxer* socketMuxer;

	// generate 16 byte nonce
	char nonceOut[16];
	if (!generateNonce(&nonceOut, 16)) {
		goto exit;
	}

	propose = libp2p_secio_propose_new();
	libp2p_secio_propose_set_property(&propose->rand, &propose->rand_size, nonceOut, 16);

	// will need:
	// TODO: public key
	// supported exchanges
	libp2p_secio_propose_set_property(&propose->exchanges, &propose->exchanges_size, SupportedExchanges, strlen(SupportedExchanges));
	// supported ciphers
	libp2p_secio_propose_set_property(&propose->ciphers, &propose->ciphers_size, SupportedCiphers, strlen(SupportedCiphers));
	// supported hashes
	libp2p_secio_propose_set_property(&propose->hashes, &propose->exchanges_size, SupportedHashes, strlen(SupportedHashes));

	// send request (protobuf, then send)
	protobuf_size = libp2p_secio_propose_protobuf_encode_size(propose);
	protobuf = (unsigned char*) malloc(protobuf_size);
	if (protobuf == NULL)
		goto exit;
	if (!libp2p_secio_propose_protobuf_encode(propose, protobuf, protobuf_size, &protobuf_size))
		goto exit;
	libp2p_secio_propose_free(propose);
	if (!libp2p_net_socket_muxer_send(socketMuxer, protobuf, protobuf_size))
		goto exit;

	// receive response (turn back into a Propose struct)
	if (!libp2p_net_socket_muxer_receive(socketMuxer, &results, &results_size))
		goto exit;
	if (!libp2p_secio_propose_protobuf_decode(results, results_size, &propose))
		goto exit;

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

	retVal = 1;

	exit:

	ipfs_secio_propose_free(propose);
	if (protobuf != NULL)
		free(protobuf);

	return retVal;

}
