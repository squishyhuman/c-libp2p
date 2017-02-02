#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "libp2p/secio/secio.h"
#include "libp2p/secio/propose.h"
//#include "libp2p/net/p2pnet.h"
#include "libp2p/net/multistream.h"

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
	results = "abcdefghijklmno";
	return 1;
}

/***
 * performs initial communication over an insecure channel to share
 * keys, IDs, and initiate connection. This is a framed messaging system
 * @param session the secure session to be filled
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_secio_handshake(struct SecureSession* session, struct RsaPrivateKey* private_key) {
	int retVal = 0, bytes_written = 0;
	size_t protobuf_size = 0, results_size = 0;
	unsigned char* protobuf = 0;
	unsigned char* results = NULL;
	struct Propose* propose_out = NULL;
	struct Propose* propose_in = NULL;
	struct PublicKey* public_key = NULL;

	// generate 16 byte nonce
	char nonceOut[16];
	if (!libp2p_secio_generate_nonce(&nonceOut[0], 16)) {
		goto exit;
	}

	propose_out = libp2p_secio_propose_new();
	libp2p_secio_propose_set_property((void**)&propose_out->rand, &propose_out->rand_size, nonceOut, 16);

	// will need:
	// TODO: public key
	// supported exchanges
	libp2p_secio_propose_set_property((void**)&propose_out->exchanges, &propose_out->exchanges_size, SupportedExchanges, strlen(SupportedExchanges));
	// supported ciphers
	libp2p_secio_propose_set_property((void**)&propose_out->ciphers, &propose_out->ciphers_size, SupportedCiphers, strlen(SupportedCiphers));
	// supported hashes
	libp2p_secio_propose_set_property((void**)&propose_out->hashes, &propose_out->exchanges_size, SupportedHashes, strlen(SupportedHashes));

	// send request (protobuf, then send)
	protobuf_size = libp2p_secio_propose_protobuf_encode_size(propose_out);
	protobuf = (unsigned char*) malloc(protobuf_size);
	if (protobuf == NULL)
		goto exit;
	if (!libp2p_secio_propose_protobuf_encode(propose_out, protobuf, protobuf_size, &protobuf_size))
		goto exit;

	// connect to host
	session->socket_descriptor = libp2p_net_multistream_connect(session->host, session->port);

	bytes_written = libp2p_net_multistream_send(session->socket_descriptor, protobuf, protobuf_size);
	if (bytes_written <= 0)
		goto exit;

	// receive response (turn back into a Propose struct)
	bytes_written = libp2p_net_multistream_receive(session->socket_descriptor, (char**)&results, &results_size);
	if (bytes_written == 65535)
		goto exit;

	if (!libp2p_secio_propose_protobuf_decode(results, results_size, &propose_in))
		goto exit;

	// get public key
	if (!libp2p_crypto_public_key_protobuf_decode(propose_in->public_key, propose_in->public_key_size, &public_key))
		goto exit;
	// generate their peer id
	char* remote_peer_id;
	libp2p_crypto_public_key_to_peer_id(public_key, &remote_peer_id);

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

	libp2p_secio_propose_free(propose_out);
	libp2p_secio_propose_free(propose_in);
	if (protobuf != NULL)
		free(protobuf);

	return retVal;

}
