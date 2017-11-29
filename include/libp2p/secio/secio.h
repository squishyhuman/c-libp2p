#pragma once

#include "libp2p/crypto/key.h"
#include "libp2p/crypto/rsa.h"
#include "libp2p/conn/session.h"
#include "libp2p/peer/peerstore.h"
#include "libp2p/net/protocol.h"

/**
 * Handling of a secure connection
 */

enum SecioStatus {
	secio_status_unknown,
	secio_status_initialized,
	secio_status_syn,
	secio_status_ack
};

struct SecioContext {
	struct Stream* stream;
	struct SessionContext* session_context;
	struct RsaPrivateKey* private_key;
	struct Peerstore* peer_store;
	struct StreamMessage* buffered_message;
	size_t buffered_message_pos;
	volatile enum SecioStatus status;
};

struct Libp2pProtocolHandler* libp2p_secio_build_protocol_handler(struct RsaPrivateKey* private_key, struct Peerstore* peer_store);

/***
 * Initiates a secio handshake. Use this method when you want to initiate a secio
 * session. This should not be used to respond to incoming secio requests
 * @param parent_stream the parent stream
 * @param peerstore the peerstore
 * @param rsa_private_key the local private key
 * @returns a Secio Stream
 */
struct Stream* libp2p_secio_stream_new(struct Stream* parent_stream, struct Peerstore* peerstore, struct RsaPrivateKey* rsa_private_key);

/***
 * Initiates a secio handshake. Use this method when you want to initiate a secio
 * session. This should not be used to respond to incoming secio requests
 * @param ctx the SecioContext
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_secio_initiate_handshake(struct SecioContext* ctx);

/***
 * Send the protocol string to the remote stream
 * @param stream stream
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_secio_send_protocol(struct Stream* stream);

/***
 * Attempt to read the secio protocol as a reply from the remote
 * @param session the context
 * @returns true(1) if we received what we think we should have, false(0) otherwise
 */
int libp2p_secio_receive_protocol(struct Stream* stream);

/***
 * performs initial communication over an insecure channel to share
 * keys, IDs, and initiate connection. This is a framed messaging system
 * NOTE: session must contain a valid socket_descriptor that is a multistream.
 * @param secio_stream a stream that is a Secio stream
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_secio_handshake(struct Stream* secio_stream);

/***
 * Wait for secio stream to become ready
 * @param session_context the session context to check
 * @param timeout_secs the number of seconds to wait for things to become ready
 * @returns true(1) if it becomes ready, false(0) otherwise
 */
int libp2p_secio_ready(struct SessionContext* session_context, int timeout_secs);

