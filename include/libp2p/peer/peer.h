#pragma once

#include "multiaddr/multiaddr.h"
#include "libp2p/net/stream.h"
#include "libp2p/crypto/rsa.h"
#include "libp2p/conn/session.h"
//#include "libp2p/conn/dialer.h"

struct Peerstore;
struct Dialer;

enum ConnectionType {
	// sender does not have a connection to the peer, and no extra information (default)
	CONNECTION_TYPE_NOT_CONNECTED = 0,
	// sender has a live connection to the peer
	CONNECTION_TYPE_CONNECTED = 1,
	// sender recently connected to peer
	CONNECTION_TYPE_CAN_CONNECT = 2,
	// sender recently tried to connect to peer repeatedly but failed to connect
	CONNECTION_TYPE_CANNOT_CONNECT = 3
};

struct Libp2pPeer {
	char* id; // protobuf field 1; the ID (aka peer id) of the peer
	size_t id_size; // the length of id
	struct Libp2pLinkedList* addr_head; // protobuf field 2 of multiaddr bytes (repeatable) (stored here as a struct MultiAddr)
	enum ConnectionType connection_type; // protobuf field 3 (a varint)
	struct SessionContext *sessionContext; // not protobuf'd, the current connection to the peer
	int is_local; // not protobuf'd, true if this is the local peer
};

/**
 * create a new Peer struct
 * @returns a struct or NULL if there was a problem
 */
struct Libp2pPeer* libp2p_peer_new();

/**
 * Create a new Peer based on a multiaddress
 * @param in the multiaddress
 * @returns a Peer initialized with the values from "in"
 */
struct Libp2pPeer* libp2p_peer_new_from_multiaddress(const struct MultiAddress* multi_addr);

/**
 * frees resources from a peer struct
 * @param in the peer to free
 */
void libp2p_peer_free(struct Libp2pPeer* in);

/**
 * Attempt to connect to the peer, setting connection_type correctly
 * NOTE: If successful, this will set peer->connection to the stream
 *
 * @param dialer the dialer
 * @param peer the peer to connect to
 * @param peerstore if connection is successfull, will add peer to peerstore
 * @param timeout number of seconds before giving up
 * @returns true(1) on success, false(0) if we could not connect
 */
int libp2p_peer_connect(const struct Dialer* dialer, struct Libp2pPeer* peer, struct Peerstore* peerstore, struct Datastore* datastore, int timeout);

/***
 * Clean up a bad connection
 * @param peer the peer to clean up
 * @returns true(1)
 */
int libp2p_peer_handle_connection_error(struct Libp2pPeer* peer);

/**
 * Make a copy of a peer
 * @param in what is to be copied
 * @returns a new struct, that does not rely on the old
 */
struct Libp2pPeer* libp2p_peer_copy(const struct Libp2pPeer* in);

/**
 * Compare 2 Libp2pPeers
 * @param a side A
 * @param b side B
 * @returns <0 if A wins, 0 if equal, or >0 if B wins
 */
int libp2p_peer_compare(const struct Libp2pPeer* a, const struct Libp2pPeer* b);

/***
 * Determine if the passed in peer and id match
 * @param in the peer to check
 * @param peer_id peer id
 * @param peer_size length of peer_id
 * @returns true if peer matches
 */
int libp2p_peer_matches_id(struct Libp2pPeer* in, const unsigned char* peer_id, int peer_size);

/***
 * Convert peer id to null terminated string
 * @param in the peer object
 * @returns the peer id as a null terminated string
 */
char* libp2p_peer_id_to_string(const struct Libp2pPeer* in);

/***
 * Determine if we are currently connected to this peer
 * @param in the peer to check
 * @returns true(1) if connected
 */
int libp2p_peer_is_connected(struct Libp2pPeer* in);

/**
 * Get an estimate of the necessary size of the buffer to protobuf a particular peer
 * @param in the peer to examine
 * @returns an approximation of the buffer size required (erring on the side of bigger)
 */
size_t libp2p_peer_protobuf_encode_size(struct Libp2pPeer* in);

/**
 * Encode the Peer into a buffer
 * @param in the peer
 * @param buffer where to put it
 * @param max_buffer_size the maximum amount of memory reserved for the buffer
 * @param bytes_written the number of bytes written to the buffer
 * @returns true(1) on success, otherwise 0
 */
int libp2p_peer_protobuf_encode(struct Libp2pPeer* in, unsigned char* buffer, size_t max_buffer_size, size_t* bytes_written);

/**
 * Encode the Peer into a buffer
 * @param in the peer
 * @param buffer where to put it (will be allocated by this function)
 * @param buffer_size the number of bytes written to the buffer
 * @returns true(1) on success, otherwise 0
 */
int libp2p_peer_protobuf_encode_with_alloc(struct Libp2pPeer* in, unsigned char** buffer, size_t *buffer_size);

/**
 * turn an array of bytes into a Peer
 * @param in the protobuf formatted peer
 * @param in_size the size of in
 * @param out the new Peer
 * @returns true(1) on success, otherwise false
 */
int libp2p_peer_protobuf_decode(unsigned char* in, size_t in_size, struct Libp2pPeer** out);

