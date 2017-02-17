#pragma once

#include "libp2p/record/record.h"

/**
 * protobuf stuff for Message and Peer
 * This is used for the KAD / DHT stuff
 */

enum MessageType {
	MESSAGE_TYPE_PUT_VALUE = 0,
	MESSAGE_TYPE_GET_VALUE = 1,
	MESSAGE_TYPE_ADD_PROVIDER = 2,
	MESSAGE_TYPE_GET_PROVIDERS = 3,
	MESSAGE_TYPE_FIND_NODE = 4,
	MESSAGE_TYPE_PING = 5
};

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
	char* id; // protobuf field 1
	size_t id_size;
	struct Libp2pLinkedList* addr_head; // protobuf field 2 of multiaddr bytes (repeatable) (stored here as a Libp2pVector)
	enum ConnectionType connection_type; // protobuf field 3 (a varint)
};

struct Libp2pMessage {
	enum MessageType message_type; // protobuf field 1 (a varint)
	char* key; // protobuf field 2
	size_t key_size;
	struct Libp2pRecord* record; // protobuf field 3
	struct Libp2pLinkedList* closer_peer_head; // protobuf field 8
	struct Libp2pLinkedList* provider_peer_head; // protobuf field 9
	int32_t cluster_level_raw; // protobuf field 10
};

/**
 * create a new Peer struct
 * @returns a struct or NULL if there was a problem
 */
struct Libp2pPeer* libp2p_message_peer_new();

/**
 * frees resources from a peer struct
 * @param in the peer to free
 */
void libp2p_message_peer_free(struct Libp2pPeer* in);

/**
 * Get an estimate of the necessary size of the buffer to protobuf a particular peer
 * @param in the peer to examine
 * @returns an approximation of the buffer size required (erring on the side of bigger)
 */
size_t libp2p_message_peer_protobuf_encode_size(struct Libp2pPeer* in);

/**
 * Encode the Peer into a buffer
 * @param in the peer
 * @param buffer where to put it
 * @param max_buffer_size the maximum amount of memory reserved for the buffer
 * @param bytes_written the number of bytes written to the buffer
 * @returns true(1) on success, otherwise 0
 */
int libp2p_message_peer_protobuf_encode(struct Libp2pPeer* in, unsigned char* buffer, size_t max_buffer_size, size_t* bytes_written);

/**
 * turn an array of bytes into a Peer
 * @param in the protobuf formatted peer
 * @param in_size the size of in
 * @param out the new Peer
 * @returns true(1) on success, otherwise false
 */
int libp2p_message_peer_protobuf_decode(unsigned char* in, size_t in_size, struct Libp2pPeer** out);

/**
 * create a new Libp2pMessage struct
 * @returns a new Libp2pMessage with default settings
 */
struct Libp2pMessage* libp2p_message_new();

/**
 * Deallocate memory from a Message struct
 * @param in the struct
 */
void libp2p_message_free(struct Libp2pMessage* in);

/**
 * determine the size necessary for a message struct to be protobuf'd
 * @param in the struct to be protobuf'd
 * @returns the size required
 */
size_t libp2p_message_protobuf_encode_size(struct Libp2pMessage* in);

/**
 * Encode a Message into a protobuf
 * @param in the message
 * @param buffer the byte array that will hold the protobuf
 * @param max_buffer_size the amount of memory previously reserved for buffer
 * @param bytes_written will hold the number of bytes written to buffer
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_message_protobuf_encode(struct Libp2pMessage* in, unsigned char* buffer, size_t max_buffer_size, size_t* bytes_written);

/**
 * turn a protobuf back into a message
 * @param buffer the protobuf
 * @param buffer_size the length of the buffer
 * @param out the message
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_message_protobuf_decode(unsigned char* buffer, size_t buffer_size, struct Libp2pMessage** out);
