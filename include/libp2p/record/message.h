#pragma once

#include <stdint.h>
#include "libp2p/record/record.h"

/**
 * protobuf stuff for Message
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

struct Libp2pMessage {
	enum MessageType message_type; // protobuf field 1 (a varint)
	char* key; // protobuf field 2
	size_t key_size;
	struct Libp2pRecord* record; // protobuf field 3
	struct Libp2pLinkedList* closer_peer_head; // protobuf field 8 linked list of Libp2pPeers
	struct Libp2pLinkedList* provider_peer_head; // protobuf field 9 linked list of Libp2pPeers
	int32_t cluster_level_raw; // protobuf field 10
};

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
size_t libp2p_message_protobuf_encode_size(const struct Libp2pMessage* in);

/**
 * Encode a Message into a protobuf
 * @param in the message
 * @param buffer the byte array that will hold the protobuf
 * @param max_buffer_size the amount of memory previously reserved for buffer
 * @param bytes_written will hold the number of bytes written to buffer
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_message_protobuf_encode(const struct Libp2pMessage* in, unsigned char* buffer, size_t max_buffer_size, size_t* bytes_written);

/**
 * Convert a Libp2pMessage into protobuf format,
 * allocating memory as needed
 * @param in the Libp2pMessage to convert
 * @param buffer where to store the protobuf
 * @param buffer_size the size written into buffer
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_message_protobuf_allocate_and_encode(const struct Libp2pMessage* in, unsigned char **buffer, size_t* buffer_size);

/**
 * turn a protobuf back into a message
 * @param buffer the protobuf
 * @param buffer_size the length of the buffer
 * @param out the message
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_message_protobuf_decode(unsigned char* buffer, size_t buffer_size, struct Libp2pMessage** out);

