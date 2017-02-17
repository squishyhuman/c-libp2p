#pragma once

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

