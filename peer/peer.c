#include <stdlib.h>

#include "libp2p/peer/peer.h"
#include "libp2p/utils/linked_list.h"
#include "multiaddr/multiaddr.h"
#include "protobuf.h"
#include "libp2p/net/multistream.h"
#include "libp2p/utils/logger.h"

/**
 * create a new Peer struct
 * @returns a struct or NULL if there was a problem
 */
struct Libp2pPeer* libp2p_peer_new() {
	struct Libp2pPeer* out = (struct Libp2pPeer*)malloc(sizeof(struct Libp2pPeer));
	if (out != NULL) {
		out->id = NULL;
		out->id_size = 0;
		out->addr_head = NULL;
		out->connection_type = CONNECTION_TYPE_NOT_CONNECTED;
		out->connection = NULL;
	}
	return out;
}

/**
 * Create a new Peer based on a multiaddress
 * @param in the multiaddress
 * @returns a Peer initialized with the values from "in"
 */
struct Libp2pPeer* libp2p_peer_new_from_multiaddress(const struct MultiAddress* in) {
	struct Libp2pPeer* out = libp2p_peer_new();
	char* id = multiaddress_get_peer_id(in);
	if (id != NULL) {
		out->id_size = strlen(id) + 1;
		out->id = malloc(out->id_size);
		strcpy(out->id, id);
		free(id);
	}
	out->addr_head = libp2p_utils_linked_list_new();
	out->addr_head->item = multiaddress_copy(in);
	return out;
}

/**
 * Attempt to connect to the peer, setting connection_type correctly
 * NOTE: If successful, this will set peer->connection to the stream
 * @param peer the peer to connect to
 * @returns true(1) on success, false(0) if we could not connect
 */
int libp2p_peer_connect(struct Libp2pPeer* peer) {
	// find an appropriate address
	struct Libp2pLinkedList* current_address = peer->addr_head;
	while (current_address != NULL && peer->connection_type != CONNECTION_TYPE_CONNECTED) {
		struct MultiAddress *ma = (struct MultiAddress*)current_address->item;
		if (multiaddress_is_ip(ma)) {
			char* ip = NULL;
			if (!multiaddress_get_ip_address(ma, &ip))
				continue;
			int port = multiaddress_get_ip_port(ma);
			peer->connection = libp2p_net_multistream_connect(ip, port);
			if (peer->connection != NULL) {
				peer->connection_type = CONNECTION_TYPE_CONNECTED;
			}
			free(ip);
		} // is IP
	} // trying to connect
	return peer->connection_type == CONNECTION_TYPE_CONNECTED;
}

/**
 * Create a new peer struct with some data
 * @param id the id
 * @param id_size the length of the id
 * @param multi_addr the MultiAddresss
 * @returns the Libp2pPeer or NULL if there was a problem
 */
/*
struct Libp2pPeer* libp2p_peer_new_from_data(const char* id, size_t id_size, const struct MultiAddress* multi_addr) {
	struct Libp2pPeer* out = libp2p_peer_new();
	if (out != NULL) {
		out->id = malloc(id_size);
		strncpy(out->id, id, id_size);
		out->id_size = id_size;
		out->addr_head = libp2p_utils_linked_list_new();
		if (out->addr_head == NULL) {
			libp2p_peer_free(out);
			return NULL;
		}
		out->addr_head->item = multiaddress_copy(multi_addr);
		if (out->addr_head->item == NULL) {
			libp2p_peer_free(out);
			return NULL;
		}
	}

	return out;
}
*/

void libp2p_peer_free(struct Libp2pPeer* in) {
	if (in != NULL) {
		if (in->addr_head != NULL && in->addr_head->item != NULL) {
			libp2p_logger_debug("peer", "Freeing peer %s\n", ((struct MultiAddress*)in->addr_head->item)->string);
		} else {
			libp2p_logger_debug("peer", "Freeing peer with no multiaddress.\n");
		}
		if (in->id != NULL)
			free(in->id);
		if (in->connection != NULL) {
			libp2p_net_multistream_stream_free(in->connection);
			in->connection = NULL;
		}
		// free the memory in the linked list
		struct Libp2pLinkedList* current = in->addr_head;
		while (current != NULL) {
			struct Libp2pLinkedList* temp = current->next;
			multiaddress_free((struct MultiAddress*)current->item);
			free(current);
			current = temp;
		}
		free(in);
	}
}

/**
 * Make a copy of a peer
 * @param in what is to be copied
 * @returns a new struct, that does not rely on the old
 */
struct Libp2pPeer* libp2p_peer_copy(struct Libp2pPeer* in) {
	struct Libp2pPeer* out = libp2p_peer_new();
	if (out != NULL) {
		out->id_size = in->id_size;
		out->id = malloc(in->id_size);
		if (out->id == NULL) {
			libp2p_peer_free(out);
			return NULL;
		}
		memcpy(out->id, in->id, in->id_size);
		out->connection_type = in->connection_type;
		// loop through the addresses
		struct Libp2pLinkedList* current_in = in->addr_head;
		struct Libp2pLinkedList* current_out = NULL;
		while (current_in != NULL) {
			struct MultiAddress* addr = (struct MultiAddress*)current_in->item;
			struct Libp2pLinkedList* copy_item = libp2p_utils_linked_list_new();
			copy_item->item = multiaddress_copy(addr);
			if (out->addr_head == NULL) {
				out->addr_head = copy_item;
			} else {
				current_out->next = copy_item;
			}
			current_out = copy_item;
			current_in = current_in->next;
		}
		out->connection = in->connection;
	}
	return out;
}

/***
 * Determine if the passed in peer and id match
 * @param in the peer to check
 * @param peer_id peer id, zero terminated string
 * @returns true if peer matches
 */
int libp2p_peer_matches_id(struct Libp2pPeer* in, const unsigned char* peer_id) {
	if (strlen(peer_id) == in->id_size) {
		if (strncmp(in->id, peer_id, in->id_size) == 0)
			return 1;
	}
	return 0;
}

/***
 * Determine if we are currently connected to this peer
 * @param in the peer to check
 * @returns true(1) if connected
 */
int libp2p_peer_is_connected(struct Libp2pPeer* in) {
	if (in->connection_type == CONNECTION_TYPE_CONNECTED) {
		if (in->connection == NULL) {
			in->connection_type = CONNECTION_TYPE_NOT_CONNECTED;
		}
	}
	return in->connection_type == CONNECTION_TYPE_CONNECTED;
}

size_t libp2p_peer_protobuf_encode_size(struct Libp2pPeer* in) {
	int sz = 0;
	if (in != NULL) {
		// id + connection_type
		sz = 11 + in->id_size + 11;
		// loop through the multiaddresses
		struct Libp2pLinkedList* current = in->addr_head;
		while (current != NULL) {
			// find the length of the MultiAddress converted into bytes
			struct MultiAddress* data = (struct MultiAddress*)current->item;
			sz += 11 + data->bsize;
			current = current->next;
		}
	}
	return sz;
}

int libp2p_peer_protobuf_encode(struct Libp2pPeer* in, unsigned char* buffer, size_t max_buffer_size, size_t* bytes_written) {
	// data & data_size
	size_t bytes_used = 0;
	*bytes_written = 0;
	int retVal = 0;
	// field 1 (id)
	retVal = protobuf_encode_length_delimited(1, WIRETYPE_LENGTH_DELIMITED, in->id, in->id_size, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
	if (retVal == 0)
		return 0;
	*bytes_written += bytes_used;
	// field 2 (repeated)
	struct Libp2pLinkedList* current = in->addr_head;
	while (current != NULL) {
		struct MultiAddress* data = (struct MultiAddress*)current->item;
		retVal = protobuf_encode_length_delimited(2, WIRETYPE_LENGTH_DELIMITED, data->bytes, data->bsize, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
		if (retVal == 0)
			return 0;
		*bytes_written += bytes_used;
		current = current->next;
	}
	// field 3 (varint)
	retVal = protobuf_encode_varint(3, WIRETYPE_VARINT, in->connection_type, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
	if (retVal == 0)
		return 0;
	*bytes_written += bytes_used;
	return 1;
}

int libp2p_peer_protobuf_encode_with_alloc(struct Libp2pPeer* in, unsigned char** buffer, size_t *buffer_size) {
	*buffer_size = libp2p_peer_protobuf_encode_size(in);
	*buffer = malloc(*buffer_size);
	return libp2p_peer_protobuf_encode(in, *buffer, *buffer_size, buffer_size);
}

int libp2p_peer_protobuf_decode(unsigned char* in, size_t in_size, struct Libp2pPeer** out) {
	size_t pos = 0;
	int retVal = 0;
	char* buffer = NULL;
	size_t buffer_size = 0;
	struct Libp2pLinkedList* current = NULL;
	struct Libp2pLinkedList* last = NULL;
	struct MultiAddress* ma = NULL;

	*out = libp2p_peer_new();
	if ( *out == NULL)
		goto exit;

	struct Libp2pPeer* ptr = *out;

	ptr->addr_head = NULL;

	while(pos < in_size) {
		size_t bytes_read = 0;
		int field_no;
		enum WireType field_type;
		if (protobuf_decode_field_and_type(&in[pos], in_size, &field_no, &field_type, &bytes_read) == 0) {
			goto exit;
		}
		pos += bytes_read;
		switch(field_no) {
			case (1): // id
				if (!protobuf_decode_length_delimited(&in[pos], in_size - pos, (char**)&(ptr->id),&(ptr->id_size), &bytes_read))
					goto exit;
				pos += bytes_read;
				break;
			case (2): { // multiaddress bytes
				if (!protobuf_decode_length_delimited(&in[pos], in_size - pos, &buffer, &buffer_size, &bytes_read))
					goto exit;
				pos += bytes_read;
				// now turn it into multiaddress
				struct Libp2pLinkedList* current = libp2p_utils_linked_list_new();
				if (current == NULL)
					goto exit;
				struct MultiAddress* address = multiaddress_new_from_bytes(buffer, buffer_size);
				current->item = (void*)address;
				free(buffer);
				buffer = NULL;
				// assign the values
				if (ptr->addr_head == NULL) {
					ptr->addr_head = current;
				} else {
					last->next = current;
				}
				last = current;
				current = NULL;
				break;
			}
			case (3): // enum as varint
				if (!protobuf_decode_varint(&in[pos], in_size - pos, (long long unsigned int*)&ptr->connection_type, &bytes_read))
					goto exit;
				pos += bytes_read;
				break;
		}
	}

	retVal = 1;

exit:
	if (retVal == 0) {
		free(*out);
		*out = NULL;
	}
	if (buffer != NULL)
		free(buffer);
	return retVal;
}
