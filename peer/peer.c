#include <stdlib.h>

#include "libp2p/peer/peer.h"
#include "libp2p/utils/linked_list.h"
#include "multiaddr/multiaddr.h"
#include "protobuf.h"

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
	}
	return out;
}

void libp2p_peer_free(struct Libp2pPeer* in) {
	if (in != NULL) {
		if (in->id != NULL)
			free(in->id);
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
				current_out = copy_item;
			}
			current_in = current_in->next;
		}
	}
	return out;
}

size_t libp2p_peer_protobuf_encode_size(struct Libp2pPeer* in) {
	// id + connection_type
	int sz = 11 + in->id_size + 11;
	// loop through the multiaddresses
	struct Libp2pLinkedList* current = in->addr_head;
	while (current != NULL) {
		// find the length of the MultiAddress converted into bytes
		struct MultiAddress* data = (struct MultiAddress*)current->item;
		sz += 11 + data->bsize;
		current = current->next;
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

int libp2p_peer_protobuf_decode(unsigned char* in, size_t in_size, struct Libp2pPeer** out) {
	size_t pos = 0;
	int retVal = 0;
	char* buffer = NULL;
	size_t buffer_size = 0;
	struct Libp2pLinkedList* current = NULL;
	struct Libp2pLinkedList* last = NULL;
	struct MultiAddress* ma = NULL;

	if ( (*out = (struct Libp2pPeer*)malloc(sizeof(struct Libp2pPeer))) == NULL)
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
				current->item = (void*)multiaddress_new_from_bytes(buffer, buffer_size);
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
