#include <stdlib.h>

#include "libp2p/record/message.h"
#include "libp2p/utils/linked_list.h"
#include "libp2p/utils/vector.h"
#include "protobuf.h"
/**
 * create a new Peer struct
 * @returns a struct or NULL if there was a problem
 */
struct Libp2pPeer* libp2p_message_peer_new() {
	struct Libp2pPeer* out = (struct Libp2pPeer*)malloc(sizeof(struct Libp2pPeer));
	if (out != NULL) {
		out->id = NULL;
		out->id_size = 0;
		out->addr_head = NULL;
		out->connection_type = CONNECTION_TYPE_NOT_CONNECTED;
	}
	return out;
}

void libp2p_message_peer_free(struct Libp2pPeer* in) {
	if (in != NULL) {
		if (in->id != NULL)
			free(in);
		// free the memory in the linked list
		struct Libp2pLinkedList* current = in->addr_head;
		while (current != NULL) {
			struct Libp2pLinkedList* temp = current->next;
			free(current->item);
			current = temp;
		}
		free(in);
	}
}

size_t libp2p_message_peer_protobuf_encode_size(struct Libp2pPeer* in) {
	// id + connection_type
	int sz = 11 + in->id_size + 11;
	// loop through the multiaddresses
	struct Libp2pLinkedList* current = in->addr_head;
	while (current != NULL) {
		unsigned char* data = (unsigned char*)current->item;
		struct Libp2pVector* vector;
		if (!libp2p_utils_vector_unserialize(data, &vector))
			return 0;
		sz += 11 + vector->buffer_size;
		libp2p_utils_vector_free(vector);
		current = current->next;
	}
	return sz;
}

int libp2p_message_peer_protobuf_encode(struct Libp2pPeer* in, unsigned char* buffer, size_t max_buffer_size, size_t* bytes_written) {
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
		struct Libp2pVector* vector;
		if (!libp2p_utils_vector_unserialize(current->item, &vector))
			return 0;
		retVal = protobuf_encode_length_delimited(2, WIRETYPE_LENGTH_DELIMITED, vector->buffer, vector->buffer_size, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
		libp2p_utils_vector_free(vector);
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

int libp2p_message_peer_protobuf_decode(unsigned char* in, size_t in_size, struct Libp2pPeer** out) {
	size_t pos = 0;
	int retVal = 0;
	unsigned char* buffer = NULL;
	size_t buffer_size = 0;
	struct Libp2pVector vector;
	struct Libp2pLinkedList* current = NULL;
	struct Libp2pLinkedList* last = NULL;

	vector.buffer = NULL;

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
				if (!protobuf_decode_length_delimited(&in[pos], in_size - pos, (char**)&(ptr->id),&(ptr->id_size), &bytes_read) == 0)
					goto exit;
				pos += bytes_read;
				break;
			case (2): { // array of bytes that is a multiaddress, put it in a vector
				if (!protobuf_decode_length_delimited(&in[pos], in_size - pos, (char**)&vector.buffer, &vector.buffer_size, &bytes_read) == 0)
					goto exit;
				pos += bytes_read;
				// now turn it into a byte array
				struct Libp2pLinkedList* current = (struct Libp2pLinkedList*)malloc(sizeof(struct Libp2pLinkedList));
				if (current == NULL)
					goto exit;
				current->next = NULL;
				size_t vector_size;
				if (!libp2p_utils_vector_serialize(&vector, (unsigned char**)&current->item, &vector_size)) {
					free(current);
					goto exit;
				}
				// clean up vector
				free(vector.buffer);
				vector.buffer = NULL;
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
				if (!protobuf_decode_varint(&in[pos], in_size - pos, (long long unsigned int*)&ptr->connection_type, &bytes_read) == 0)
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
	if (vector.buffer != NULL)
		free(vector.buffer);
	return retVal;

}

