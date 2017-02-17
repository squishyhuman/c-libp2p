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
				if (!protobuf_decode_length_delimited(&in[pos], in_size - pos, (char**)&(ptr->id),&(ptr->id_size), &bytes_read))
					goto exit;
				pos += bytes_read;
				break;
			case (2): { // array of bytes that is a multiaddress, put it in a vector
				if (!protobuf_decode_length_delimited(&in[pos], in_size - pos, (char**)&vector.buffer, &vector.buffer_size, &bytes_read))
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
	if (vector.buffer != NULL)
		free(vector.buffer);
	return retVal;
}

/***
 * protobuf and other methods for Message
 */

struct Libp2pMessage* libp2p_message_new() {
	struct Libp2pMessage* out = (struct Libp2pMessage*)malloc(sizeof(struct Libp2pMessage));
	if (out != NULL) {
		out->closer_peer_head = NULL;
		out->cluster_level_raw = 0;
		out->key = NULL;
		out->key_size = 0;
		out->message_type = MESSAGE_TYPE_PING;
		out->provider_peer_head = NULL;
		out->record = NULL;
	}
	return out;
}

void libp2p_message_free(struct Libp2pMessage* in) {
	struct Libp2pLinkedList* current = in->closer_peer_head;
	while (current != NULL) {
		struct Libp2pLinkedList* next = current->next;
		libp2p_message_peer_free((struct Libp2pPeer*)next->item);
		current = next;
	}
	if (in->key != NULL)
		free(in->key);
	current = in->provider_peer_head;
	while (current != NULL) {
		struct Libp2pLinkedList* next = current->next;
		libp2p_message_peer_free((struct Libp2pPeer*)next->item);
		current = next;
	}
	libp2p_record_free(in->record);
	free(in);
}

size_t libp2p_message_protobuf_encode_size(struct Libp2pMessage* in) {
	// message type
	size_t retVal = 11;
	// clusterlevelraw
	retVal += 11;
	// key
	retVal += in->key_size + 11;
	// record
	retVal += 11 + libp2p_record_protobuf_encode_size(in->record);
	// closer peers
	struct Libp2pLinkedList* current = in->closer_peer_head;
	while (current != NULL) {
		retVal += 11 + libp2p_message_peer_protobuf_encode_size((struct Libp2pPeer*)current->item);
		current = current->next;
	}
	// provider peers
	current = in->provider_peer_head;
	while (current != NULL) {
		retVal += 11 + libp2p_message_peer_protobuf_encode_size((struct Libp2pPeer*)current->item);
		current = current->next;
	}
	return retVal;
}

int libp2p_message_protobuf_encode(struct Libp2pMessage* in, unsigned char* buffer, size_t max_buffer_size, size_t* bytes_written) {
	// data & data_size
	size_t bytes_used = 0;
	*bytes_written = 0;
	int retVal = 0;
	// field 1
	retVal = protobuf_encode_varint(1, WIRETYPE_VARINT, in->message_type, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
	if (retVal == 0)
		return 0;
	*bytes_written += bytes_used;
	// field 2
	retVal = protobuf_encode_length_delimited(2, WIRETYPE_LENGTH_DELIMITED, in->key, in->key_size, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
	if (retVal == 0)
		return 0;
	*bytes_written += bytes_used;
	// field 3
	size_t protobuf_size = libp2p_record_protobuf_encode_size(in->record);
	unsigned char protobuf[protobuf_size];
	if (!libp2p_record_protobuf_encode(in->record, protobuf, protobuf_size, &protobuf_size))
		return 0;
	retVal = protobuf_encode_length_delimited(3, WIRETYPE_LENGTH_DELIMITED, protobuf, protobuf_size, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
	if (retVal == 0)
		return 0;
	*bytes_written += bytes_used;
	// field 8 (repeated)
	struct Libp2pLinkedList* current = in->closer_peer_head;
	while (current != NULL) {
		struct Libp2pPeer* peer = (struct Libp2pPeer*)current->item;
		protobuf_size = libp2p_message_peer_protobuf_encode_size(peer);
		unsigned char* peer_buffer = (unsigned char*)malloc(protobuf_size);
		if (peer_buffer == NULL)
			return 0;
		if (!libp2p_message_peer_protobuf_encode(peer, peer_buffer, protobuf_size, &protobuf_size)) {
			free(peer_buffer);
			return 0;
		}
		retVal = protobuf_encode_length_delimited(8, WIRETYPE_LENGTH_DELIMITED, peer_buffer, protobuf_size, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
		free(peer_buffer);
		if (retVal == 0)
			return 0;
		*bytes_written += bytes_used;
		current = current->next;
	}
	// field 9 (repeated)
	current = in->provider_peer_head;
	while (current != NULL) {
		struct Libp2pPeer* peer = (struct Libp2pPeer*)current->item;
		protobuf_size = libp2p_message_peer_protobuf_encode_size(peer);
		unsigned char* peer_buffer = (unsigned char*)malloc(protobuf_size);
		if (peer_buffer == NULL)
			return 0;
		if (!libp2p_message_peer_protobuf_encode(peer, peer_buffer, protobuf_size, &protobuf_size)) {
			free(peer_buffer);
			return 0;
		}
		retVal = protobuf_encode_length_delimited(9, WIRETYPE_LENGTH_DELIMITED, peer_buffer, protobuf_size, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
		free(peer_buffer);
		if (retVal == 0)
			return 0;
		*bytes_written += bytes_used;
		current = current->next;
	}
	// field 10
	retVal = protobuf_encode_varint(10, WIRETYPE_VARINT, in->cluster_level_raw, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
	if (retVal == 0)
		return 0;
	*bytes_written += bytes_used;
	return 1;
}

int libp2p_message_protobuf_decode(unsigned char* in, size_t in_size, struct Libp2pMessage** out) {
	size_t pos = 0;
	int retVal = 0;
	size_t buffer_size = 0;
	unsigned char* buffer = NULL;
	struct Libp2pLinkedList* current_item = NULL;
	struct Libp2pLinkedList* last_closer = NULL;
	struct Libp2pLinkedList* last_provider = NULL;

	if ( (*out = (struct Libp2pMessage*)malloc(sizeof(struct Libp2pMessage))) == NULL)
		goto exit;

	struct Libp2pMessage* ptr = *out;

	while(pos < in_size) {
		size_t bytes_read = 0;
		int field_no;
		enum WireType field_type;
		if (protobuf_decode_field_and_type(&in[pos], in_size, &field_no, &field_type, &bytes_read) == 0) {
			goto exit;
		}
		pos += bytes_read;
		switch(field_no) {
			case (1): // message type
				if (!protobuf_decode_varint(&in[pos], in_size - pos, (long long unsigned int*)&ptr->message_type , &bytes_read))
					goto exit;
				pos += bytes_read;
				break;
			case (2): // key
				if (!protobuf_decode_length_delimited(&in[pos], in_size - pos, (char**)&ptr->key, &ptr->key_size, &bytes_read))
					goto exit;
				pos += bytes_read;
				break;
			case (3): // record
				if (!protobuf_decode_length_delimited(&in[pos], in_size - pos, (char**)&buffer, &buffer_size, &bytes_read))
					goto exit;
				// turn this back into a record
				if (!libp2p_record_protobuf_decode(buffer, buffer_size, &ptr->record)) {
					free(buffer);
					buffer = NULL;
					goto exit;
				}
				pos += bytes_read;
				break;
			case (8): // closer peers
				if (!protobuf_decode_length_delimited(&in[pos], in_size - pos, (char**)&buffer, &buffer_size, &bytes_read))
					goto exit;
				// turn this back into a peer
				current_item = (struct Libp2pLinkedList*)malloc(sizeof(struct Libp2pLinkedList));
				if (current_item == NULL)
					goto exit;
				current_item->next = NULL;
				if (!libp2p_message_peer_protobuf_decode(buffer, buffer_size, (struct Libp2pPeer**)&current_item->item))
					goto exit;
				free(buffer);
				buffer = NULL;
				if (ptr->closer_peer_head == NULL) {
					ptr->closer_peer_head = current_item;
				} else {
					last_closer->next = current_item;
				}
				last_closer = current_item;
				pos += bytes_read;
				break;
			case (9): // provider peers
				if (!protobuf_decode_length_delimited(&in[pos], in_size - pos, (char**)&buffer, &buffer_size, &bytes_read))
					goto exit;
				// turn this back into a peer
				current_item = (struct Libp2pLinkedList*)malloc(sizeof(struct Libp2pLinkedList));
				if (current_item == NULL)
					goto exit;
				current_item->next = NULL;
				if (!libp2p_message_peer_protobuf_decode(buffer, buffer_size, (struct Libp2pPeer**)&current_item->item))
					goto exit;
				free(buffer);
				buffer = NULL;
				if (ptr->provider_peer_head == NULL) {
					ptr->provider_peer_head = current_item;
				} else {
					last_provider->next = current_item;
				}
				last_provider = current_item;
				pos += bytes_read;
				break;
			case (10): // cluster level raw
				if (!protobuf_decode_varint(&in[pos], in_size - pos, (long long unsigned int*)&ptr->cluster_level_raw , &bytes_read))
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
