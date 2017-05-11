#include <stdlib.h>

#include "libp2p/record/message.h"
#include "libp2p/peer/peer.h"
#include "libp2p/utils/linked_list.h"
#include "libp2p/utils/vector.h"
#include "protobuf.h"
#include "multiaddr/multiaddr.h"


/***
 * protobuf and other methods for Message
 */

/**
 * Allocate memory for a message
 * @returns a new, allocated Libp2pMessage struct
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

/**
 * Frees all resources related to a Libp2pMessage
 * @param in the incoming message
 */
void libp2p_message_free(struct Libp2pMessage* in) {
	if (in != NULL) {
		// a linked list of peer structs
		struct Libp2pLinkedList* current = in->closer_peer_head;
		struct Libp2pLinkedList* next = NULL;
		while (current != NULL) {
			next = current->next;
			struct Libp2pPeer* peer = (struct Libp2pPeer*)current->item;
			libp2p_peer_free(peer);
			current->item = NULL;
			libp2p_utils_linked_list_free(current);
			current = next;
		}
		if (in->key != NULL)
			free(in->key);
		current = in->provider_peer_head;
		while (current != NULL) {
			next = current->next;
			struct Libp2pPeer* peer = (struct Libp2pPeer*)current->item;
			libp2p_peer_free(peer);
			current->item = NULL;
			libp2p_utils_linked_list_free(current);
			current = next;
		}
		libp2p_record_free(in->record);
		free(in);
	}
}

size_t libp2p_message_protobuf_encode_size(const struct Libp2pMessage* in) {
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
		retVal += 11 + libp2p_peer_protobuf_encode_size((struct Libp2pPeer*)current->item);
		current = current->next;
	}
	// provider peers
	current = in->provider_peer_head;
	while (current != NULL) {
		retVal += 11 + libp2p_peer_protobuf_encode_size((struct Libp2pPeer*)current->item);
		current = current->next;
	}
	return retVal;
}

/**
 * Convert a Libp2pMessage into protobuf format,
 * allocating memory as needed
 * @param in the Libp2pMessage to convert
 * @param buffer where to store the protobuf
 * @param buffer_size the size of the buffer
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_message_protobuf_allocate_and_encode(const struct Libp2pMessage* in, unsigned char **buffer, size_t *buffer_size) {
	*buffer_size = libp2p_message_protobuf_encode_size(in);
	*buffer = malloc(*buffer_size);
	if (*buffer == NULL) {
		*buffer_size = 0;
		return 0;
	}
	int retVal = libp2p_message_protobuf_encode(in, *buffer, *buffer_size, buffer_size);
	if (retVal == 0) {
		free(*buffer);
		*buffer = NULL;
		*buffer_size = 0;
	}
	return retVal;
}

int libp2p_message_protobuf_encode(const struct Libp2pMessage* in, unsigned char* buffer, size_t max_buffer_size, size_t* bytes_written) {
	// data & data_size
	size_t bytes_used = 0;
	*bytes_written = 0;
	int retVal = 0;
	size_t protobuf_size = 0;
	unsigned char* protobuf = NULL;
	// field 1
	retVal = protobuf_encode_varint(1, WIRETYPE_VARINT, in->message_type, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
	if (retVal == 0)
		return 0;
	*bytes_written += bytes_used;
	// field 2
	if (in->key != NULL) {
		retVal = protobuf_encode_length_delimited(2, WIRETYPE_LENGTH_DELIMITED, in->key, in->key_size, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
		if (retVal == 0)
			return 0;
		*bytes_written += bytes_used;
	}
	// field 3
	if (in->record != NULL) {
		protobuf_size = libp2p_record_protobuf_encode_size(in->record);
		protobuf = (unsigned char*) malloc(protobuf_size);
		if (!libp2p_record_protobuf_encode(in->record, protobuf, protobuf_size, &protobuf_size)) {
			free(protobuf);
			return 0;
		}
		retVal = protobuf_encode_length_delimited(3, WIRETYPE_LENGTH_DELIMITED, protobuf, protobuf_size, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
		free(protobuf);
		if (retVal == 0)
			return 0;
		*bytes_written += bytes_used;
	}
	// field 8 (repeated)
	struct Libp2pLinkedList* current = in->closer_peer_head;
	while (current != NULL) {
		struct Libp2pPeer* peer = (struct Libp2pPeer*)current->item;
		protobuf_size = libp2p_peer_protobuf_encode_size(peer);
		unsigned char* peer_buffer = (unsigned char*)malloc(protobuf_size);
		if (peer_buffer == NULL)
			return 0;
		if (!libp2p_peer_protobuf_encode(peer, peer_buffer, protobuf_size, &protobuf_size)) {
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
		protobuf_size = libp2p_peer_protobuf_encode_size(peer);
		unsigned char* peer_buffer = (unsigned char*)malloc(protobuf_size);
		if (peer_buffer == NULL)
			return 0;
		if (!libp2p_peer_protobuf_encode(peer, peer_buffer, protobuf_size, &protobuf_size)) {
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
	size_t bytes_read = 0;
	int field_no = 0;
	enum WireType field_type = 0;
	unsigned char* buffer = NULL;
	struct Libp2pLinkedList* current_item = NULL;
	struct Libp2pLinkedList* last_closer = NULL;
	struct Libp2pLinkedList* last_provider = NULL;
	struct Libp2pMessage* ptr = NULL;

	if ( (*out = libp2p_message_new()) == NULL)
		goto exit;

	ptr = *out;

	while(pos < in_size) {
		bytes_read = 0;
		field_no = 0;
		field_type = 0;
		if (protobuf_decode_field_and_type(&in[pos], in_size, &field_no, &field_type, &bytes_read) == 0) {
			goto exit;
		}
		pos += bytes_read;
		if (field_no < 1 || field_no > 10)
			goto exit;
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
				free(buffer);
				buffer = NULL;
				pos += bytes_read;
				break;
			case (8): // closer peers
				if (!protobuf_decode_length_delimited(&in[pos], in_size - pos, (char**)&buffer, &buffer_size, &bytes_read))
					goto exit;
				// turn this back into a peer
				current_item = libp2p_utils_linked_list_new();
				if (current_item == NULL)
					goto exit;
				if (!libp2p_peer_protobuf_decode(buffer, buffer_size, (struct Libp2pPeer**)&current_item->item))
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
				current_item = libp2p_utils_linked_list_new();
				if (current_item == NULL)
					goto exit;
				struct Libp2pPeer* peer = NULL;
				if (!libp2p_peer_protobuf_decode(buffer, buffer_size, &peer))
					goto exit;
				current_item->item = peer;
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
