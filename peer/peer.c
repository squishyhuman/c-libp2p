#include <stdlib.h>
#include <time.h>

#include "multiaddr/multiaddr.h"
#include "protobuf.h"
#include "libp2p/net/multistream.h"
#include "libp2p/peer/peer.h"
#include "libp2p/secio/secio.h"
#include "libp2p/utils/linked_list.h"
#include "libp2p/utils/logger.h"
#include "libp2p/yamux/yamux.h"

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
		out->sessionContext = NULL;
		out->is_local = 0;
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
		out->id_size = strlen(id);
		out->id = malloc(out->id_size);
		memcpy(out->id, id, out->id_size);
		free(id);
	}
	out->addr_head = libp2p_utils_linked_list_new();
	out->addr_head->item = multiaddress_copy(in);
	return out;
}

/***
 * Free resources of a Libp2pPeer
 * @param in the struct to free
 */
void libp2p_peer_free(struct Libp2pPeer* in) {
	if (in != NULL) {
		if (in->addr_head != NULL && in->addr_head->item != NULL) {
			//libp2p_logger_debug("peer", "Freeing peer %s\n", ((struct MultiAddress*)in->addr_head->item)->string);
		} else {
			//libp2p_logger_debug("peer", "Freeing peer with no multiaddress.\n");
		}
		if (in->id != NULL)
			free(in->id);
		if (in->sessionContext != NULL) {
			libp2p_session_context_free(in->sessionContext);
			//libp2p_net_multistream_stream_free(in->connection);
			in->sessionContext = NULL;
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

/***
 * Clean up a bad connection
 * @param peer the peer to clean up
 * @returns true(1)
 */
int libp2p_peer_handle_connection_error(struct Libp2pPeer* peer) {
	peer->connection_type = CONNECTION_TYPE_NOT_CONNECTED;
	libp2p_session_context_free(peer->sessionContext);
	peer->sessionContext = NULL;
	return 1;
}

/**
 * Attempt to connect to the peer, setting connection_type correctly
 * NOTE: If successful, this will set peer->connection to the stream
 *
 * @param privateKey the local private key to use
 * @param peer the peer to connect to
 * @param peerstore if connection is successfull, will add peer to peerstore
 * @returns true(1) on success, false(0) if we could not connect
 */
int libp2p_peer_connect(const struct RsaPrivateKey* privateKey, struct Libp2pPeer* peer, struct Peerstore* peerstore, struct Datastore *datastore, int timeout) {
	// fix the connection type if in an invalid state
	if (peer->connection_type == CONNECTION_TYPE_CONNECTED && peer->sessionContext == NULL)
		peer->connection_type = CONNECTION_TYPE_NOT_CONNECTED;
	libp2p_logger_debug("peer", "Attemping to connect to %s.\n", libp2p_peer_id_to_string(peer));
	time_t now, prev = time(NULL);
	// find an appropriate address
	struct Libp2pLinkedList* current_address = peer->addr_head;
	while (current_address != NULL && peer->connection_type != CONNECTION_TYPE_CONNECTED) {
		struct MultiAddress *ma = (struct MultiAddress*)current_address->item;
		if (multiaddress_is_ip(ma)) {
			char* ip = NULL;
			if (!multiaddress_get_ip_address(ma, &ip))
				continue;
			int port = multiaddress_get_ip_port(ma);
			// out with the old
			if (peer->sessionContext != NULL) {
				libp2p_session_context_free(peer->sessionContext);
			}
			peer->sessionContext = libp2p_session_context_new();
			peer->sessionContext->host = ip;
			peer->sessionContext->port = port;
			peer->sessionContext->datastore = datastore;
			peer->sessionContext->insecure_stream = libp2p_net_multistream_connect_with_timeout(ip, port, timeout);
			if (peer->sessionContext->insecure_stream == NULL) {
				libp2p_logger_debug("peer", "Unable to connect to IP %s and port %d for peer %s.\n", ip, port, libp2p_peer_id_to_string(peer));
				free(ip);
				return 0;
			}
			if (peer->sessionContext->insecure_stream != NULL) {
				peer->sessionContext->default_stream = peer->sessionContext->insecure_stream;
				peer->connection_type = CONNECTION_TYPE_CONNECTED;
			}
			// switch to secio
			if (libp2p_secio_initiate_handshake(peer->sessionContext, privateKey, peerstore) <= 0) {
				libp2p_logger_error("peer", "Attempted secio handshake, but failed for peer %s.\n", libp2p_peer_id_to_string(peer));
				free(ip);
				return 0;
			}
			// switch to yamux
			if (!yamux_send_protocol(peer->sessionContext)) {
				libp2p_logger_error("peer", "Attempted yamux handshake, but could not send protocol header for peer %s.\n", libp2p_peer_id_to_string(peer));
				free(ip);
				return 0;
			}
			free(ip);
		} // is IP
		now = time(NULL);
		if (now >= (prev + timeout))
			break;
	} // trying to connect
	int retVal = peer->connection_type == CONNECTION_TYPE_CONNECTED;
	if (!retVal) {
		libp2p_logger_debug("peer", "Attempted connect to %s but failed.\n", libp2p_peer_id_to_string(peer));
	}
	return retVal;
}

/**
 * Make a copy of a peer
 *
 * NOTE: SessionContext is not copied.
 *
 * @param in what is to be copied
 * @returns a new struct, that does not rely on the old
 */
struct Libp2pPeer* libp2p_peer_copy(const struct Libp2pPeer* in) {
	struct Libp2pPeer* out = libp2p_peer_new();
	if (out != NULL) {
		out->is_local = in->is_local;
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
			if (addr == NULL) {
				libp2p_logger_error("peer", "Attempted to copy MultiAddress, but current item is NULL.\n");
			} else {
				struct Libp2pLinkedList* copy_item = libp2p_utils_linked_list_new();
				copy_item->item = multiaddress_copy(addr);
				if (out->addr_head == NULL) {
					// first one
					out->addr_head = copy_item;
				} else {
					// not the first, tack it on the end
					current_out->next = copy_item;
				}
				current_out = copy_item;
			}
			current_in = current_in->next;
		}
		out->sessionContext = in->sessionContext;
	}
	return out;
}

/***
 * Determine if the passed in peer and id match
 * @param in the peer to check
 * @param peer_id peer id, zero terminated string
 * @returns true if peer matches
 */
int libp2p_peer_matches_id(struct Libp2pPeer* in, const unsigned char* peer_id, int peer_size) {
	if (peer_size == in->id_size) {
		if (strncmp(in->id, (char*)peer_id, in->id_size) == 0)
			return 1;
	}
	return 0;
}

static char string_retval[100];
/***
 * Convert peer id to null terminated string
 * @param in the peer object
 * @returns the peer id as a null terminated string
 */
char* libp2p_peer_id_to_string(const struct Libp2pPeer* in) {
	memcpy(string_retval, in->id, in->id_size);
	string_retval[in->id_size] = 0;
	return string_retval;
}

/***
 * Determine if we are currently connected to this peer
 * @param in the peer to check
 * @returns true(1) if connected
 */
int libp2p_peer_is_connected(struct Libp2pPeer* in) {
	if (in->connection_type == CONNECTION_TYPE_CONNECTED) {
		if (in->sessionContext == NULL || in->sessionContext->default_stream == NULL) {
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
			if (data == NULL) {
				libp2p_logger_error("peer", "encode_size: Attempted to get MultiAddress, but item was NULL.\n");
			} else {
				sz += 11 + data->bsize;
			}
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
		if (data == NULL) {
			libp2p_logger_error("peer", "encode: Attempted to get multiaddress, but item was NULL.\n");
		}  else {
			retVal = protobuf_encode_length_delimited(2, WIRETYPE_LENGTH_DELIMITED, (char*)data->bytes, data->bsize, &buffer[*bytes_written], max_buffer_size - *bytes_written, &bytes_used);
			if (retVal == 0)
				return 0;
			*bytes_written += bytes_used;
		}
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
				struct MultiAddress* address = multiaddress_new_from_bytes((unsigned char*)buffer, buffer_size);
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

/**
 * Compare 2 Libp2pPeers
 * @param a side A
 * @param b side B
 * @returns <0 if A wins, 0 if equal, or >0 if B wins
 */
int libp2p_peer_compare(const struct Libp2pPeer* a, const struct Libp2pPeer* b) {
	if (a == NULL && b == NULL)
		return 0;
	if (a == NULL && b != NULL)
		return -1;
	if (a != NULL && b == NULL)
		return 1;
	if (a->id_size != b->id_size)
		return b->id_size - a->id_size;
	for(int i = 0; i < a->id_size; i++) {
		if (a->id[i] != b->id[i])
			return b->id[i] - a->id[i];
	}
	return 0;
}
