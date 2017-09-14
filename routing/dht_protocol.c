#include <stdlib.h>
#include <string.h>

#include "libp2p/crypto/encoding/base58.h"
#include "libp2p/net/stream.h"
#include "libp2p/os/utils.h"
#include "libp2p/routing/dht_protocol.h"
#include "libp2p/record/message.h"
#include "libp2p/utils/linked_list.h"
#include "libp2p/utils/logger.h"
#include "libp2p/conn/session.h"


/***
 * This is where kademlia and dht talk to the outside world
 */

struct DhtContext {
	struct Peerstore* peer_store;
	struct ProviderStore* provider_store;
};

int libp2p_routing_dht_can_handle(const uint8_t* incoming, size_t incoming_size) {
	if (incoming_size < 8)
		return 0;
	char* result = strnstr((char*)incoming, "/ipfs/kad", incoming_size);
	if (result != NULL && result == (char*)incoming)
		return 1;
	return 0;
}

int libp2p_routing_dht_shutdown(void* context) {
	free(context);
	return 1;
}

int libp2p_routing_dht_handle_msg(const uint8_t* incoming, size_t incoming_size, struct SessionContext* session_context, void* context) {
	libp2p_logger_debug("dht_protocol", "Handling incoming dht routing request.\n");
	struct DhtContext* ctx = (struct DhtContext*)context;
	if (!libp2p_routing_dht_handshake(session_context))
		return -1;
	return (libp2p_routing_dht_handle_message(session_context, ctx->peer_store, ctx->provider_store) == 0) ? -1 : 1;
}

struct Libp2pProtocolHandler* libp2p_routing_dht_build_protocol_handler(struct Peerstore* peer_store, struct ProviderStore* provider_store) {
	struct Libp2pProtocolHandler* handler = (struct Libp2pProtocolHandler*) malloc(sizeof(struct Libp2pProtocolHandler));
	if (handler != NULL) {
		struct DhtContext* ctx = (struct DhtContext*) malloc(sizeof(struct DhtContext));
		ctx->peer_store = peer_store;
		ctx->provider_store = provider_store;
		handler->context = ctx;
		handler->CanHandle = libp2p_routing_dht_can_handle;
		handler->HandleMessage = libp2p_routing_dht_handle_msg;
		handler->Shutdown = libp2p_routing_dht_shutdown;
	}
	return handler;
}

/***
 * Helper method to protobuf a message
 * @param message the message
 * @param buffer where to put the results
 * @param buffer_size the size of the results
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_routing_dht_protobuf_message(struct KademliaMessage* message, unsigned char** buffer, size_t *buffer_size) {
	*buffer_size = libp2p_message_protobuf_encode_size(message);
	*buffer = malloc(*buffer_size);
	if (!libp2p_message_protobuf_encode(message, *buffer, *buffer_size, buffer_size)) {
		free(*buffer);
		*buffer_size = 0;
		return 0;
	}
	return 1;
}

/**
 * Take existing stream and upgrade to the Kademlia / DHT protocol/codec
 * @param context the context
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_routing_dht_upgrade_stream(struct SessionContext* context) {
	int retVal = 0;
	char* protocol = "/ipfs/kad/1.0.0\n";
	unsigned char* results = NULL;
	size_t results_size = 0;
	if (!context->default_stream->write(context, (unsigned char*)protocol, strlen(protocol))) {
		libp2p_logger_error("dht_protocol", "Unable to write to stream during upgrade attempt.\n");
		goto exit;
	}
	if (!context->default_stream->read(context, &results, &results_size, 5)) {
		libp2p_logger_error("dht_protocol", "Unable to read from stream during upgrade attempt.\n");
		goto exit;
	}
	if (results_size != strlen(protocol)) {
		libp2p_logger_error("dht_protocol", "Expected response size incorrect during upgrade attempt.\n");
		goto exit;
	}
	if (strncmp((char*)results, protocol, results_size) != 0) {
		libp2p_logger_error("dht_protocol", "Expected %s but received %s.\n", protocol, results);
		goto exit;
	}
	retVal = 1;
	exit:
	if (results != NULL) {
		free(results);
		results = NULL;
	}
	return retVal;
}

/**
 * Handle a client requesting an upgrade to the DHT protocol
 * @param context the context
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_routing_dht_handshake(struct SessionContext* context) {
	char* protocol = "/ipfs/kad/1.0.0\n";
	return context->default_stream->write(context, (unsigned char*)protocol, strlen(protocol));
}

/**
 * A remote client has requested a ping
 * @param message the message
 * @param buffer where to put the results
 * @param buffer_size the length of the results
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_routing_dht_handle_ping(struct KademliaMessage* message, unsigned char** buffer, size_t *buffer_size) {
	// just turn message back into a protobuf and send it back...
	return libp2p_routing_dht_protobuf_message(message, buffer, buffer_size);
}

/**
 * See if we have information as to who can provide this item
 * @param session the context
 * @param message the message from the caller, contains a key
 * @param peerstore the list of peers
 * @param providerstore the list of peers that can provide things
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_routing_dht_handle_get_providers(struct SessionContext* session, struct KademliaMessage* message, struct Peerstore* peerstore,
		struct ProviderStore* providerstore, unsigned char** results, size_t* results_size) {
	unsigned char* peer_id = NULL;
	int peer_id_size = 0;

	// This shouldn't be needed, but just in case:
	message->provider_peer_head = NULL;

	// Can I provide it locally?
	struct DatastoreRecord* datastore_record = NULL;
	if (session->datastore->datastore_get((unsigned char*)message->key, message->key_size, &datastore_record, session->datastore)) {
		// we can provide this hash from our datastore
		libp2p_datastore_record_free(datastore_record);
		libp2p_logger_debug("dht_protocol", "I can provide myself as a provider for this key.\n");
		message->provider_peer_head = libp2p_utils_linked_list_new();
		message->provider_peer_head->item = libp2p_peer_copy(libp2p_peerstore_get_local_peer(peerstore));
	} else if (libp2p_providerstore_get(providerstore, (unsigned char*)message->key, message->key_size, &peer_id, &peer_id_size)) {
		// Can I provide it because someone announced it earlier?
		libp2p_logger_debug("dht_protocol", "I can provide a provider for this key.\n");
		// we have a peer id, convert it to a peer object
		struct Libp2pPeer* peer = libp2p_peerstore_get_peer(peerstore, peer_id, peer_id_size);
		if (peer != NULL) {
			// add it to the message
			if (message->provider_peer_head == NULL) {
				message->provider_peer_head = libp2p_utils_linked_list_new();
				message->provider_peer_head->item = libp2p_peer_copy(peer);
			} else {
				struct Libp2pLinkedList* current = message->provider_peer_head;
				// find the last one in the list
				while (current->next != NULL) {
					current = current->next;
				}
				// add to the list
				current->next = libp2p_utils_linked_list_new();
				current->next->item = peer;
			}
		}
	} else {
		size_t b58_size = 100;
		uint8_t *b58key = (uint8_t *) malloc(b58_size);
		if (!libp2p_crypto_encoding_base58_encode((unsigned char*)message->key, message->key_size, (unsigned char**)&b58key, &b58_size)) {
			libp2p_logger_debug("dht_protocol", "I cannot provide a provider for this key.\n");
		} else {
			libp2p_logger_debug("dht_protocol", "I cannot provide a provider for the key %s.\n", b58key);
		}
		free(b58key);
	}
	if (peer_id != NULL)
		free(peer_id);
	// TODO: find closer peers
	/*
	if (message->provider_peer_head == NULL) {
		// Who else can provide it?
		//while ()
	}
	*/
	if (message->provider_peer_head != NULL) {
		libp2p_logger_debug("dht_protocol", "GetProviders: We have a peer. Sending it back\n");
		// protobuf it and send it back
		if (!libp2p_routing_dht_protobuf_message(message, results, results_size)) {
			libp2p_logger_error("dht_protocol", "GetProviders: Error protobufing results\n");
			return 0;
		}
	}
	return 1;
}

/***
 * helper method to get ip multiaddress from peer's linked list
 * @param head linked list of multiaddresses
 * @returns the IP multiaddress in the list, or NULL if none found
 */
struct MultiAddress* libp2p_routing_dht_find_peer_ip_multiaddress(struct Libp2pLinkedList* head) {
	struct MultiAddress* out = NULL;
	struct Libp2pLinkedList* current = head;
	while (current != NULL) {
		out = (struct MultiAddress*)current->item;
		if (multiaddress_is_ip(out)) {
			libp2p_logger_debug("dht_protocol", "Found MultiAddress %s\n", out->string);
			break;
		}
		current = current->next;
	}
	if (current == NULL)
		out = NULL;
	return out;
}

/***
 * Remote peer has announced that he can provide a key
 * @param session session context
 * @param message the message
 * @param peerstore the peerstore
 * @param providerstore the providerstore
 * @param result_buffer where to put the result
 * @param result_buffer_size the size of the result buffer
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_routing_dht_handle_add_provider(struct SessionContext* session, struct KademliaMessage* message,
			struct Peerstore* peerstore, struct ProviderStore* providerstore, unsigned char** result_buffer, size_t* result_buffer_size) {
	int retVal = 0;
	struct Libp2pPeer *peer = NULL;
	
	//TODO: verify peer signature
	/*
	if (message->record != NULL && message->record->author != NULL && message->record->author_size > 0
			&& message->key != NULL && message->key_size > 0)
	*/

	struct Libp2pLinkedList* current = message->provider_peer_head;
	if (current == NULL) {
		libp2p_logger_error("dht_protocol", "Provider has no peer.\n");
		goto exit;
	}
	// there should only be 1 when adding a provider
	if (current != NULL) {
		peer = current->item;
		if (peer == NULL) {
			libp2p_logger_error("dht_protocol", "Message add_provider has no peer\n");
			goto exit;
		}
		struct MultiAddress *peer_ma = libp2p_routing_dht_find_peer_ip_multiaddress(peer->addr_head);
		if (peer_ma == NULL) {
			libp2p_logger_error("dht_protocol", "Peer has no IP MultiAddress.\n");
			goto exit;
		}
		// add what we know to be the ip for this peer
		char *ip;
		char new_string[255];
		multiaddress_get_ip_address(session->default_stream->address, &ip);
		int port = multiaddress_get_ip_port(peer_ma);
		char* peer_id = multiaddress_get_peer_id(peer_ma);
		sprintf(new_string, "/ip4/%s/tcp/%d/ipfs/%s", ip, port, peer_id);
		free(ip);
		free(peer_id);
		struct MultiAddress* new_ma = multiaddress_new_from_string(new_string);
		if (new_ma == NULL)
			goto exit;
		libp2p_logger_debug("dht_protocol", "New MultiAddress made with %s.\n", new_string);
		// TODO: See if the sender is who he says he is
		// set it as the first in the list
		struct Libp2pLinkedList* new_head = libp2p_utils_linked_list_new();
		new_head->item = new_ma;
		new_head->next = peer->addr_head;
		peer->addr_head = new_head;
		// now add the peer to the peerstore
		libp2p_logger_debug("dht_protocol", "About to add peer %s to peerstore\n", peer_ma->string);
		if (!libp2p_peerstore_add_peer(peerstore, peer))
			goto exit;
		libp2p_logger_debug("dht_protocol", "About to add key to providerstore\n");
		if (!libp2p_providerstore_add(providerstore, (unsigned char*)message->key, message->key_size, (unsigned char*)peer->id, peer->id_size))
			goto exit;
	}

	if (!libp2p_routing_dht_protobuf_message(message, result_buffer, result_buffer_size)) {
		goto exit;
	}

	retVal = 1;
	exit:
	if (retVal != 1) {
		if (*result_buffer != NULL) {
			free(*result_buffer);
			*result_buffer_size = 0;
			*result_buffer = NULL;
		}
		libp2p_logger_error("dht_protocol", "add_provider returning false\n");
	}
	/*
	if (peer != NULL)
		libp2p_peer_free(peer);
	*/
	return retVal;
}

/**
 * Retrieve something from the dht datastore
 * @param session the session context
 * @param message the message
 * @param peerstore the peerstore
 * @param providerstore the providerstore
 * @param result_buffer the results, as a protobuf'd KademliaMessage
 * @param result_buffer_size the size of the results
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_routing_dht_handle_get_value(struct SessionContext* session, struct KademliaMessage* message,
		struct Peerstore* peerstore, struct ProviderStore* providerstore, unsigned char** result_buffer, size_t *result_buffer_size) {

	struct Datastore* datastore = session->datastore;
	struct Filestore* filestore = session->filestore;
	size_t data_size = 0;
	unsigned char* data = NULL;

	// We need to get the data from the disk
	if(!filestore->node_get((unsigned char*)message->key, message->key_size, (void**)&data, &data_size, filestore)) {
		libp2p_logger_debug("dht_protocol", "handle_get_value: Unable to get key from filestore\n");
	}

	libp2p_logger_debug("dht_protocol", "handle_get_value: value retrieved from the datastore\n");

	struct Libp2pRecord *record = libp2p_record_new();
	record->key_size = message->key_size;
	record->key = malloc(record->key_size);
	memcpy(record->key, message->key, record->key_size);
	record->value_size = data_size;
	record->value = malloc(record->value_size);
	memcpy(record->value, data, record->value_size);
	message->record = record;
	free(data);

	if (!libp2p_routing_dht_protobuf_message(message, result_buffer, result_buffer_size)) {
		libp2p_record_free(record);
		message->record = NULL;
		return 0;
	}

	return 1;
}

/**
 * Put something in the dht datastore
 * @param session the session context
 * @param message the message
 * @param peerstore the peerstore
 * @param providerstore the providerstore
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_routing_dht_handle_put_value(struct SessionContext* session, struct KademliaMessage* message,
		struct Peerstore* peerstore, struct ProviderStore* providerstore) {

	if (message->record == NULL)
		return 0;

	struct DatastoreRecord* record = libp2p_datastore_record_new();
	if (record == NULL)
		return 0;

	// set the key from the message->record->key
	record->key_size = message->record->key_size;
	record->key = (uint8_t*) malloc(record->key_size);
	if (record->key == NULL) {
		libp2p_datastore_record_free(record);
		return 0;
	}
	memcpy(record->key, message->record->key, record->key_size);
	// set the value from the message->record->value
	record->value_size = message->record->value_size;
	record->value = (uint8_t*) malloc(record->value_size);
	if (record->value == NULL) {
		libp2p_datastore_record_free(record);
		return 0;
	}
	memcpy(record->value, message->record->value, record->value_size);

	int retVal = session->datastore->datastore_put(record, session->datastore);
	libp2p_datastore_record_free(record);
	return retVal;
}

/**
 * Find a node
 * @param session the session context
 * @param message the message
 * @param peerstore the peerstore
 * @param providerstore the providerstore
 * @param result_buffer the results
 * @param result_buffer_size the size of the results
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_routing_dht_handle_find_node(struct SessionContext* session, struct KademliaMessage* message,
		struct Peerstore* peerstore, struct ProviderStore* providerstore, unsigned char** result_buffer, size_t *result_buffer_size) {
	// look through peer store
	struct Libp2pPeer* peer = libp2p_peerstore_get_peer(peerstore, (unsigned char*)message->key, message->key_size);
	if (peer != NULL) {
		message->provider_peer_head = libp2p_utils_linked_list_new();
		message->provider_peer_head->item = libp2p_peer_copy(peer);
		if (!libp2p_routing_dht_protobuf_message(message, result_buffer, result_buffer_size)) {
			return 0;
		}
		return 1;
	}
	return 0;
}

/***
 * Handle the incoming message. Handshake should have already
 * been done. We should expect  that the next read contains
 * a protobuf'd kademlia message.
 * @param session the context
 * @param peerstore a list of peers
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_routing_dht_handle_message(struct SessionContext* session, struct Peerstore* peerstore, struct ProviderStore* providerstore) {
	unsigned char* buffer = NULL, *result_buffer = NULL;
	size_t buffer_size = 0, result_buffer_size = 0;
	int retVal = 0;
	struct KademliaMessage* message = NULL;

	// read from stream
	if (!session->default_stream->read(session, &buffer, &buffer_size, 5))
		goto exit;
	// unprotobuf
	if (!libp2p_message_protobuf_decode(buffer, buffer_size, &message))
		goto exit;

	// handle message
	switch(message->message_type) {
		case(MESSAGE_TYPE_PUT_VALUE): // store a value in local storage
				libp2p_routing_dht_handle_put_value(session, message, peerstore, providerstore);
				break;
		case(MESSAGE_TYPE_GET_VALUE): // get a value from local storage
				libp2p_routing_dht_handle_get_value(session, message, peerstore, providerstore, &result_buffer, &result_buffer_size);
				break;
		case(MESSAGE_TYPE_ADD_PROVIDER): // client wants us to know he can provide something
				libp2p_routing_dht_handle_add_provider(session, message, peerstore, providerstore, &result_buffer, &result_buffer_size);
				break;
		case(MESSAGE_TYPE_GET_PROVIDERS): // see if we can help, and send closer peers
				libp2p_routing_dht_handle_get_providers(session, message, peerstore, providerstore, &result_buffer, &result_buffer_size);
				break;
		case(MESSAGE_TYPE_FIND_NODE): // find peers
				libp2p_routing_dht_handle_find_node(session, message, peerstore, providerstore, &result_buffer, &result_buffer_size);
				break;
		case(MESSAGE_TYPE_PING):
				libp2p_routing_dht_handle_ping(message, &result_buffer, &result_buffer_size);
				break;
	}
	// if we have something to send, send it.
	if (result_buffer != NULL) {
		libp2p_logger_debug("dht_protocol", "Sending message back to caller. Message type: %d\n", message->message_type);
		if (!session->default_stream->write(session, result_buffer, result_buffer_size))
			goto exit;
	} else {
		libp2p_logger_debug("dht_protocol", "DhtHandleMessage: Nothing to send back. Kademlia call has been handled. Message type: %d\n", message->message_type);
	}
	retVal = 1;
	exit:
	if (buffer != NULL)
		free(buffer);
	if (result_buffer != NULL)
		free(result_buffer);
	if (message != NULL)
		libp2p_message_free(message);
	return retVal;
}
