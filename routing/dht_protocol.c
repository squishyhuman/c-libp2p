#include <stdlib.h>
#include <string.h>

#include "libp2p/net/stream.h"
#include "libp2p/routing/dht_protocol.h"
#include "libp2p/record/message.h"


/***
 * This is where kademlia and dht talk to the outside world
 */

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
	if (!context->default_stream->write(context, (unsigned char*)protocol, strlen(protocol)))
		goto exit;
	if (!context->default_stream->read(context, &results, &results_size))
		goto exit;
	if (results_size != strlen(protocol))
		goto exit;
	if (strncmp((char*)results, protocol, results_size) != 0)
		goto exit;
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
int libp2p_routing_dht_handle_ping(struct Libp2pMessage* message, unsigned char** buffer, size_t *buffer_size) {
	// just turn message back into a protobuf and send it back...
	*buffer_size = libp2p_message_protobuf_encode_size(message);
	*buffer = (unsigned char*)malloc(*buffer_size);
	return libp2p_message_protobuf_encode(message, *buffer, *buffer_size, buffer_size);
}

/**
 * See if we have information as to who can provide this item
 * @param session the context
 * @param message the message from the caller, contains a key
 * @param peerstore the list of peers
 * @param providerstore the list of peers that can provide things
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_routing_dht_handle_get_providers(struct SessionContext* session, struct Libp2pMessage* message, struct Peerstore* peerstore,
		struct ProviderStore* providerstore, unsigned char** results, size_t* results_size) {
	unsigned char* peer_id = NULL;
	int peer_id_size = 0;

	// This shouldn't be needed, but just in case:
	message->provider_peer_head = NULL;

	// Can I provide it?
	if (libp2p_providerstore_get(providerstore, message->key, message->key_size, &peer_id, &peer_id_size)) {
		// we have a peer id, convert it to a peer object
		struct Libp2pPeer* peer = libp2p_peerstore_get_peer(peerstore, peer_id, peer_id_size);
		if (peer->addr_head != NULL)
			message->provider_peer_head = peer->addr_head;
	}
	free(peer_id);
	// TODO: find closer peers
	/*
	if (message->provider_peer_head == NULL) {
		// Who else can provide it?
		//while ()
	}
	*/
	if (message->provider_peer_head != NULL) {
		// protobuf it and send it back
		*results_size = libp2p_message_protobuf_encode_size(message);
		*results = (unsigned char*)malloc(*results_size);
		if (!libp2p_message_protobuf_encode(message, *results, *results_size, results_size)) {
			free(*results);
			*results = NULL;
			*results_size = 0;
			return 0;
		}
	}
	return 1;
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
int libp2p_routing_dht_handle_add_provider(struct SessionContext* session, struct Libp2pMessage* message,
			struct Peerstore* peerstore, struct ProviderStore* providerstore, unsigned char** result_buffer, size_t* result_buffer_size) {
	int retVal = 0;
	struct Libp2pPeer *peer = NULL;

	//TODO: verify peer signature
	if (message->record != NULL && message->record->author != NULL && message->record->author_size > 0
			&& message->key != NULL && message->key_size > 0) {
		peer = libp2p_peer_new();
		peer->id_size = message->record->author_size;
		peer->id = malloc(peer->id_size);
		//TODO: Add addresses
		memcpy(peer->id, message->record->author, message->record->author_size);
		if (!libp2p_peerstore_add_peer(peerstore, peer))
			goto exit;

		libp2p_peer_free(peer);

		if (retVal == 0)
			goto exit;

		*result_buffer_size = libp2p_message_protobuf_encode_size(message);
		*result_buffer = (unsigned char*)malloc(*result_buffer_size);
		if (*result_buffer == NULL)
			goto exit;
		if (!libp2p_message_protobuf_encode(message, *result_buffer, *result_buffer_size, result_buffer_size))
			goto exit;
	}
	retVal = 1;
	exit:
	if (peer != NULL)
		libp2p_peer_free(peer);
	return retVal;
}

/**
 * Retrieve something from the dht datastore
 * @param session the session context
 * @param message the message
 * @param peerstore the peerstore
 * @param providerstore the providerstore
 * @param result_buffer the results
 * @param result_buffer_size the size of the results
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_routing_dht_handle_get_value(struct SessionContext* session, struct Libp2pMessage* message,
		struct Peerstore* peerstore, struct ProviderStore* providerstore, unsigned char** result_buffer, size_t *result_buffer_size) {
	//TODO: implement this
	return 0;
}

/**
 * Put something in the dht datastore
 * @param session the session context
 * @param message the message
 * @param peerstore the peerstore
 * @param providerstore the providerstore
 * @param result_buffer the results
 * @param result_buffer_size the size of the results
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_routing_dht_handle_put_value(struct SessionContext* session, struct Libp2pMessage* message,
		struct Peerstore* peerstore, struct ProviderStore* providerstore, unsigned char** result_buffer, size_t *result_buffer_size) {
	//TODO: implement this
	return 0;
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
int libp2p_routing_dht_handle_find_node(struct SessionContext* session, struct Libp2pMessage* message,
		struct Peerstore* peerstore, struct ProviderStore* providerstore, unsigned char** result_buffer, size_t *result_buffer_size) {
	// look through peer store
	struct Libp2pPeer* peer = libp2p_peerstore_get_peer(peerstore, message->key, message->key_size);
	if (peer != NULL) {
		message->closer_peer_head = peer->addr_head;
		*result_buffer_size = libp2p_message_protobuf_encode_size(message);
		*result_buffer = (unsigned char*)malloc(*result_buffer_size);
		if (libp2p_message_protobuf_encode(message, *result_buffer, *result_buffer_size, result_buffer_size)) {
			return 1;
		}
		free(*result_buffer);
		*result_buffer = NULL;
		*result_buffer_size = 0;
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
	struct Libp2pMessage* message = NULL;

	// read from stream
	if (!session->default_stream->read(session, &buffer, &buffer_size))
		goto exit;
	// unprotobuf
	if (!libp2p_message_protobuf_decode(buffer, buffer_size, &message))
		goto exit;
	// handle message
	switch(message->message_type) {
		case(MESSAGE_TYPE_PUT_VALUE): // store a value in local storage
				libp2p_routing_dht_handle_put_value(session, message, peerstore, providerstore, &result_buffer, &result_buffer_size);
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
		libp2p_logger_debug("dht_protocol", "Sending message back to caller\n");
		if (!session->default_stream->write(session, result_buffer, result_buffer_size))
			goto exit;
	}
	retVal = 1;
	exit:
	if (buffer != NULL)
		free(buffer);
	if (result_buffer != NULL)
		free(result_buffer);
	return retVal;
}
