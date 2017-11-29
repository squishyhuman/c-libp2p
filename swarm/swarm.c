/***
 * This listens for requests from the connected peers
 */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "libp2p/net/protocol.h"
#include "libp2p/net/connectionstream.h"
#include "libp2p/swarm/swarm.h"
#include "libp2p/utils/logger.h"

/**
 * Helps pass information to a new thread
 */
struct SwarmSession {
	struct SessionContext* session_context;
	struct SwarmContext* swarm_context;
};

int DEFAULT_NETWORK_TIMEOUT = 5;

/***
 * Listens on a particular stream, and marshals the request
 * @param stream the stream to listen to
 * @param protocol_handlers a vector of protocol handlers
 * @returns <0 on error, 0 if we shouldn't handle this anymore, or 1 on success
 */
int libp2p_swarm_listen_and_handle(struct Stream* stream, struct Libp2pVector* protocol_handlers) {
	struct StreamMessage* results = NULL;
	int retVal = 0;
	// Read from the network
	libp2p_logger_debug("swarm", "Attempting to get read lock.\n");
	pthread_mutex_lock(stream->socket_mutex);
	libp2p_logger_debug("swarm", "Got read lock.\n");
	if (!stream->read(stream->stream_context, &results, 1)) {
		libp2p_logger_debug("swarm", "Releasing read lock\n");
		pthread_mutex_unlock(stream->socket_mutex);
		libp2p_logger_error("swarm", "Unable to read from network. Exiting.\n");
		return retVal;
	}
	libp2p_logger_debug("swarm", "Releasing read lock.\n");
	pthread_mutex_unlock(stream->socket_mutex);
	if (results != NULL) {
		libp2p_logger_debug("swarm", "Attempting to marshal %d bytes from network.\n", results->data_size);
		retVal = libp2p_protocol_marshal(results, stream, protocol_handlers);
		libp2p_logger_debug("swarm", "The return value from the attempt to marshal %d bytes was %d.\n", results->data_size, retVal);
		libp2p_stream_message_free(results);
	} else {
		libp2p_logger_debug("swarm", "Attempted read, but results were null. This is normal.\n");
	}
	return retVal;
}

/***
 * This is on its own thread, and listens for incoming data from a particular client
 * @param session the SessionContext
 */
void libp2p_swarm_listen(void* ctx) {
	struct SwarmSession* swarm_session = (struct SwarmSession*) ctx;
	struct SessionContext* session_context = swarm_session->session_context;
	int retVal = 0;
	for(;;) {
		// Read from the network
		retVal = libp2p_swarm_listen_and_handle(session_context->default_stream, swarm_session->swarm_context->protocol_handlers);
		if (retVal < 0) {
			// exit the loop on error
			libp2p_logger_debug("swarm", "listen: Exiting loop due to retVal being %d.\n", retVal);
			break;
		}
	} // end of loop

	// clean up memory
	if (session_context->host != NULL)
		free(session_context->host);
	free(swarm_session);
}

/***
 * Add a connected peer to the swarm
 * NOTE: We should already have a connection to the peer
 * @param context the SwarmContext
 * @param peer the connected peer
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_swarm_add_peer(struct SwarmContext* context, struct Libp2pPeer* peer) {
	// spin off a thread for this peer
    struct SwarmSession* swarm_session = (struct SwarmSession*) malloc(sizeof(struct SwarmSession));
    swarm_session->session_context = peer->sessionContext;
    swarm_session->swarm_context = context;

    if (thpool_add_work(context->thread_pool, libp2p_swarm_listen, swarm_session) < 0) {
    	libp2p_logger_error("swarm", "Unable to fire up thread for peer %s\n", libp2p_peer_id_to_string(peer));
    	return 0;
    }
    libp2p_logger_info("swarm", "add_connection: added connection for peer %s.\n", libp2p_peer_id_to_string(peer));

    return 1;
}


/**
 * add an incoming connection
 * @param context the SwarmContext
 * @param file_descriptor the incoming file descriptor of the connection
 * @param ip the incoming ip (ipv4 format)
 * @param port the incoming port
 * @return true(1) on success, false(0) otherwise
 */
int libp2p_swarm_add_connection(struct SwarmContext* context, int file_descriptor, int ip, int port ) {

	// build a session context
    struct SessionContext* session = libp2p_session_context_new();
    if (session == NULL) {
		libp2p_logger_error("swarm", "Unable to allocate SessionContext. Out of memory?\n");
		return 0;
    }

    session->datastore = context->datastore;
    session->filestore = context->filestore;
    // convert IP address to text
	session->host = malloc(INET_ADDRSTRLEN);
	if (session->host == NULL) {
		// we are out of memory
		free(session->host);
		return 0;
	}
	if (inet_ntop(AF_INET, &ip, session->host, INET_ADDRSTRLEN) == NULL) {
		free(session->host);
		session->host = NULL;
		session->port = 0;
		return 0;
	}
    session->port = port;
    session->insecure_stream = libp2p_net_connection_new(file_descriptor, session->host, session->port, session);
    session->default_stream = session->insecure_stream;

    struct SwarmSession* swarm_session = (struct SwarmSession*) malloc(sizeof(struct SwarmSession));
    swarm_session->session_context = session;
    swarm_session->swarm_context = context;

    if (thpool_add_work(context->thread_pool, libp2p_swarm_listen, swarm_session) < 0) {
    	libp2p_logger_error("swarm", "Unable to fire up thread for connection %d\n", file_descriptor);
    	return 0;
    }
    libp2p_logger_info("swarm", "add_connection: added connection %d.\n", file_descriptor);

    return 1;
}

/**
 * Fire up the swarm engine, and return its context
 * @param protocol_handlers the protocol handlers
 * @param datastore the datastore
 * @param filestore the file store
 * @returns the SwarmContext
 */
struct SwarmContext* libp2p_swarm_new(struct Libp2pVector* protocol_handlers, struct Datastore* datastore, struct Filestore* filestore) {
	struct SwarmContext* context = (struct SwarmContext*) malloc(sizeof(struct SwarmContext));
	if (context != NULL) {
		context->thread_pool = thpool_init(25);
		context->protocol_handlers = protocol_handlers;
		context->datastore = datastore;
		context->filestore = filestore;
	}
	return context;
}
