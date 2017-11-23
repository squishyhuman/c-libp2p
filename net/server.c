/**
 * A simple tcp server that uses thread pools and protocol handlers
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "libp2p/conn/session.h"
#include "libp2p/net/connectionstream.h"
#include "libp2p/net/multistream.h"
#include "libp2p/net/p2pnet.h"
#include "libp2p/net/protocol.h"
#include "libp2p/nodeio/nodeio.h"
#include "libp2p/os/utils.h"
#include "libp2p/record/message.h"
#include "libp2p/routing/dht_protocol.h"
#include "libp2p/secio/secio.h"
#include "libp2p/utils/logger.h"
#include "libp2p/utils/thread_pool.h"

struct server_connection_params {
	uint32_t ip_address_binary;
	const char* ip_address_text;
	uint16_t port;
	struct Libp2pVector* protocol_handlers;
};

struct client_connection_params {
	int file_descriptor;
	int count;
	uint16_t port;
	char* ip;
	struct Libp2pVector* protocol_handlers;
};

// this is the thread id NOTE: there should only be 1 server per instance, as this is a global
pthread_t server_pthread;

#define BUF_SIZE 4096

// this should be set to 5 for normal operation, perhaps higher for debugging purposes
#define DEFAULT_NETWORK_TIMEOUT 5

static int server_shutting_down = 0;

/**
 * We've received a new connection. Find out what they want.
 *
 * @param ptr a pointer to a null_connection_params struct
 */
void libp2p_net_connection (void *ptr) {
    struct client_connection_params *connection_param = (struct client_connection_params*) ptr;
    int retVal = 0;

    libp2p_logger_info("null", "Connection %d, count %d\n", connection_param->file_descriptor, connection_param->count);

    struct SessionContext sessionContext;
    struct Stream* clientStream = libp2p_net_connection_established(connection_param->file_descriptor, connection_param->ip, connection_param->port, &sessionContext);
    sessionContext.default_stream = clientStream;

    if (sessionContext.default_stream == NULL)
    	return;

    // try to read from the network
    struct StreamMessage *results = NULL;
	// handle the call
	for(;;) {
		// Read from the network
		if (!sessionContext.default_stream->read(sessionContext.default_stream->stream_context, &results, DEFAULT_NETWORK_TIMEOUT)) {
			// problem reading
  	    		break;
		}
		if (results != NULL) {
			retVal = libp2p_protocol_marshal(results, sessionContext.default_stream, connection_param->protocol_handlers);
			libp2p_stream_message_free(results);
			results = NULL;
		}
		if (retVal < 0 || server_shutting_down) {
			// exit the loop on error
			break;
		}
	} // end of loop

	connection_param->count--; // update counter.
	if (connection_param->ip != NULL)
		free(connection_param->ip);
	free (connection_param);
    return;
}

/***
 * Called by the daemon to listen for connections
 * @param ptr a pointer to an IpfsNodeListenParams struct
 * @returns nothing useful.
 */
void* libp2p_server_listen (void *ptr)
{
	server_shutting_down = 0;
    int socketfd, s, count = 0;
    threadpool thpool = thpool_init(25);
    struct server_connection_params *connection_param = (struct server_connection_params*)ptr;

    if ((socketfd = socket_listen(socket_tcp4(), &(connection_param->ip_address_binary), &(connection_param->port))) <= 0) {
        libp2p_logger_error("null", "Failed to init null router. Address: %d, Port: %d\n", connection_param->ip_address_text, connection_param->port);
        return (void*) 2;
    }

    struct client_connection_params* clientConnection = NULL;

    // the main loop, listening for new connections
    for (;;) {
		int numDescriptors = socket_read_select4(socketfd, 2);
		if (server_shutting_down) {
			break;
		}
		if (numDescriptors > 0) {
			s = socket_accept4(socketfd, &(connection_param->ip_address_binary), &(connection_param->port));
			if (count >= 50) { // limit reached.
				close (s);
				continue;
			}

			count++;
			clientConnection = malloc (sizeof (struct client_connection_params));
			if (clientConnection) {
				clientConnection->file_descriptor = s;
				clientConnection->count = count;
				clientConnection->port = connection_param->port;
				clientConnection->ip = malloc(INET_ADDRSTRLEN);
				clientConnection->protocol_handlers = connection_param->protocol_handlers;
				if (clientConnection->ip == NULL) {
					// we are out of memory
					free(clientConnection);
					continue;
				}
				if (inet_ntop(AF_INET, &(connection_param->ip_address_binary), clientConnection->ip, INET_ADDRSTRLEN) == NULL) {
					free(clientConnection->ip);
					clientConnection->ip = NULL;
					clientConnection->port = 0;
				}
				// Create pthread for clientConnection.
				thpool_add_work(thpool, libp2p_net_connection, clientConnection);
			}
    		} else {
    			// timeout...
    		}
    }

    thpool_destroy(thpool);

    free(connection_param);

    close(socketfd);

    return (void*) 2;
}

/***
 * Start a server given the information
 * NOTE: This spins off a thread.
 * @param ip the ip address to attach to
 * @param port the port to use
 * @param protocol_handlers the protocol handlers
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_net_server_start(const char* ip, int port, struct Libp2pVector* protocol_handlers) {
	struct server_connection_params* params = (struct server_connection_params*) malloc(sizeof(struct server_connection_params));
	params->ip_address_text = ip;
	inet_pton(AF_INET, ip, &params->ip_address_binary);
	params->port = port;
	params->protocol_handlers = protocol_handlers;
	// start on a separate thread
	pthread_create(&server_pthread, NULL, libp2p_server_listen, params);
	return 1;
}

/***
 * Shut down the server started by libp2p_net_start_server
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_net_server_stop() {
	server_shutting_down = 1;
	pthread_join(server_pthread, NULL);
	return 1;
}
