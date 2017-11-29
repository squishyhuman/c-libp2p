#pragma once

/***
 * This listens for requests from the connected peers
 */
#include "libp2p/utils/thread_pool.h"
#include "libp2p/db/datastore.h"
#include "libp2p/db/filestore.h"
#include "libp2p/peer/peer.h"

struct SwarmContext {
	threadpool thread_pool;
	struct Libp2pVector* protocol_handlers;
	struct Datastore* datastore;
	struct Filestore* filestore;
};

/***
 * Add a connected peer to the swarm
 * NOTE: We should already have a connection to the peer
 * @param context the SwarmContext
 * @param peer the connected peer
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_swarm_add_peer(struct SwarmContext* context, struct Libp2pPeer* peer);

/**
 * add an incoming connection
 * @param context the SwarmContext
 * @param file_descriptor the incoming file descriptor of the connection
 * @param ip the incoming ip (ipv4 format)
 * @param port the incoming port
 * @return true(1) on success, false(0) otherwise
 */
int libp2p_swarm_add_connection(struct SwarmContext* context, int file_descriptor, int ip, int port );

/**
 * Fire up the swarm engine, and return its context
 * @param protocol_handlers the protocol handlers
 * @param datastore the datastore
 * @param filestore the file store
 * @returns the SwarmContext
 */
struct SwarmContext* libp2p_swarm_new(struct Libp2pVector* protocol_handlers, struct Datastore* datastore, struct Filestore* filestore);
