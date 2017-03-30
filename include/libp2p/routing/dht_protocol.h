#pragma once

#include "libp2p/conn/session.h"
#include "libp2p/peer/peerstore.h"
#include "libp2p/peer/providerstore.h"


/***
 * This is where kademlia and dht talk to the outside world
 */

/**
 * Take existing stream and upgrade to the Kademlia / DHT protocol/codec
 * @param context the context
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_routing_dht_upgrade_stream(struct SessionContext* context);

/**
 * Handle a client requesting an upgrade to the DHT protocol
 * @param context the context
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_routing_dht_handshake(struct SessionContext* context);

/***
 * Handle the incoming message. Handshake should have already
 * been done. We should expect  that the next read contains
 * a protobuf'd kademlia message.
 * @param session the context
 * @param peerstore a list of peers
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_routing_dht_handle_message(struct SessionContext* session, struct Peerstore* peerstore, struct ProviderStore* providerstore);
