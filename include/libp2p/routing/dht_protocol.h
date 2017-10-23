#pragma once

#include "libp2p/conn/session.h"
#include "libp2p/net/protocol.h"
#include "libp2p/peer/peerstore.h"
#include "libp2p/peer/providerstore.h"
#include "libp2p/record/message.h"

/***
 * This is where kademlia and dht talk to the outside world
 */

struct Libp2pProtocolHandler* libp2p_routing_dht_build_protocol_handler(struct Peerstore* peer_store, struct ProviderStore* provider_store);

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

/***
 * Send a kademlia message
 * NOTE: this call upgrades the stream to /ipfs/kad/1.0.0
 * @param context the context
 * @param message the message
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_routing_dht_send_message(struct SessionContext* sessionContext, struct KademliaMessage* message);

/**
 * Attempt to receive a kademlia message
 * NOTE: This call assumes that a send_message was sent
 * @param sessionContext the context
 * @param result where to put the results
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_routing_dht_receive_message(struct SessionContext* sessionContext, struct KademliaMessage** result);

/**
 * Used to send a message to the nearest x peers
 *
 * @param private_key the private key of the local peer
 * @param peerstore the collection of peers
 * @param datastore a connection to the datastore
 * @param msg the message to send
 * @returns true(1) if we sent to at least 1, false(0) otherwise
 */
int libp2p_routing_dht_send_message_nearest_x(const struct Dialer* dialer, struct Peerstore* peerstore,
		struct Datastore* datastore, struct KademliaMessage* msg, int numToSend);
