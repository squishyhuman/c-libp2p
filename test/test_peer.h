#pragma once

#include <stdlib.h>
#include "libp2p/peer/peer.h"
#include "libp2p/peer/peerstore.h"

/***
 * Includes Libp2pPeer, PeerEntry, Peerstore
 */

/**
 * Test the basics of peer
 */
int test_peer() {
	struct Libp2pPeer* obj = libp2p_peer_new();
	if (obj == NULL)
		return 0;

	libp2p_peer_free(obj);
	return 1;
}

/**
 * Test the peerstore
 */
int test_peerstore() {
	struct Peerstore* peerstore = libp2p_peerstore_new();
	struct PeerEntry* peer_entry = NULL;
	struct PeerEntry* results = NULL;
	int retVal = 0;

	if (peerstore == NULL)
		goto exit;

	// add a peer entry to the peerstore
	peer_entry = libp2p_peer_entry_new();
	peer_entry->peer = libp2p_peer_new();
	peer_entry->peer->id_size = 6;
	peer_entry->peer->id = malloc(peer_entry->peer->id_size);
	memcpy(peer_entry->peer->id, "ABC123", peer_entry->peer->id_size);
	peer_entry->peer->connection_type = CONNECTION_TYPE_NOT_CONNECTED;

	if (!libp2p_peerstore_add_peer_entry(peerstore, peer_entry))
		goto exit;

	// now try to retrieve it
	results = libp2p_peerstore_get_peer_entry(peerstore, "ABC123", 6);

	if (results == NULL || results->peer->id_size != 6)
		goto exit;

	// cleanup
	retVal = 1;

	exit:
	if (peerstore != NULL)
		libp2p_peerstore_free(peerstore);
	if (peer_entry != NULL)
		libp2p_peer_entry_free(peer_entry);
	return retVal;
}
