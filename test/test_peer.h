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
	struct Peerstore* peerstore = libp2p_peerstore_new("Qmabcdefg");
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

int test_peer_protobuf() {
	int retVal = 0;
	struct Libp2pPeer *peer = NULL, *peer_result = NULL;
	struct MultiAddress* ma = NULL, *ma_result = NULL;
	char* peer_id = "QmW8CYQuoJhgfxTeNVFWktGFnTRzdUAimerSsHaE4rUXk8";
	unsigned char* protobuf = NULL;
	size_t protobuf_size;

	peer = libp2p_peer_new();
	peer->id_size = strlen(peer_id);
	peer->id = malloc(peer->id_size);
	memcpy(peer->id, peer_id, peer->id_size);
	peer->addr_head = libp2p_utils_linked_list_new();
	ma = multiaddress_new_from_string("/ip4/127.0.0.1/tcp/4001/ipfs/QmW8CYQuoJhgfxTeNVFWktGFnTRzdUAimerSsHaE4rUXk8/");
	peer->addr_head->item = ma;

	// protobuf
	libp2p_peer_protobuf_encode_with_alloc(peer, &protobuf, &protobuf_size);

	// unprotobuf
	libp2p_peer_protobuf_decode(protobuf, protobuf_size, &peer_result);
	ma_result = peer_result->addr_head->item;

	if (strcmp(ma->string, ma_result->string) != 0) {
		fprintf(stderr, "Results to not match: %s vs %s\n", ma->string, ma_result->string);
		goto exit;
	}

	retVal = 1;
	exit:
	//multiaddress_free(ma);
	libp2p_peer_free(peer);
	libp2p_peer_free(peer_result);
	if (protobuf != NULL)
		free(protobuf);
	return retVal;
}
