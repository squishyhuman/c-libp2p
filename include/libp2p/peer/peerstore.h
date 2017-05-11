#pragma once

#include "libp2p/utils/linked_list.h"
#include "libp2p/peer/peer.h"

/**
 * Structures and functions to implement a storage area for peers and
 * their connections and metadata
 */

/**
 * An entry in the "database" is a PeerEntry. This contains metadata
 * about the peer
 */
struct PeerEntry {
	struct Libp2pPeer* peer;
	// other metadata for the peer goes here
	// TODO: add some type of timer to expire the record
};

/**
 * Contains a collection of peers and their metadata
 * NOTE: this is currently a linked list. Perhaps a better algo would
 * improve performance, but will wait.
 */
struct Peerstore {
	struct Libp2pLinkedList* head_entry;
	struct Libp2pLinkedList* last_entry;
};

struct PeerEntry* libp2p_peer_entry_new();
void libp2p_peer_entry_free(struct PeerEntry* in);

/**
 * Creates a new empty peerstore
 * @param peer_id the peer id as a null terminated string
 * @returns an empty peerstore or NULL on error
 */
struct Peerstore* libp2p_peerstore_new(const char* peer_id);

/**
 * Deallocate resources used by the peerstore
 * @param in the struct to deallocate
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_peerstore_free(struct Peerstore* in);

/**
 * Add a Peer to the Peerstore
 * @param peerstore the peerstore to add the entry to
 * @param peer_entry the entry to add
 * @returns true(1) on success, otherwise false
 */
int libp2p_peerstore_add_peer_entry(struct Peerstore* peerstore, struct PeerEntry* peer_entry);

/***
 * Add a peer to the peerstore
 * @param peerstore the peerstore to add the entry to
 * @param peer the peer to add (will be wrapped in PeerEntry struct)
 * @returns true(1) on success, otherwise false
 */
int libp2p_peerstore_add_peer(struct Peerstore* peerstore, struct Libp2pPeer* peer);

/**
 * Retrieve a peer from the peerstore based on the peer id
 * @param peerstore the peerstore to search
 * @param peer_id the id to search for as a binary array
 * @param peer_id_size the size of the binary array
 * @returns the PeerEntry struct if found, otherwise NULL
 */
struct PeerEntry* libp2p_peerstore_get_peer_entry(struct Peerstore* peerstore, const unsigned char* peer_id, size_t peer_id_size);

/**
 * Retrieve a peer from the peerstore based on the peer id
 * @param peerstore the peerstore to search
 * @param peer_id the id to search for as a binary array
 * @param peer_id_size the size of the binary array
 * @returns the Libp2pPeer struct if found, otherwise NULL
 */
struct Libp2pPeer* libp2p_peerstore_get_peer(struct Peerstore* peerstore, const unsigned char* peer_id, size_t peer_id_size);

/**
 * Look for this peer in the peerstore. If it is found, return a reference to that object.
 * If it is not found, add it, and return a reference to the new copy
 * @param peerstore the peerstore to search
 * @param in the peer to search for
 */
struct Libp2pPeer* libp2p_peerstore_get_or_add_peer(struct Peerstore* peerstore, struct Libp2pPeer* in);

