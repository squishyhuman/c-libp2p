#include <stdlib.h>
#include <string.h>

#include "libp2p/peer/peerstore.h"
#include "libp2p/utils/logger.h"

struct PeerEntry* libp2p_peer_entry_new() {
	struct PeerEntry* out = (struct PeerEntry*)malloc(sizeof(struct PeerEntry));
	if (out != NULL) {
		out->peer = NULL;
	}
	return out;
}

void libp2p_peer_entry_free(struct PeerEntry* in) {
	if (in != NULL) {
		libp2p_peer_free(in->peer);
		free(in);
	}
}

struct PeerEntry* libp2p_peer_entry_copy(struct PeerEntry* in) {
	struct PeerEntry* out = libp2p_peer_entry_new();
	if (out != NULL) {
		out->peer = libp2p_peer_copy(in->peer);
		if (out->peer == NULL) {
			free(out);
			return NULL;
		}
	}
	return out;
}

/**
 * Creates a new empty peerstore
 * @param peer_id the peer id as a null terminated string
 * @returns an empty peerstore or NULL on error
 */
struct Peerstore* libp2p_peerstore_new(const char* peer_id) {
	struct Peerstore* out = (struct Peerstore*)malloc(sizeof(struct Peerstore));
	if (out != NULL) {
		out->head_entry = NULL;
		out->last_entry = NULL;
		// now add this peer as the first entry
		struct Libp2pPeer* peer = libp2p_peer_new();
		peer->connection_type = CONNECTION_TYPE_NOT_CONNECTED;
		peer->id_size = strlen(peer_id);
		peer->id = malloc(peer->id_size);
		memcpy(peer->id, peer_id, peer->id_size);
		libp2p_peerstore_add_peer(out, peer);
		libp2p_peer_free(peer);
	}
	return out;
}

/**
 * Deallocate resources used by the peerstore
 * @param in the struct to deallocate
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_peerstore_free(struct Peerstore* in) {
	if (in != NULL) {
		struct Libp2pLinkedList* current = in->head_entry;
		struct Libp2pLinkedList* next = NULL;
		while (current != NULL) {
			next = current->next;
			libp2p_peer_entry_free((struct PeerEntry*)current->item);
			current->item = NULL;
			current = next;
		}
		libp2p_utils_linked_list_free(in->head_entry);
		free(in);
	}
	return 1;
}

/**
 * Add a Peer to the Peerstore
 * @param peerstore the peerstore to add the entry to
 * @param peer_entry the entry to add
 * @returns true(1) on success, otherwise false
 */
int libp2p_peerstore_add_peer_entry(struct Peerstore* peerstore, struct PeerEntry* peer_entry) {
	struct Libp2pLinkedList* new_item = libp2p_utils_linked_list_new();
	if (new_item == NULL)
		return 0;
	new_item->item = libp2p_peer_entry_copy(peer_entry);
	if (new_item->item == NULL) {
		libp2p_utils_linked_list_free(new_item);
		return 0;
	}
	if (peerstore->head_entry == NULL) {
		peerstore->head_entry = new_item;
		peerstore->last_entry = new_item;
	} else {
		peerstore->last_entry->next = new_item;
		peerstore->last_entry = new_item;
	}
	return 1;
}

/***
 * Add a peer to the peerstore
 * @param peerstore the peerstore to add the entry to
 * @param peer the peer to add (will be wrapped in PeerEntry struct)
 * @returns true(1) on success, otherwise false
 */
int libp2p_peerstore_add_peer(struct Peerstore* peerstore, struct Libp2pPeer* peer) {
	int retVal = 0;

	char* ma_string = "";
	if (peer != NULL && peer->addr_head != NULL && peer->addr_head->item != NULL) {
		ma_string = ((struct MultiAddress*)peer->addr_head->item)->string;
	}
	// first check to see if it exists. If it does, return TRUE
	if (libp2p_peerstore_get_peer_entry(peerstore, peer->id, peer->id_size) != NULL) {
		libp2p_logger_debug("peerstore", "Attempted to add %s to peerstore, but already there.\n", ma_string);
		return 1;
	}

	if (peer->id_size > 0) {
		char peer_id[peer->id_size + 1];
		memcpy(peer_id, peer->id, peer->id_size);
		peer_id[peer->id_size] = 0;
		if (peer->addr_head != NULL) {
			char* address = ((struct MultiAddress*)peer->addr_head->item)->string;
			libp2p_logger_debug("peerstore", "Adding peer %s with address %s to peer store\n", peer_id, address);
		}
		struct PeerEntry* peer_entry = libp2p_peer_entry_new();
		if (peer_entry == NULL) {
			return 0;
		}
		peer_entry->peer = libp2p_peer_copy(peer);
		if (peer_entry->peer == NULL)
			return 0;
		retVal = libp2p_peerstore_add_peer_entry(peerstore, peer_entry);
		libp2p_peer_entry_free(peer_entry);
		libp2p_logger_debug("peerstore", "Adding peer %s to peerstore was a success\n", peer_id);
	}
	return retVal;
}

/**
 * Retrieve a peer from the peerstore based on the peer id
 * @param peerstore the peerstore to search
 * @param peer_id the id to search for as a binary array
 * @param peer_id_size the size of the binary array
 * @returns the PeerEntry struct if found, otherwise NULL
 */
struct PeerEntry* libp2p_peerstore_get_peer_entry(struct Peerstore* peerstore, const unsigned char* peer_id, size_t peer_id_size) {
	struct Libp2pLinkedList* current = peerstore->head_entry;
	// JMJ Debugging
	int count = 0;
	while(current != NULL) {
		count++;
		struct Libp2pPeer* peer = ((struct PeerEntry*)current->item)->peer;
		if (peer->id_size == peer_id_size) {
			if (memcmp(peer_id, peer->id, peer->id_size) == 0) {
				return (struct PeerEntry*)current->item;
			}
		}
		current = current->next;
	}
	return NULL;
}

/**
 * Retrieve a peer from the peerstore based on the peer id
 * @param peerstore the peerstore to search
 * @param peer_id the id to search for as a binary array
 * @param peer_id_size the size of the binary array
 * @returns the Peer struct if found, otherwise NULL
 */
struct Libp2pPeer* libp2p_peerstore_get_peer(struct Peerstore* peerstore, const unsigned char* peer_id, size_t peer_id_size) {
	struct PeerEntry* entry = libp2p_peerstore_get_peer_entry(peerstore, peer_id, peer_id_size);
	if (entry == NULL)
		return NULL;
	return entry->peer;
}

/**
 * Look for this peer in the peerstore. If it is found, return a reference to that object.
 * If it is not found, add it, and return a reference to the new copy
 * @param peerstore the peerstore to search
 * @param in the peer to search for
 */
struct Libp2pPeer* libp2p_peerstore_get_or_add_peer(struct Peerstore* peerstore, struct Libp2pPeer* in) {
	struct Libp2pPeer* out = libp2p_peerstore_get_peer(peerstore, (unsigned char*)in->id, in->id_size);
	if (out != NULL)
		return out;

	// we didn't find it. attempt to add
	if (!libp2p_peerstore_add_peer(peerstore, in))
		return NULL;

	return libp2p_peerstore_get_peer(peerstore, (unsigned char*)in->id, in->id_size);
}
