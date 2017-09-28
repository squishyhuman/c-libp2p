#include <stdlib.h>
#include <string.h>

#include "libp2p/peer/peerstore.h"
#include "libp2p/utils/logger.h"

/***
 * Creates a new PeerEntry struct
 * @returns the newly allocated struct or NULL
 */
struct PeerEntry* libp2p_peer_entry_new() {
	struct PeerEntry* out = (struct PeerEntry*)malloc(sizeof(struct PeerEntry));
	if (out != NULL) {
		out->peer = NULL;
	}
	return out;
}

/***
 * Frees resources
 * @param in the PeerEntry to free
 */
void libp2p_peer_entry_free(struct PeerEntry* in) {
	if (in != NULL) {
		libp2p_peer_free(in->peer);
		free(in);
	}
}

/***
 * Copies a PeerEntry
 * @param in the PeerEntry to copy
 * @returns a newly allocated PeerEntry with the values from "in"
 */
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
struct Peerstore* libp2p_peerstore_new(const struct Libp2pPeer* local_peer) {
	struct Peerstore* out = (struct Peerstore*)malloc(sizeof(struct Peerstore));
	if (out != NULL) {
		out->head_entry = NULL;
		out->last_entry = NULL;
		// now add this peer as the first entry
		libp2p_peerstore_add_peer(out, local_peer);
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
		// first empty out the peer entries
		while (current != NULL) {
			next = current->next;
			libp2p_peer_entry_free((struct PeerEntry*)current->item);
			current->item = NULL;
			current = next;
		}
		// now free the linked list entries
		libp2p_utils_linked_list_free(in->head_entry);
		// and finally the peerstore itself
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
	if (peer_entry == NULL)
		return 0;

	struct Libp2pLinkedList* new_item = libp2p_utils_linked_list_new();
	if (new_item == NULL)
		return 0;

	new_item->item = peer_entry;
	if (peerstore->head_entry == NULL) {
		peerstore->head_entry = new_item;
		peerstore->last_entry = new_item;
	} else {
		peerstore->last_entry->next = new_item;
		peerstore->last_entry = new_item;
	}
	return 1;
}

int libp2p_peerstore_update_addresses(struct Libp2pPeer* existing, const struct Libp2pPeer* incoming) {
	struct Libp2pLinkedList* incoming_list_pos = incoming->addr_head;
	while (incoming_list_pos != NULL) {
		if (incoming_list_pos->item == NULL) {
			libp2p_logger_error("peerstore", "update_addresses: incoming address list has null item.\n");
		} else {
			struct MultiAddress* incoming_ma = (struct MultiAddress*) incoming_list_pos->item;
			// see if we have this multiaddress already
			struct Libp2pLinkedList* existing_list_pos = existing->addr_head;
			while (existing_list_pos != NULL) {
				if (multiaddress_compare(incoming_ma, (struct MultiAddress*)existing_list_pos->item) == 0) {
					// we found a match
					break;
				}
				existing_list_pos = existing_list_pos->next;
			}
			if (existing_list_pos == NULL) {
				// we didnt find a match. Add this multiaddress to the top of the existing peer's list
				struct MultiAddress* ma_copy = multiaddress_copy(incoming_ma);
				if (ma_copy == NULL) {
					libp2p_logger_error("peerstore", "Attempted copy of multiaddress, but was null.");
				} else {
					struct Libp2pLinkedList* new_ma = libp2p_utils_linked_list_new();
					new_ma->item = multiaddress_copy(incoming_list_pos->item);
					new_ma->next = existing->addr_head;
					existing->addr_head = new_ma;
				}
			}
		}
		incoming_list_pos = incoming_list_pos->next;
	}
	return 1;
}

/***
 * Add a peer to the peerstore
 * @param peerstore the peerstore to add the entry to
 * @param peer the peer to add (will be wrapped in PeerEntry struct)
 * @returns true(1) on success, otherwise false
 */
int libp2p_peerstore_add_peer(struct Peerstore* peerstore, const struct Libp2pPeer* peer) {
	int retVal = 0;

	char* ma_string = "";
	if (peer != NULL && peer->addr_head != NULL && peer->addr_head->item != NULL) {
		ma_string = ((struct MultiAddress*)peer->addr_head->item)->string;
	}
	// first check to see if it exists. If it does, return TRUE
	struct PeerEntry* peer_entry = libp2p_peerstore_get_peer_entry(peerstore, (unsigned char*)peer->id, peer->id_size);
	if (peer_entry != NULL) {
		libp2p_logger_debug("peerstore", "Attempted to add %s to peerstore, but already there. Checking if we need to update addresses.\n", ma_string);
		libp2p_peerstore_update_addresses(peer_entry->peer, peer);
		return 1;
	}

	if (peer->id_size > 0) {
		if (peer->addr_head != NULL && peer->addr_head->item != NULL) {
			char* address = ((struct MultiAddress*)peer->addr_head->item)->string;
			libp2p_logger_debug("peerstore", "Adding peer %s with address %s to peer store\n", libp2p_peer_id_to_string(peer), address);
		} else {
			libp2p_logger_debug("peerstore", "Adding peer %s with no addresses to peer store.\n", libp2p_peer_id_to_string(peer));
		}
		struct PeerEntry* peer_entry = libp2p_peer_entry_new();
		if (peer_entry == NULL) {
			libp2p_logger_error("peerstore", "Unable to allocate memory for new PeerEntry.\n");
			return 0;
		}
		peer_entry->peer = libp2p_peer_copy(peer);
		if (peer_entry->peer == NULL) {
			libp2p_logger_error("peerstore", "Could not copy peer for PeerEntry.\n");
			return 0;
		}
		retVal = libp2p_peerstore_add_peer_entry(peerstore, peer_entry);
		libp2p_logger_debug("peerstore", "Adding peer %s to peerstore was a success\n", peer->id);
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
	if (peer_id_size == 0 || peer_id == NULL || peerstore == NULL)
		return NULL;

	struct Libp2pLinkedList* current = peerstore->head_entry;
	while(current != NULL) {
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
 * Retrieves the local peer, which is always the first in the collection
 * @param peerstore the peerstore
 * @returns the first Libp2pPeer in the collection
 */
struct Libp2pPeer* libp2p_peerstore_get_local_peer(struct Peerstore* peerstore) {
	struct Libp2pPeer* retVal = NULL;
	if (peerstore != NULL && peerstore->head_entry != NULL && peerstore->head_entry->item != NULL) {
		struct PeerEntry* entry = peerstore->head_entry->item;
		retVal = entry->peer;
	}
	return retVal;
}

/***
 * Look for a peer by id. If not found, add it to the peerstore
 * @param peerstore the Peerstore
 * @param peer_id the peer id
 * @param peer_id_size the size of peer_id
 * @returns a Peer struct, or NULL if error
 */
struct Libp2pPeer* libp2p_peerstore_get_or_add_peer_by_id(struct Peerstore* peerstore, const unsigned char* peer_id, size_t peer_id_size) {
	if (peer_id_size == 0)
		return NULL;

	struct PeerEntry* entry = libp2p_peerstore_get_peer_entry(peerstore, peer_id, peer_id_size);
	if (entry == NULL) {
		// add it
		struct Libp2pPeer* temp_peer = libp2p_peer_new();
		temp_peer->id_size = peer_id_size;
		temp_peer->id = (char*)peer_id;
		libp2p_peerstore_add_peer(peerstore, temp_peer);
		libp2p_peer_free(temp_peer);
		entry = libp2p_peerstore_get_peer_entry(peerstore, peer_id, peer_id_size);
	}
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
struct Libp2pPeer* libp2p_peerstore_get_or_add_peer(struct Peerstore* peerstore, const struct Libp2pPeer* in) {
	if (in == NULL)
		return NULL;

	struct Libp2pPeer* out = libp2p_peerstore_get_peer(peerstore, (unsigned char*)in->id, in->id_size);
	if (out != NULL)
		return out;

	// we didn't find it. attempt to add
	if (!libp2p_peerstore_add_peer(peerstore, in))
		return NULL;

	return libp2p_peerstore_get_peer(peerstore, (unsigned char*)in->id, in->id_size);
}
