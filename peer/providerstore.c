#include <stdlib.h>
#include <string.h>

#include "libp2p/peer/providerstore.h"
#include "libp2p/utils/vector.h"
#include "libp2p/utils/logger.h"

/***
 * Stores hashes, and peers where you can possibly get them
 */

/**
 * Create a new ProviderStore
 * @param datastore the datastore (required in order to look for the file locally)
 * @param local_peer the local peer
 * @returns a ProviderStore struct
 */
struct ProviderStore* libp2p_providerstore_new(const struct Datastore* datastore, const struct Libp2pPeer* local_peer) {
	struct ProviderStore* out = (struct ProviderStore*)malloc(sizeof(struct ProviderStore));
	if (out != NULL) {
		out->datastore = datastore;
		out->local_peer = local_peer;
		out->provider_entries = libp2p_utils_vector_new(4);
	}
	return out;
}

void libp2p_providerstore_entry_free(struct ProviderEntry* in) {
	if (in != NULL) {
		if (in->hash != NULL) {
			free(in->hash);
			in->hash_size = 0;
		}
		if (in->peer_id != NULL) {
			free(in->peer_id);
			in->peer_id_size = 0;
		}
		free(in);
	}
}

/***
 * Clean resources used by a ProviderStore
 * @param in the ProviderStore to clean up
 */
void libp2p_providerstore_free(struct ProviderStore* in) {
	if (in != NULL) {
		for(int i = 0; i < in->provider_entries->total; i++) {
			struct ProviderEntry* entry = (struct ProviderEntry*) libp2p_utils_vector_get(in->provider_entries, i);
			libp2p_providerstore_entry_free(entry);
		}
		libp2p_utils_vector_free(in->provider_entries);
		free(in);
		in = NULL;
	}
}

int libp2p_providerstore_add(struct ProviderStore* store, const unsigned char* hash, int hash_size, const unsigned char* peer_id, int peer_id_size) {
	char hash_str[hash_size + 1];
	memcpy(hash_str, hash, hash_size);
	hash_str[hash_size] = 0;
	char peer_str[peer_id_size + 1];
	memcpy(peer_str, peer_id, peer_id_size);
	peer_str[peer_id_size] = 0;
	libp2p_logger_debug("providerstore", "Adding hash %s to providerstore. It can be retrieved from %s\n", hash_str, peer_str);
	struct ProviderEntry* entry = (struct ProviderEntry*)malloc(sizeof(struct ProviderEntry));
	entry->hash = malloc(hash_size);
	memcpy(entry->hash, hash, hash_size);
	entry->hash_size = hash_size;
	entry->peer_id = malloc(peer_id_size);
	memcpy(entry->peer_id, peer_id, peer_id_size);
	entry->peer_id_size = peer_id_size;
	libp2p_utils_vector_add(store->provider_entries, entry);
	return 1;
}

/**
 * See if someone has announced a key. If so, pass the peer_id
 * NOTE: This will check to see if I can provide it from my datastore
 *
 * @param store the list of providers
 * @param hash what we're looking for
 * @param hash_size the length of the hash
 * @param peer_id the peer_id of who can provide it
 * @param peer_id_size the allocated size of peer_id
 * @returns true(1) if we found something, false(0) if not.
 */
int libp2p_providerstore_get(struct ProviderStore* store, const unsigned char* hash, int hash_size, unsigned char** peer_id, int *peer_id_size) {
	struct ProviderEntry* current = NULL;
	// can I provide it locally?
	struct DatastoreRecord* datastore_record = NULL;
	if (store->datastore->datastore_get(hash, hash_size, &datastore_record, store->datastore)) {
		// we found it locally. Let them know
		*peer_id = malloc(store->local_peer->id_size);
		if (*peer_id == NULL)
			return 0;
		*peer_id_size = store->local_peer->id_size;
		memcpy(*peer_id, store->local_peer->id, *peer_id_size);
		libp2p_datastore_record_free(datastore_record);
		return 1;
	}
	// skip index 0, as we checked above...
	for (int i = 0; i < store->provider_entries->total; i++) {
		current = (struct ProviderEntry*)libp2p_utils_vector_get(store->provider_entries, i);
		if (current->hash_size == hash_size && memcmp(current->hash, hash, hash_size) == 0) {
			*peer_id = malloc(current->peer_id_size);
			memcpy(*peer_id, current->peer_id, current->peer_id_size);
			*peer_id_size = current->peer_id_size;
			return 1;
		}
	}
	return 0;
}
