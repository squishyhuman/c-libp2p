#include <stdlib.h>
#include <string.h>

#include "libp2p/utils/vector.h"
#include "libp2p/utils/logger.h"

struct ProviderEntry {
	unsigned char* hash;
	int hash_size;
	unsigned char* peer_id;
	int peer_id_size;
};

struct ProviderStore {
	struct Libp2pVector* provider_entries;
};

/***
 * Stores hashes, and peers where you can possibly get them
 */

/**
 * Create a new ProviderStore
 * @returns a ProviderStore struct
 */
struct ProviderStore* libp2p_providerstore_new() {
	struct ProviderStore* out = (struct ProviderStore*)malloc(sizeof(struct ProviderStore));
	if (out != NULL) {
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
			struct ProviderEntry* entry = libp2p_utils_vector_get(in->provider_entries, i);
			libp2p_providerstore_entry_free(entry);
		}
		libp2p_utils_vector_free(in->provider_entries);
		free(in);
		in = NULL;
	}
}

int libp2p_providerstore_add(struct ProviderStore* store, unsigned char* hash, int hash_size, const unsigned char* peer_id, int peer_id_size) {
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

int libp2p_providerstore_get(struct ProviderStore* store, const unsigned char* hash, int hash_size, unsigned char** peer_id, int *peer_id_size) {
	struct ProviderEntry* current = NULL;
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
