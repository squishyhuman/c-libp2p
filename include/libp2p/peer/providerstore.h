#pragma once

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
struct ProviderStore* libp2p_providerstore_new();

/***
 * Clean resources used by a ProviderStore
 * @param in the ProviderStore to clean up
 */
void libp2p_providerstore_free(struct ProviderStore* in);

void libp2p_providerstore_add(struct ProviderStore* store, unsigned char* hash, int hash_size, unsigned char* peer_id, int peer_id_size);

int libp2p_providerstore_get(struct ProviderStore* store, unsigned char* hash, int hash_size, unsigned char** peer_id, int *peer_id_size);
