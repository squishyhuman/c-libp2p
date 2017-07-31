#pragma once

#include "libp2p/db/datastore.h"
#include "libp2p/peer/peer.h"

/**
 * Contains a hash and the peer id of
 * who can provide it
 */
struct ProviderEntry {
	unsigned char* hash;
	int hash_size;
	unsigned char* peer_id;
	int peer_id_size;
};

/***
 * A structure to store providers. The implementation
 * is a vector of ProviderEntry structures, which contain
 * the hash and peer id.
 */
struct ProviderStore {
	struct Libp2pVector* provider_entries;
	// this is requred so we can look locally for requests
	const struct Datastore* datastore;
	const struct Libp2pPeer* local_peer;
};

/**
 * Create a new ProviderStore
 * @returns a ProviderStore struct
 */
struct ProviderStore* libp2p_providerstore_new(const struct Datastore* datastore, const struct Libp2pPeer* local_peer);

/***
 * Clean resources used by a ProviderStore
 * @param in the ProviderStore to clean up
 */
void libp2p_providerstore_free(struct ProviderStore* in);

int libp2p_providerstore_add(struct ProviderStore* store, const unsigned char* hash, int hash_size, const unsigned char* peer_id, int peer_id_size);

int libp2p_providerstore_get(struct ProviderStore* store, const unsigned char* hash, int hash_size, unsigned char** peer_id, int *peer_id_size);
