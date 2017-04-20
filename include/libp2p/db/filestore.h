#pragma once

#include <stdint.h>

/***
 * Interface to data storage
 */


struct Filestore {

	// generic connection and status variables for the datastore
	void* handle; // a handle to the filesstore (a FSRepo struct)

	// function pointers for datastore operations
	/**
	 * Retrieves a protobuf'd node from the disk
	 * @param key the key
	 * @param key_size the key size
	 * @param data the protobuf'd results
	 * @param data_size the size of the results
	 * @param filestore a reference to the filestore struct
	 */
	int (*node_get)(const unsigned char* key, size_t key_size,
			void** data, size_t *data_size, const struct Filestore* filestore);
};

/***
 * Initialize the structure of the filestore to default settings. Used for
 * creating a new filestore on the disk.
 * @param filestore the struct to initialize
 * @param config_root the path to the root of IPFS
 * @returns true(1) on success
 */
int libp2p_filestore_init(struct Filestore* filestore, const char* config_root);

/***
 * initialize the structure of the filestore
 * @param filestore the struct to initialize
 * @returns true(1) on success
 */
struct Filestore* libp2p_filestore_new();


/***
 * deallocate the memory and clear resources from a filestore_init
 * @param filestore the struct to deallocate
 * @returns true(1)
 */
int libp2p_filestore_free(struct Filestore* datastore);
