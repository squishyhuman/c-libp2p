#pragma once

#include <stdint.h>

/***
 * Interface to data storage
 */

enum DatastoreCursorOp { CURSOR_FIRST, CURSOR_NEXT };

struct Datastore {
	char* type;
	char* path;
	char* storage_max;
	int storage_gc_watermark;
	char* gc_period;
	char* params;
	int no_sync;
	int hash_on_read;
	int bloom_filter_size;

	// function pointers for datastore operations
	int (*datastore_open)(int argc, char** argv, struct Datastore* datastore);
	int (*datastore_close)(struct Datastore* datastore);
	int (*datastore_put)(const unsigned char* key, size_t key_size, unsigned char* data, size_t data_length, const struct Datastore* datastore);
	int (*datastore_get)(const char* key, size_t key_size,
			unsigned char* data, size_t max_data_length, size_t* data_length,
			const struct Datastore* datastore);
	int (*datastore_cursor_open)(struct Datastore* datastore);
	int (*datastore_cursor_close)(struct Datastore* datastore);
	int (*datastore_cursor_get)(unsigned char** key, int* key_length, unsigned char** value, int* value_length, enum DatastoreCursorOp op, struct Datastore* datastore);
	// generic connection and status variables for the datastore
	void* handle; // a handle to the database
	void* cursor; // a current cursor
};

/***
 * Initialize the structure of the datastore to default settings. Used for
 * creating a new datastore on the disk.
 * @param datastore the struct to initialize
 * @param config_root the path to the root of IPFS
 * @returns true(1) on success
 */
int libp2p_datastore_init(struct Datastore* datastore, const char* config_root);

/***
 * initialize the structure of the datastore
 * @param datastore the struct to initialize
 * @returns true(1) on success
 */
int libp2p_datastore_new(struct Datastore** datastore);


/***
 * deallocate the memory and clear resources from a datastore_init
 * @param datastore the struct to deallocate
 * @returns true(1)
 */
int libp2p_datastore_free(struct Datastore* datastore);
