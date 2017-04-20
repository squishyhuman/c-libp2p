#include <stdlib.h>
#include <string.h>

#include "libp2p/db/filestore.h"
#include "libp2p/os/utils.h"

/***
 * initialize the structure of the filestore
 * @param filestore the struct to initialize
 * @returns true(1) on success
 */
int libp2p_filestore_init(struct Filestore* datastore, const char* config_root) {
	return 1;
}

/***
 * initialize the structure of the filestore
 * @param filestore the struct to initialize
 * @returns true(1) on success
 */
struct Filestore* libp2p_filestore_new() {
	struct Filestore* f = malloc(sizeof(struct Filestore));
	if (f == NULL)
		return 0;
	f->handle = NULL;
	f->node_get = NULL;
	return f;
}

/***
 * deallocate the memory and clear resources from a filestore_init
 * @param filestore the struct to deallocate
 * @returns true(1)
 */
int libp2p_filestore_free(struct Filestore* filestore) {
	if (filestore != NULL)
	{
		free(filestore);
	}
	return 1;
}
