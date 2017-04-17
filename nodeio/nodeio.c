#include <stdlib.h>
#include <string.h>

#include "libp2p/net/stream.h"
#include "libp2p/conn/session.h"

int libp2p_nodeio_upgrade_stream(struct SessionContext* context) {
	int retVal = 0;
	char* protocol = "/nodeio/1.0.0\n";
	unsigned char* results = NULL;
	size_t results_size = 0;
	if (!context->default_stream->write(context, (unsigned char*)protocol, strlen(protocol)))
		goto exit;
	if (!context->default_stream->read(context, &results, &results_size, 5))
		goto exit;
	if (results_size != strlen(protocol))
		goto exit;
	if (strncmp((char*)results, protocol, results_size) != 0)
		goto exit;
	retVal = 1;
	exit:
	if (results != NULL) {
		free(results);
		results = NULL;
	}
	return retVal;
}

/**
 * Called by requestor to get a protobuf'd node from a hash
 * @param context the session context
 * @param hash the hash
 * @param hash_size the length of the hash
 * @param results where to put the buffer
 * @param results_size the size of the results
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_nodeio_get(struct SessionContext* context, unsigned char* hash, int hash_length, unsigned char** results, size_t* results_size) {
	if (!context->default_stream->write(context, hash, hash_length))
		return 0;
	if (!context->default_stream->read(context, results, results_size, 5))
		return 0;
	return 1;
}

int libp2p_nodeio_handshake(struct SessionContext* context) {
	char* protocol = "/nodeio/1.0.0\n";
	return context->default_stream->write(context, (unsigned char*)protocol, strlen(protocol));
}
