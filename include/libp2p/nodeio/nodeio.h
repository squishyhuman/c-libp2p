#pragma once

#include "libp2p/net/stream.h"
#include "libp2p/conn/session.h"

int libp2p_nodeio_upgrade_stream(struct SessionContext* context);
int libp2p_nodeio_handshake(struct SessionContext* context);
int libp2p_nodeio_handle(struct SessionContext* context);
/**
 * Called by requestor to get a protobuf'd node from a hash
 * @param context the session context
 * @param hash the hash
 * @param hash_size the length of the hash
 * @param results where to put the buffer
 * @param results_size the size of the results
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_nodeio_get(struct SessionContext* context, unsigned char* hash, int hash_size, unsigned char** results, size_t* results_length);
