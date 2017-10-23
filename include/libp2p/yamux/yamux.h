#pragma once

#include "libp2p/net/protocol.h"
#include "libp2p/net/stream.h"

/***
 * Declarations for the Yamux protocol
 */

/**
 * Build a handler that can handle the yamux protocol
 */
struct Libp2pProtocolHandler* yamux_build_protocol_handler();
/***
 * Send the yamux protocol out the default stream
 * NOTE: if we initiate the connection, we should expect the same back
 * @param context the SessionContext
 * @returns true(1) on success, false(0) otherwise
 */
int yamux_send_protocol(struct SessionContext* context);

/***
 * Check to see if the reply is the yamux protocol header we expect
 * NOTE: if we initiate the connection, we should expect the same back
 * @param context the SessionContext
 * @returns true(1) on success, false(0) otherwise
 */
int yamux_receive_protocol(struct SessionContext* context);

struct Stream* libp2p_yamux_stream_new(struct Stream* parent_stream);
