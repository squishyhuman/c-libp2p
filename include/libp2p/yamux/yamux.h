#pragma once

#include "libp2p/net/protocol.h"
#include "libp2p/net/stream.h"
#include "libp2p/yamux/stream.h"

/***
 * Declarations for the Yamux protocol
 */

static const int yamux_default_timeout = 10;

static const char YAMUX_CONTEXT = 'Y';
static const char YAMUX_CHANNEL_CONTEXT = 'C';

/***
 * Context struct for Yamux
 */
struct YamuxContext {
	char type;
	struct Stream* stream;
	struct yamux_session* session;
	struct Libp2pVector* channels;
};

struct YamuxChannelContext {
	char type;
	struct YamuxContext* yamux_context;
	struct Stream* stream;
	// the channel number
	int channel;
	// the window size for this channel
	int window_size;
	// the state of the connection
	int state;
	// whether or not the connection is closed
	int closed;
};

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
int yamux_send_protocol(struct YamuxContext* context);

/***
 * Check to see if the reply is the yamux protocol header we expect
 * NOTE: if we initiate the connection, we should expect the same back
 * @param context the SessionContext
 * @returns true(1) on success, false(0) otherwise
 */
int yamux_receive_protocol(struct YamuxContext* context);

struct Stream* libp2p_yamux_stream_new(struct Stream* parent_stream);

void libp2p_yamux_stream_free(struct Stream* stream);

/****
 * Add a stream "channel" to the yamux handler
 * @param ctx the context
 * @param stream the stream to add
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_yamux_stream_add(struct YamuxContext* ctx, struct Stream* stream);

/**
 * Create a stream that has a "YamuxChannelContext" related to this yamux protocol
 * @param parent_stream the parent yamux stream
 * @returns a new Stream that is a YamuxChannelContext
 */
struct Stream* libp2p_yamux_channel_new(struct Stream* parent_stream);

void libp2p_yamux_channel_free(struct YamuxChannelContext* ctx);
