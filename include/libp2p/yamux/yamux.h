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
	int am_server;
	int state; // the state of the connection
	struct Libp2pVector* protocol_handlers;
};

struct YamuxChannelContext {
	char type;
	struct YamuxContext* yamux_context;
	// this stream
	struct Stream* stream;
	// the child protocol's stream
	struct Stream* child_stream;
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
struct Libp2pProtocolHandler* libp2p_yamux_build_protocol_handler();
/***
 * Send the yamux protocol out the default stream
 * NOTE: if we initiate the connection, we should expect the same back
 * @param stream the stream
 * @returns true(1) on success, false(0) otherwise
 */
int yamux_send_protocol(struct Stream* stream);

/***
 * Check to see if the reply is the yamux protocol header we expect
 * NOTE: if we initiate the connection, we should expect the same back
 * @param context the SessionContext
 * @returns true(1) on success, false(0) otherwise
 */
int yamux_receive_protocol(struct YamuxContext* context);

/***
 * Negotiate the Yamux protocol
 * @param parent_stream the parent stream
 * @param am_server true(1) if we are considered the server, false(0) if we are the client.
 * @param protocol_handlers the protocol handlers (used when a new protocol is requested)
 * @returns a Stream initialized and ready for yamux
 */
struct Stream* libp2p_yamux_stream_new(struct Stream* parent_stream, int am_server, struct Libp2pVector* protocol_handlers);

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
 * NOTE: If incoming_stream is not of the Yamux protocol, this "wraps" the incoming
 * stream, so that the returned stream is the parent of the incoming_stream. If the
 * incoming stream is of the yamux protocol, the YamuxChannelContext.child_stream
 * will be NULL, awaiting an upgrade to fill it in.
 * @param incoming_stream the stream of the new protocol
 * @param channelNumber the channel number (0 if unknown)
 * @returns a new Stream that has a YamuxChannelContext
 */
struct Stream* libp2p_yamux_channel_stream_new(struct Stream* incoming_stream, int channelNumber);

void libp2p_yamux_channel_free(struct YamuxChannelContext* ctx);

/***
 * Prepare a new Yamux StreamMessage based on another StreamMessage
 * NOTE: This is here for testing. This should normally not be used.
 * @param incoming the incoming message
 * @returns a new StreamMessage that has a yamux_frame
 */
struct StreamMessage* libp2p_yamux_prepare_to_send(struct StreamMessage* incoming);
