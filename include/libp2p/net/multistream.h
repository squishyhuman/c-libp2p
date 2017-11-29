#pragma once

#include "libp2p/net/stream.h"
#include "libp2p/conn/session.h"

/***
 * An implementation of the libp2p multistream
 *
 * NOTE: This is a severe twist on (break from?) what is multistream. In the GO code,
 * multistream does the initial connection, and has a list of protocols that
 * do the work. Here, we've gotten rid of the protocols for now, in order to
 * get things working. We're passing around DHT messages for now.
 *
 * So in short, much of this will change. But for now, think of it as a Proof of Concept.
 */

enum MultistreamStatus {
	multistream_status_initialized,
	multistream_status_syn,
	multistream_status_ack
};

struct MultistreamContext {
	struct Libp2pVector* handlers;
	struct SessionContext* session_context;
	struct Stream* stream;
	volatile enum MultistreamStatus status;
};

/***
 * The handler to handle calls to the protocol
 * @param stream_context the context
 * @returns the protocol handler
 */
struct Libp2pProtocolHandler* libp2p_net_multistream_build_protocol_handler(void* handler_vector);

/**
 * Sends the protocol header to the remote
 * @param context the context
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_net_multistream_send_protocol(struct SessionContext *context);

/***
 * Check to see if the reply is the multistream protocol header we expect
 * NOTE: if we initiate the connection, we should expect the same back
 * @param context the SessionContext
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_net_multistream_receive_protocol(struct SessionContext* context);

/**
 * Read from a multistream socket
 * @param socket_fd the socket file descriptor
 * @param data where to put the results
 * @param timeout_secs number of seconds before read gives up. Will return 0 data length.
 * @returns the number of bytes written
 */
int libp2p_net_multistream_read(void* stream_context, struct StreamMessage** data, int timeout_secs);

/**
 * Write to an open multistream host
 * @param socket_fd the socket file descriptor
 * @param msg the message to write
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_net_multistream_write(void* stream_context, struct StreamMessage* msg);

/**
 * Connect to a multistream host, and this includes the multistream handshaking.
 * @param hostname the host
 * @param port the port
 * @returns the Stream struct, or NULL on error
 */
struct Stream* libp2p_net_multistream_connect(const char* hostname, int port);

/**
 * Connect to a multistream host, and this includes the multistream handshaking.
 * @param hostname the host
 * @param port the port
 * @param timeout_secs number of secs before timeout
 * @returns the socket file descriptor of the connection, or -1 on error
 */
struct Stream* libp2p_net_multistream_connect_with_timeout(const char* hostname, int port, int timeout_secs);

/**
 * Negotiate the multistream protocol by sending and receiving the protocol id. This is a server side function.
 * Servers should send the protocol ID, and then expect it back.
 * NOTE: the SessionContext should already contain the connected stream. If not, use
 * libp2p_net_multistream_connect instead of this method.
 *
 * @param ctx a MultistreamContext
 * @param theyRequested true(1) if the multistream ID has already been received from the client
 * @returns true(1) on success, or false(0)
 */
int libp2p_net_multistream_negotiate(struct MultistreamContext* ctx, int theyRequested);

/**
 * Expect to read a message, and follow its instructions
 * @param fd the socket file descriptor
 * @returns true(1) on success, false(0) if not
 */
struct KademliaMessage* libp2p_net_multistream_get_message(struct Stream* stream);

/**
 * Add the transmission size to the front of a StreamMessage.
 * NOTE: This is used internally by multistream. It is accessible to help
 * with testing.
 * @param incoming the incoming message
 * @returns a new StreamMessage, in the format of a MessageStream buffer
 */
struct StreamMessage* libp2p_net_multistream_prepare_to_send(struct StreamMessage* incoming);

/**
 * Create a new MultiStream structure
 * @param parent_stream the stream
 * @param they_requested true(1) if they requested it (i.e. protocol id has already been sent)
 * @returns the new Stream
 */
struct Stream* libp2p_net_multistream_stream_new(struct Stream* parent_stream, int theyRequested);

void libp2p_net_multistream_stream_free(struct Stream* stream);

/***
 * Wait for multistream stream to become ready
 * @param session_context the session context to check
 * @param timeout_secs the number of seconds to wait for things to become ready
 * @returns true(1) if it becomes ready, false(0) otherwise
 */
int libp2p_net_multistream_ready(struct SessionContext* session_context, int timeout_secs);

