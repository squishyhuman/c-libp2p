#pragma once

#include "libp2p/net/stream.h"

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

/**
 * Read from a multistream socket
 * @param socket_fd the socket file descriptor
 * @param data the data to send
 * @param data_length the length of the data
 * @param timeout_secs number of seconds before read gives up. Will return 0 data length.
 * @returns the number of bytes written
 */
int libp2p_net_multistream_read(void* stream_context, unsigned char** data, size_t* data_length, int timeout_secs);
/**
 * Write to an open multistream host
 * @param socket_fd the socket file descriptor
 * @param results where to put the results. NOTE: this memory is allocated
 * @param results_size the size of the results in bytes
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_net_multistream_write(void* stream_context, const unsigned char* data, size_t data_size);

/**
 * Connect to a multistream host, and this includes the multistream handshaking.
 * @param hostname the host
 * @param port the port
 * @returns the socket file descriptor of the connection, or -1 on error
 */
struct Stream* libp2p_net_multistream_connect(const char* hostname, int port);

/**
 * Negotiate the multistream protocol by sending and receiving the protocol id. This is a server side function.
 * Servers should send the protocol ID, and then expect it back.
 * @param fd the socket file descriptor
 * @returns true(1) on success, or false(0)
 */
int libp2p_net_multistream_negotiate(struct Stream* stream);

/**
 * Expect to read a message, and follow its instructions
 * @param fd the socket file descriptor
 * @returns true(1) on success, false(0) if not
 */
struct Libp2pMessage* libp2p_net_multistream_get_message(struct Stream* stream);

struct Stream* libp2p_net_multistream_stream_new(int socket_fd, const char* ip, int port);

void libp2p_net_multistream_stream_free(struct Stream* stream);
