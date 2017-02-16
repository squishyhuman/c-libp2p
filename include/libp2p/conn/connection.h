#pragma once
/**
 * Implements an interface to connect and talk to different nodes.
 * A Dialer will connect, and return a Connection structure
 */

#include "libp2p/conn/transport_dialer.h"
#include "multiaddr/multiaddr.h"

struct Connection {
	int socket_handle;
	/**
	 * Read from the stream
	 * @param socket_handle the socket to read from
	 * @param in what was read in NOTE: this allocates memory
	 * @param in_size the number of bytes read in
	 * @returns number of bytes written or negative number on error
	 */
	int (*read)(const struct Connection* conn, char** in, size_t* in_size);
	/**
	 * Write to the stream
	 * @param socket_handle the socket to write to
	 * @param out the bytes to write to the stream
	 * @param out_size the number of bytes to write
	 * @returns 0 on success, otherwise an error code
	 */
	int (*write)(const struct Connection* conn, const char* out, size_t out_size);
};

/**
 * creates a new connection
 * @param transport_dialer the TransportDialer to use
 * @param multiaddress the destination
 * @returns a connection that is ready to be read from / written to
 */
struct Connection* libp2p_conn_connection_new(struct TransportDialer* transport_dialer, struct MultiAddress* multiaddress);

/***
 * close a connection and dispose of struct
 * @param connection the resource to clean up
 */
void libp2p_conn_connection_free(struct Connection* connection);


