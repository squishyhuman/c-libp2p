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
	 * @returns 0 on success, otherwise an error code
	 */
	int (*read)(int socket_handle, char** in, size_t* in_size);
	/**
	 * Write to the stream
	 * @param socket_handle the socket to write to
	 * @param out the bytes to write to the stream
	 * @param out_size the number of bytes to write
	 * @returns 0 on success, otherwise an error code
	 */
	int (*write)(int socket_handle, char* out, size_t* out_size);
};

struct Connection* libp2p_conn_connection_open(struct TransportDialer* transport_dialer, struct maddr* multiaddress);
