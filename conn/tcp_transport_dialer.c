#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "multiaddr/multiaddr.h"
#include "libp2p/net/p2pnet.h"
#include "libp2p/conn/connection.h"
#include "libp2p/conn/transport_dialer.h"
#include "multiaddr/multiaddr.h"

/**
 * An implementation of a tcp transport dialer
 */

int libp2p_conn_tcp_can_handle(const struct MultiAddress* addr) {
	return 1;
}

int libp2p_conn_tcp_read(const struct Connection* connection, char** out, size_t* num_bytes) {
	int buffer_size = 65535;
	*out = (char*)malloc(buffer_size);
	ssize_t bytes = socket_read(connection->socket_handle, *out, buffer_size, 0, 5);
	*num_bytes = bytes;
	return bytes > 0;
}

int libp2p_conn_tcp_write(const struct Connection* connection, const char* in, size_t num_bytes) {
	ssize_t bytes = socket_write(connection->socket_handle, in, num_bytes, 0);
	return bytes == num_bytes;
}

struct Connection* libp2p_conn_tcp_dial(const struct TransportDialer* transport_dialer, const struct MultiAddress* addr) {
	struct Connection* conn = (struct Connection*) malloc(sizeof(struct Connection));
	conn->socket_handle = socket_open4();
	char* ip;
	int port = multiaddress_get_ip_port(addr);
	if (!multiaddress_get_ip_address(addr, &ip))
		return NULL;
	struct hostent* host = gethostbyname(ip);
	free(ip);
	struct in_addr** addr_list = (struct in_addr**)host->h_addr_list;
	socket_connect4(conn->socket_handle, (*addr_list[0]).s_addr, port);
	conn->read = libp2p_conn_tcp_read;
	conn->write = libp2p_conn_tcp_write;
	return conn;
}

struct TransportDialer* libp2p_conn_tcp_transport_dialer_new(char* peer_id, struct PrivateKey* private_key) {
	struct TransportDialer* out = libp2p_conn_transport_dialer_new(peer_id, private_key);
	out->can_handle = libp2p_conn_tcp_can_handle;
	out->dial = libp2p_conn_tcp_dial;
	return out;
}
