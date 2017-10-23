#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "multiaddr/multiaddr.h"
#include "libp2p/net/p2pnet.h"
#include "libp2p/net/connectionstream.h"
#include "libp2p/conn/connection.h"
#include "libp2p/conn/transport_dialer.h"
#include "multiaddr/multiaddr.h"

/**
 * An implementation of a tcp transport dialer
 */

int libp2p_conn_tcp_can_handle(const struct MultiAddress* addr) {
	return multiaddress_is_ip(addr);
}

struct Stream* libp2p_conn_tcp_dial(const struct TransportDialer* transport_dialer, const struct MultiAddress* addr) {
	int socket_descriptor = socket_open4();
	char* ip;
	int port = multiaddress_get_ip_port(addr);
	if (!multiaddress_get_ip_address(addr, &ip))
		return NULL;

	struct Stream* stream = libp2p_net_connection_new(socket_descriptor, ip, port);
	free(ip);

	return stream;
}

struct TransportDialer* libp2p_conn_tcp_transport_dialer_new(char* peer_id, struct PrivateKey* private_key) {
	struct TransportDialer* out = libp2p_conn_transport_dialer_new(peer_id, private_key);
	out->can_handle = libp2p_conn_tcp_can_handle;
	out->dial = libp2p_conn_tcp_dial;
	return out;
}
