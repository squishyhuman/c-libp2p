#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "multiaddr/multiaddr.h"
#include "libp2p/net/p2pnet.h"
#include "libp2p/conn/connection.h"
#include "libp2p/conn/transport_dialer.h"

/**
 * An implementation of a tcp transport dialer
 */


struct TcpIp {
	char* ip;
	int port;
};

struct TcpIp* libp2p_conn_parse_ip_multiaddress(struct MultiAddress* addr) {
	struct TcpIp* out = (struct TcpIp*)malloc(sizeof(struct TcpIp));
	char* address = malloc(strlen(addr->string) + 1);
	strcpy(address, addr->string);
	char* tok = strtok(address, "/");
	int pos = 0;
	while (tok != NULL) {
		switch (pos) {
			case 2: {
				out->ip = malloc(strlen(tok) + 1);
				strcpy(out->ip, tok);
				break;
			}
			case 4: {
				out->port = strtol(tok, NULL, 10);
				break;
			}
		}
		tok = strtok(NULL, "/");
		pos++;
	}
	//TODO: do a better job of parsing the results
	return out;
}

int libp2p_conn_tcp_can_handle(struct MultiAddress* addr) {
	return 1;
}



struct Connection* libp2p_conn_tcp_dial(struct TransportDialer* transport_dialer, struct MultiAddress* addr) {
	struct Connection* conn = (struct Connection*) malloc(sizeof(struct Connection*));
	conn->socket_handle = socket_open4();
	struct TcpIp* results = libp2p_conn_parse_ip_multiaddress(addr);
	struct hostent* host = gethostbyname(results->ip);
	struct in_addr** addr_list = (struct in_addr**)host->h_addr_list;
	socket_connect4(conn->socket_handle, (*addr_list[0]).s_addr, results->port);
	return conn;
}

struct TransportDialer* libp2p_conn_tcp_transport_dialer_new(char* peer_id, struct PrivateKey* private_key) {
	struct TransportDialer* out = libp2p_conn_transport_dialer_new(peer_id, private_key);
	out->can_handle = libp2p_conn_tcp_can_handle;
	out->dial = libp2p_conn_tcp_dial;
	return out;
}
