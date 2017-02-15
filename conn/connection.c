#include <stdlib.h>

#include "libp2p/conn/connection.h"

struct Connection* libp2p_conn_connection_new(struct TransportDialer* transport_dialer, struct MultiAddress* multiaddress) {
	struct Connection* out = NULL;

	if (transport_dialer != NULL) {
		out = (struct Connection*)malloc(sizeof(struct Connection));
		if (out != NULL) {
			//TODO implement this
		}
	}
	return out;
}

void libp2p_conn_connection_free(struct Connection* connection) {
	if (connection != NULL) {
		//close(connection->socket_handle);
		free(connection);
	}
}

