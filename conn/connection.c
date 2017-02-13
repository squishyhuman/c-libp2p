#include <stdlib.h>

#include "libp2p/conn/connection.h"

struct Connection* libp2p_conn_connection_open(struct TransportDialer* transport_dialer, struct maddr* multiaddress) {
	struct Connection* out = NULL;

	if (transport_dialer != NULL) {
		out = (struct Connection*)malloc(sizeof(struct Connection));
		if (out != NULL) {
			//TODO implement this
		}
	}
	return out;
}
