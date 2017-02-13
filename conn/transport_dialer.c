#include <stdlib.h>

#include "libp2p/conn/transport_dialer.h"

struct TransportDialer* libp2p_conn_transport_dialer_new(struct MultiAddress* multiaddr) {
	struct TransportDialer* out = (struct TransportDialer*)malloc(sizeof(struct TransportDialer));
	if (out != NULL) {
		out->multiaddr = (struct MultiAddress*)malloc(sizeof(struct MultiAddress));
		if (out->multiaddr == NULL) {
			libp2p_conn_transport_dialer_free(out);
			return NULL;
		}
		if (multiaddress_copy(multiaddr, out->multiaddr) == 0) {
			libp2p_conn_transport_dialer_free(out);
			return NULL;
		}
	}
	return out;
}

/**
 * free resources from a TransportDialer struct
 * @param in the struct to be freed
 */
void libp2p_conn_transport_dialer_free(struct TransportDialer* in) {
	free(in);
}

/**
 * Given a list of dialers, find the appropriate dialer for this multiaddress
 * @param transport_dialers a list of dialers
 * @param multiaddr the address
 * @returns a connection, or NULL if no appropriate dialer was found
 */
struct Connection* libp2p_conn_transport_dialer_get(struct Libp2pLinkedList* transport_dialers, struct MultiAddress* multiaddr) {
	//TODO: implement this method
	return NULL;
}
