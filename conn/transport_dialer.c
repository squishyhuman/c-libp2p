#include <stdlib.h>

#include "libp2p/conn/transport_dialer.h"

struct TransportDialer* libp2p_conn_transport_dialer_new(struct maddr* multiaddr) {
	struct TransportDialer* out = (struct TransportDialer*)malloc(sizeof(struct TransportDialer));
	if (out != NULL) {
		out->multiaddr = (struct maddr*)malloc(sizeof(struct maddr));
		if (out->multiaddr == NULL) {
			free(out);
			return NULL;
		}
		out->multiaddr->bsize[0] = multiaddr->bsize[0];
		memcpy(out->multiaddr->bytes, multiaddr->bytes, 400);
		memcpy(out->multiaddr->string, multiaddr->string, 800);
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
struct Connection* libp2p_conn_transport_dialer_get(struct Libp2pLinkedList* transport_dialers, struct maddr* multiaddr) {
	//TODO: implement this method
	return NULL;
}
