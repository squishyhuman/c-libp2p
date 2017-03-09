#include <stdlib.h>
/**
 * Functions for handling the local dialer
 */

#include "libp2p/conn/dialer.h"
#include "libp2p/conn/connection.h"
#include "libp2p/conn/transport_dialer.h"
#include "libp2p/crypto/key.h"
#include "libp2p/utils/linked_list.h"
#include "multiaddr/multiaddr.h"
#include "libp2p/net/multistream.h"

struct TransportDialer* libp2p_conn_tcp_transport_dialer_new();

/**
 * Create a Dialer with the specified local information
 */
struct Dialer* libp2p_conn_dialer_new(char* peer_id, struct PrivateKey* private_key) {
	int success = 0;
	struct Dialer* dialer = (struct Dialer*)malloc(sizeof(struct Dialer));
	if (dialer != NULL) {
		dialer->peer_id = malloc(strlen(peer_id) + 1);
		if (dialer->peer_id != NULL) {
			strcpy(dialer->peer_id, peer_id);
			dialer->private_key = (struct PrivateKey*)malloc(sizeof(struct PrivateKey));
			if (dialer->private_key != NULL) {
				libp2p_crypto_private_key_copy(private_key, dialer->private_key);
				//TODO: build transport dialers
				dialer->transport_dialers = NULL;
				dialer->fallback_dialer = libp2p_conn_tcp_transport_dialer_new(peer_id, private_key);
				return dialer;
			}
		}
	}
	libp2p_conn_dialer_free(dialer);
	return NULL;
}

/**
 * Free resources from the Dialer
 * NOTE: this frees the fallback dialer too (should we be doing this?
 * @param in the Dialer struct to free
 */
void libp2p_conn_dialer_free(struct Dialer* in) {
	if (in != NULL) {
		free(in->peer_id);
		libp2p_crypto_private_key_free(in->private_key);
		if (in->transport_dialers != NULL) {
			struct Libp2pLinkedList* current = in->transport_dialers;
			while(current != NULL) {
				libp2p_conn_transport_dialer_free((struct TransportDialer*)current->item);
				current = current->next;
			}
		}
		if (in->fallback_dialer != NULL)
			libp2p_conn_transport_dialer_free((struct TransportDialer*)in->fallback_dialer);
		free(in);
	}
	return;
}

/**
 * Retrieve a Connection struct from the dialer
 * NOTE: This should no longer be used. _get_stream should
 * be used instead (which calls this method internally).
 * @param dialer the dialer to use
 * @param muiltiaddress who to connect to
 * @returns a Connection, or NULL
 */
struct Connection* libp2p_conn_dialer_get_connection(const struct Dialer* dialer, const struct MultiAddress* multiaddress) {
	struct Connection* conn = libp2p_conn_transport_dialer_get(dialer->transport_dialers, multiaddress);
	if (conn == NULL) {
		conn = dialer->fallback_dialer->dial(dialer->fallback_dialer, multiaddress);
	}
	return conn;
}

/**
 * return a Stream that is already set up to use the passed in protocol
 * @param dialer the dialer to use
 * @param multiaddress the host to dial
 * @param protocol the protocol to use (right now only 'multistream' is supported)
 * @returns the ready-to-use stream
 */
struct Stream* libp2p_conn_dialer_get_stream(const struct Dialer* dialer, const struct MultiAddress* multiaddress, const char* protocol) {
	// this is a shortcut for now. Other protocols will soon be implemented
	if (strcmp(protocol, "multistream") != 0)
		return NULL;
	char* ip;
	int port = multiaddress_get_ip_port(multiaddress);
	if (!multiaddress_get_ip_address(multiaddress, &ip)) {
		free(ip);
		return NULL;
	}
	struct Stream* stream = libp2p_net_multistream_connect(ip, port);
	free(ip);
	return stream;
}
