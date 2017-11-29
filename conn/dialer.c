#include <stdlib.h>
/**
 * Functions for handling the local dialer
 */

#include "libp2p/crypto/encoding/x509.h"
#include "libp2p/conn/dialer.h"
#include "libp2p/conn/connection.h"
#include "libp2p/conn/transport_dialer.h"
#include "libp2p/crypto/key.h"
#include "libp2p/utils/linked_list.h"
#include "libp2p/utils/logger.h"
#include "multiaddr/multiaddr.h"
#include "libp2p/net/multistream.h"
#include "libp2p/secio/secio.h"
#include "libp2p/yamux/yamux.h"
#include "libp2p/identify/identify.h"

struct TransportDialer* libp2p_conn_tcp_transport_dialer_new();

/**
 * Create a Dialer with the specified local information
 * @param peer the local peer
 * @param peerstore the local peerstore
 * @param private_key the local private key
 * @returns a new Dialer struct
 */
struct Dialer* libp2p_conn_dialer_new(struct Libp2pPeer* peer, struct Peerstore* peerstore, struct RsaPrivateKey* rsa_private_key, struct SwarmContext* swarm) {
	int success = 0;
	struct Dialer* dialer = (struct Dialer*)malloc(sizeof(struct Dialer));
	if (dialer != NULL) {
		dialer->peerstore = peerstore;
		dialer->private_key = rsa_private_key;
		dialer->transport_dialers = NULL;
		dialer->fallback_dialer = libp2p_conn_tcp_transport_dialer_new(dialer->peer_id, rsa_private_key);
		dialer->swarm = swarm;
		if (peer != NULL) {
			dialer->peer_id = malloc(peer->id_size + 1);
			memset(dialer->peer_id, 0, peer->id_size + 1);
			if (dialer->peer_id != NULL) {
				strncpy(dialer->peer_id, peer->id, peer->id_size);
			}
		}
		return dialer;
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
		if (in->peer_id != NULL)
			free(in->peer_id);
		libp2p_crypto_rsa_rsa_private_key_free(in->private_key);
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
 * @returns a stream that is a ConnectionStream, or NULL
 */
struct Stream* libp2p_conn_dialer_get_connection(const struct Dialer* dialer, const struct MultiAddress* multiaddress) {
	struct Stream* conn = libp2p_conn_transport_dialer_get(dialer->transport_dialers, multiaddress);
	if (conn == NULL) {
		conn = dialer->fallback_dialer->dial(dialer->fallback_dialer, multiaddress);
	}
	return conn;
}

/***
 * Attempt to connect to a particular peer. This will negotiate several protocols
 * @param dialer the dialer
 * @param peer the peer to join
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_conn_dialer_join_swarm(const struct Dialer* dialer, struct Libp2pPeer* peer, int timeout_secs) {
	if (dialer == NULL || peer == NULL)
		return 0;
	// find the right Multiaddress
	struct Libp2pLinkedList* current_entry = peer->addr_head;
	struct Stream* conn_stream = NULL;
	while (current_entry != NULL) {
		struct MultiAddress* ma = current_entry->item;
		conn_stream = libp2p_conn_dialer_get_connection(dialer, ma);
		if (conn_stream != NULL) {
			if (peer->sessionContext == NULL) {
				peer->sessionContext = libp2p_session_context_new();
				struct ConnectionContext* conn_ctx = conn_stream->stream_context;
				conn_ctx->session_context = peer->sessionContext;
			}
			peer->sessionContext->insecure_stream = conn_stream;
			peer->sessionContext->default_stream = conn_stream;
			peer->sessionContext->port = multiaddress_get_ip_port(ma);
			multiaddress_get_ip_address(ma, &peer->sessionContext->host);
			break;
		}
		current_entry = current_entry->next;
	}
	if (conn_stream == NULL)
		return 0;
	// we're connected. start listening for responses
	libp2p_swarm_add_peer(dialer->swarm, peer);
	// wait for multistream
	int counter = 0;
	if (!libp2p_net_multistream_ready(peer->sessionContext, 5)) {
		return 0;
	}
	struct Stream* new_stream = peer->sessionContext->default_stream;
	if (new_stream != NULL) {
		// secio over multistream
		new_stream = libp2p_secio_stream_new(new_stream, dialer->peerstore, dialer->private_key);
		counter = 0;
		if (!libp2p_secio_ready(peer->sessionContext, 10) ) {
			return 0;
		}
		counter = 0;
		if (new_stream != NULL) {
			peer->sessionContext->default_stream = new_stream;
			// multistream over secio
			new_stream = libp2p_net_multistream_stream_new(new_stream, 0);
			if (new_stream != NULL) {
				peer->sessionContext->default_stream = new_stream;
				// yamux over multistream
				new_stream = libp2p_yamux_stream_new(new_stream, 0, NULL);
				if (new_stream != NULL) {
					peer->sessionContext->default_stream = new_stream;
					// we have our swarm connection. Now we ask for some "channels"
					// id over yamux
					//libp2p_yamux_stream_add(new_stream->stream_context, libp2p_identify_stream_new(new_stream));
					// kademlia over yamux
					//libp2p_yamux_stream_add(new_stream->stream_context, libp2p_kademlia_stream_new(new_stream));
					// circuit relay over yamux
					//libp2p_yamux_stream_add(new_stream->stream_context, libp2p_circuit_relay_stream_new(new_stream));
					return 1;
				} else {
					libp2p_logger_error("dialer", "Unable to do yamux negotiation.\n");
				}
			} else {
				libp2p_logger_error("dialer", "Unable to do secio/multistream negotiation.\n");
			}
		} else {
			libp2p_logger_error("dialer", "Unable to do secio negotiation.\n");
		}
	} else {
		libp2p_logger_error("dialer", "Unable to do initial multistream negotiation.\n");
	}

	return 0;
}

/**
 * return a Stream that is already set up to use the passed in protocol
 * @param dialer the dialer to use
 * @param multiaddress the host to dial
 * @param protocol the protocol to use (right now only 'multistream' is supported)
 * @returns the ready-to-use stream
 */
struct Stream* libp2p_conn_dialer_get_stream(const struct Dialer* dialer, const struct Libp2pPeer* peer, const char* protocol) {
	// TODO: Implement this method
	return NULL;
}
