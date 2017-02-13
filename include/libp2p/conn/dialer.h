/***
 * A local dialer. Uses MultiAddr to figure out the best way to
 * connect to a client, then returns an open Connection that can be
 * closed, read from and written to.
 */

#include "libp2p/crypto/key.h"
#include "multiaddr/multiaddr.h"

struct Dialer {
	/**
	 * These two are used to create connections
	 */
	char* peer_id; // the local peer ID as null terminated string
	struct PrivateKey* private_key; // used to initiate secure connections, can be NULL, and connections will not be secured

	/**
	 * A linked list of transport dialers. A transport dialer can be selected
	 * based on the MultiAddr being dialed. Most common: TCP and UDP
	 */
	struct Libp2pLinkedList* transport_dialers;

	//TODO: See dial.go, need to implement Protector

	struct TransportDialer* fallback_dialer; // the default dialer. NOTE: this should not be in the list of transport_dialers
};

/**
 * Create a Dialer with the specified local information
 */
struct Dialer* libp2p_conn_dialer_new(char* peer_id, struct PrivateKey* private_key);

/**
 * free resources from the Dialer
 */
void libp2p_conn_dialer_free(struct Dialer* in);

/**
 * Retrieve a Connection struct from the dialer
 * @param dialer the dialer to use
 * @param muiltiaddress who to connect to
 * @returns a Connection, or NULL
 */
struct Connection* libp2p_conn_dialer_get_connection(struct Dialer* dialer, struct maddr* multiaddress);
