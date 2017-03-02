/***
 * A local dialer. Uses MultiAddr to figure out the best way to
 * connect to a client, then returns an open Connection that can be
 * closed, read from and written to. The normal procedure is as follows:
 * 1) Create a Dialer struct, with the required information about the local host
 * 2) Call _get_connection to create the connection with a specific host
 * NOTE: 1 Dialer could be used to create all connections, saving time and resources
 * if it is not too difficult to pass it around. The struct has enough information to
 * build connections that negotiate many protocols
 */

#include "libp2p/crypto/key.h"
#include "multiaddr/multiaddr.h"
#include "libp2p/conn/connection.h"
#include "libp2p/conn/transport_dialer.h"

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
 * NOTE: This fills in the fallback_dialer too
 * @param peer_id the local PeerID
 * @param private_key the local private key
 * @returns a new Dialer struct
 */
struct Dialer* libp2p_conn_dialer_new(char* peer_id, struct PrivateKey* private_key);

/**
 * free resources from the Dialer struct
 * @param in the Dialer struct to relieve of their resources
 */
void libp2p_conn_dialer_free(struct Dialer* in);

/**
 * Retrieve a Connection struct from the dialer
 * @param dialer the dialer to use
 * @param muiltiaddress who to connect to
 * @returns a Connection, or NULL
 */
struct Connection* libp2p_conn_dialer_get_connection(const struct Dialer* dialer, const struct MultiAddress* multiaddress);

/**
 * return a Stream that is already set up to use the passed in protocol
 * @param dialer the dialer to use
 * @param multiaddress the host to dial
 * @param protocol the protocol to use (right now only 'multistream' is supported)
 * @returns the ready-to-use stream
 */
struct Stream* libp2p_conn_dialer_get_stream(const struct Dialer* dialer, const struct MultiAddress* multiaddress, const char* protocol);

