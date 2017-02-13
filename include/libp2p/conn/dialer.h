/***
 * A local dialer. Uses MultiAddr to figure out the best way to
 * connect to a client.
 */

#include "libp2p/crypto/key.h"

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
	struct TransportDialer* transport_dialers;

	//TODO: See dial.go, need to implement Protector

	struct TransportDialer* fallback_dialer; // the default dialer
};
