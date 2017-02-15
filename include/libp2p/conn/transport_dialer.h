#pragma once

#include "multiaddr/multiaddr.h"
#include "libp2p/utils/linked_list.h"

struct TransportDialer {
	char* peer_id;
	struct PrivateKey* private_key;
	int (*can_handle)(struct MultiAddress* multiaddr);
	struct Connection* (*dial)(struct TransportDialer* transport_dialer, struct MultiAddress* multiaddr);
};

struct TransportDialer* libp2p_conn_transport_dialer_new(char* peer_id, struct PrivateKey* private_key);
void libp2p_conn_transport_dialer_free(struct TransportDialer* in);

struct Connection* libp2p_conn_transport_dialer_get(struct Libp2pLinkedList* transport_dialers, struct MultiAddress* multiaddr);
