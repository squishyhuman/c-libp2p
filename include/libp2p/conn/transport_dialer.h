#pragma once

#include "multiaddr/multiaddr.h"
#include "libp2p/utils/linked_list.h"

struct TransportDialer {
	struct MultiAddress* multiaddr;
};

struct TransportDialer* libp2p_conn_transport_dialer_new(struct MultiAddress* multiaddr);
void libp2p_conn_transport_dialer_free(struct TransportDialer* in);

struct Connection* libp2p_conn_transport_dialer_get(struct Libp2pLinkedList* transport_dialers, struct MultiAddress* multiaddr);
