#pragma once

#include "libp2p/net/stream.h"

int libp2p_nodeio_upgrade_stream(struct Stream* stream);
struct Node* libp2p_nodeio_get(struct Stream* stream, unsigned char* hash, int hash_length);
