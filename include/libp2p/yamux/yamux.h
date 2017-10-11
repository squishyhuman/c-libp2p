#pragma once

#include "libp2p/net/protocol.h"

/**
 * Build a handler that can handle the yamux protocol
 */
struct Libp2pProtocolHandler* yamux_build_protocol_handler();
