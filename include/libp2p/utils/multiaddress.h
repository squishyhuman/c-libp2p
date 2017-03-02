#pragma once
#include "multiaddr/multiaddr.h"

/**
 * This is a hack to get ip4/tcp working
 * TODO: this should be moved further down in the networking stack and generified for different multiaddresses
 * This makes too many assumptions
 * @param address the multiaddress to parse
 * @param ip the first IP address in the multiaddress
 * @param port the first port in the multiaddress
 * @returns true(1) on success, false(0) on failure
 */
int libp2p_utils_multiaddress_parse_ip4_tcp(const struct MultiAddress* address, char** ip, int* port);
