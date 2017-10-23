#pragma once

#include "libp2p/net/stream.h"

/***
 * Create a new stream based on a network connection
 * @param fd the handle to the network connection
 * @param ip the IP address of the connection
 * @param port the port of the connection
 * @returns a Stream
 */
struct Stream* libp2p_net_connection_new(int fd, char* ip, int port);
