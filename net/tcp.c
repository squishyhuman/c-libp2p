#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "libp2p/net/p2pnet.h"

/**
 * Methods for tcp sockets
 */

/**
 * Create a TCP socket.
 * @returns the socket descriptor returned by socket()
 */
int socket_tcp4(void)
{
   int s;
   s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
   return s;
}
