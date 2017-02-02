#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "libp2p/net/p2pnet.h"

/* Create a UDP socket.
 */
int socket_udp4(void)
{
   int s;

   s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

   if (s == -1) return -1;
   return s;
}
