#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "libp2p/net/p2pnet.h"

/* Create a TCP socket.
 */
int socket_tcp4(void)
{
   int s;

   s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
   if (s == -1) return -1;
   return s;
}
