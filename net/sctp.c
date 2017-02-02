#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "libp2p/net/p2pnet.h"

/* Create a SCTP socket.
 */
int socket_stream_sctp4(void)
{
   int s;

   s = socket(PF_INET, SOCK_STREAM, IPPROTO_SCTP);
   if (s == -1) return -1;
   return s;
}
