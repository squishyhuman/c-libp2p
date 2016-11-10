#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "p2pnet.h"

/* associate an IP address with an port to a socket.
 * first param is the socket file description
 * second is an array of four bytes IP address
 * in binary format, this function return 0 on sucess
 * or -1 on error setting errno apropriated.
 */
int socket_bind4(int s, uint32_t ip, uint16_t port)
{
   struct sockaddr_in sa;

   bzero(&sa, sizeof sa);
   sa.sin_family = AF_INET;
   sa.sin_port = htons(port);
   sa.sin_addr.s_addr = ip;

   return bind(s, (struct sockaddr *) &sa, sizeof sa);
}

/* Same as socket_bind4(), but set SO_REUSEADDR before
 */
int socket_bind4_reuse(int s, uint32_t ip, uint16_t port)
{
   int opt = 1;
   setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
   return socket_bind4(s, ip, port);
}

/* Accept a connection in a socket and return ip and port of
 * remote connection at pointers passed as parameters.
 */
int socket_accept4(int s, uint32_t *ip, uint16_t *port)
{
   struct sockaddr_in sa;
   socklen_t dummy = sizeof sa;
   int fd;

   fd = accept(s, (struct sockaddr *) &sa, &dummy);
   if (fd == -1) return -1;

   *ip = sa.sin_addr.s_addr;
   *port = ntohs(sa.sin_port);

   return fd;
}

/* retrieve local ip and port information from a socket.
 */
int socket_local4(int s, uint32_t *ip, uint16_t *port)
{
   struct sockaddr_in sa;
   socklen_t dummy = sizeof sa;

   if (getsockname(s, (struct sockaddr *) &sa, &dummy) == -1) return -1;
   *ip = sa.sin_addr.s_addr;
   *port = ntohs(sa.sin_port);
   return 0;
}

/* start a client connection.
 */
int socket_connect4(int s, uint32_t ip, uint16_t port)
{
   struct sockaddr_in sa;

   memset(&sa, 0, sizeof sa);
   sa.sin_family = AF_INET;
   sa.sin_port = htons(port);
   sa.sin_addr.s_addr = ip;

   return connect(s, (struct sockaddr *) &sa, sizeof sa);
}

/* bind and listen to a socket.
 */
int socket_listen(int s, uint32_t *localip, uint16_t *localport)
{
   if (socket_bind4_reuse(s, *localip, *localport) == -1) {
      close(s);
      return -1;
   }
   if (socket_local4(s, localip, localport) == -1) {
      close(s);
      return -1;
   }
   if (listen(s, 1) == -1) {
      close(s);
      return -1;
   }
   return s;
}

/* Reads data from a socket, used instead of recv so if a protocol needs
 * to use something else before or after it can be done here instead of
 * outside the lib.
 */
ssize_t socket_read(int s, char *buf, size_t len, int flags)
{
   return recv(s, buf, len, flags);
}

/* Same reason as socket_read, but to send data instead of receive.
 */
ssize_t socket_write(int s, char *buf, size_t len, int flags)
{
   return send(s, buf, len, flags);
}
