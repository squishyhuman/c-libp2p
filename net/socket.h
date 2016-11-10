#ifndef SOCKET_H
   #define SOCKET_H

   int socket_tcp4(void);
   int socket_bind4(int s, uint32_t ip, uint16_t port);
   int socket_bind4_reuse(int s, uint32_t ip, uint16_t port);
   int socket_accept4(int s, uint32_t *ip, uint16_t *port);
   int socket_local4(int s, uint32_t *ip, uint16_t *port);
   int socket_connect4(int s, uint32_t ip, uint16_t port);
   int socket_listen(int s, uint32_t *localip, uint16_t *localport);
#endif
