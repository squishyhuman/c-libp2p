#ifndef P2PNET_H
   #define P2PNET_H

   int socket_bind4(int s, uint32_t ip, uint16_t port);
   int socket_bind4_reuse(int s, uint32_t ip, uint16_t port);
   int socket_accept4(int s, uint32_t *ip, uint16_t *port);
   int socket_local4(int s, uint32_t *ip, uint16_t *port);
   int socket_connect4(int s, uint32_t ip, uint16_t port);
   int socket_listen(int s, uint32_t *localip, uint16_t *localport);
   ssize_t socket_read(int s, char *buf, size_t len, int flags);
   ssize_t socket_write(int s, char *buf, size_t len, int flags);

   int socket_tcp4(void);

   int socket_stream_sctp4(void);
#endif // P2PNET_H
