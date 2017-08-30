#pragma once

#include <stdint.h>
#include <unistd.h>

int socket_open4();
int socket_bind4(int s, uint32_t ip, uint16_t port);
int socket_bind4_reuse(int s, uint32_t ip, uint16_t port);
int socket_read_select4(int socket_fd, int num_seconds);
int socket_accept4(int s, uint32_t *ip, uint16_t *port);
int socket_local4(int s, uint32_t *ip, uint16_t *port);
int socket_connect4(int s, uint32_t ip, uint16_t port);
int socket_connect4_with_timeout(int s, uint32_t ip, uint16_t port, int timeout_secs);
int socket_listen(int s, uint32_t *localip, uint16_t *localport);

/***
 * Reads data from a socket, used instead of recv so if a protocol needs
 * to use something else before or after it can be done here instead of
 * outside the lib.
 *
 * @param s the socket
 * @param buf what to send
 * @param len the length of buf
 * @param flags network flags
 * @param num_secs the number of seconds before a timeout
 * @returns number of bytes, 0, or negative number on error (i.e. EAGAIN or EWOULDBLOCK)
*/
ssize_t socket_read(int s, char *buf, size_t len, int flags, int timeout_secs);
ssize_t socket_write(int s, const char *buf, size_t len, int flags);
/**
 * Used to send the size of the next transmission for "framed" transmissions. NOTE: This will send in big endian format
 * @param s the socket descriptor
 * @param size the size to send
 * @param flags socket flags
 * @returns number of bytes sent
 */
ssize_t socket_write_size(int s, unsigned long size, int flags);

int socket_tcp4(void);

int socket_stream_sctp4(void);

int socket_udp4(void);

/**
 * convert a hostname into an ip address
 * @param hostname the name of the host. i.e. www.jmjatlanta.com
 * @returns the ip address as an uint32_t
*/
uint32_t hostname_to_ip(const char* hostname);
