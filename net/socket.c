#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>

#include "libp2p/net/p2pnet.h"

/**
 * associate an IP address with an port to a socket.
 * @param s the socket file descriptor
 * @param ip an array of four bytes IP address in binary format
 * @returns 0 on sucess  or -1 on error setting errno apropriated.
 **/
int socket_bind4(int s, uint32_t ip, uint16_t port)
{
   struct sockaddr_in sa;

   bzero(&sa, sizeof sa);
   sa.sin_family = AF_INET;
   sa.sin_port = htons(port);
   sa.sin_addr.s_addr = ip;

   return bind(s, (struct sockaddr *) &sa, sizeof sa);
}

/**
 * Same as socket_bind4(), but set SO_REUSEADDR before
 * @param s the socket file descriptor
 * @param ip the ip address to use
 * @param port the port to use
 * @returns something...
 */
int socket_bind4_reuse(int s, uint32_t ip, uint16_t port)
{
   int opt = 1;
   setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
   setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
   return socket_bind4(s, ip, port);
}

int socket_read_select4(int socket_fd, int num_seconds) {
	fd_set rfds;
	struct timeval tv;

	FD_ZERO(&rfds);
	FD_SET(socket_fd, &rfds);

	tv.tv_sec = num_seconds;
	tv.tv_usec = 0;

	return select(socket_fd +1, &rfds, NULL, NULL, &tv);
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

/**
 * retrieve local ip and port information from a socket.
 * @param s the file descriptor
 * @param ip the IP address
 * @param port the port
 * @returns 0 on success, -1 on error
 */
int socket_local4(int s, uint32_t *ip, uint16_t *port)
{
   struct sockaddr_in sa;
   socklen_t dummy = sizeof sa;

   if (getsockname(s, (struct sockaddr *) &sa, &dummy) == -1)
	   return -1;

   *ip = sa.sin_addr.s_addr;
   *port = ntohs(sa.sin_port);

   return 0;
}

/***
 * start a client connection.
 * @param s the socket number
 * @param ip the ip address
 * @param port the port number
 * @return 0 on success, otherwise -1
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

/**
 *  bind and listen to a socket.
 *  @param s socket file descriptor
 *  @param localip the ip address
 *  @param localport the port
 *  @returns the socket file descriptor
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
ssize_t socket_read(int s, char *buf, size_t len, int flags, int num_secs)
{
	struct timeval tv;
	tv.tv_sec = num_secs;
	tv.tv_usec = 0;
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(struct timeval));

	return recv(s, buf, len, flags);
}

/* Same reason as socket_read, but to send data instead of receive.
 */
ssize_t socket_write(int s, const char *buf, size_t len, int flags)
{
   return send(s, buf, len, flags);
}

int socket_open4() {
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);

	return sockfd;
}

/**
 * Used to send the size of the next transmission for "framed" transmissions. NOTE: This will send in big endian format
 * @param s the socket descriptor
 * @param size the size to send
 * @param flags socket flags
 * @returns number of bytes sent
 */
ssize_t socket_write_size(int s, unsigned long size, int flags) {
	// determine if we're big or little endian
	int big_endian = 1;
	if (*(char*)&big_endian == 1) {
		big_endian = 0;
	}
	// convert to int32_t
	int32_t conv = htonl(size);
	// swap bytes if this machine is little endian
	if (!big_endian) {
		uint32_t b0, b1, b2, b3;
		b0 = (conv & 0x000000ff) << 24u;
		b1 = (conv & 0x0000ff00) << 8u;
		b2 = (conv & 0x00ff0000) >> 8u;
		b3 = (conv & 0xff000000) >> 24u;
		conv = b0 | b1 | b2 | b3;
	}

	// send to socket
	char* data = (char*)&conv;
	int left = sizeof(conv);
	ssize_t rc;
	int retries_left = 100;
	do {
		rc = send(s, data, left, flags);
		if (rc < 0) {
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
				retries_left--;
				if (retries_left <= 0)
					break;
			} else {
				return -1;
			}
		} else {
			data += rc;
			left -= rc;
		}
	} while (left > 0);
	return sizeof(conv) - left;
	//return send(s, size, 4, flags);
}


/**
 * convert a hostname into an ip address
 * @param hostname the name of the host. i.e. www.jmjatlanta.com
 * @returns the ip address as an uint32_t
 */
uint32_t hostname_to_ip(const char* hostname)
{
	struct sockaddr_in sa;
	int result = inet_pton(AF_INET, hostname, &(sa.sin_addr));
	if (result != 0) {
		// an ip address was passed in instead of a hostname
		return sa.sin_addr.s_addr;
	} else {
		// it is probably an actual host name and not just an ip address
		struct hostent *he;
		struct in_addr **addr_list;

		if ( (he = gethostbyname( hostname ) ) == NULL)
		{
			// get the host info
			herror("gethostbyname");
			return 1;
		}

		addr_list = (struct in_addr **) he->h_addr_list;
		if ((*addr_list) == NULL)
			return 0;

		return addr_list[0]->s_addr;
	}
}
