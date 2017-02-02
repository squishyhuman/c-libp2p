#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "libp2p/net/multistream.h"

int test_multistream_connect() {
	int retVal = 0, socket_fd = -1;
	char* response;
	size_t response_size;

	socket_fd = libp2p_net_multistream_connect("www.jmjatlanta.com", 4001);
	if (socket_fd < 0)
		goto exit;

	// try to respond something, perhaps either the protocol id or the ls command
	//const unsigned char* out = "/multistream/1.0.0\n";
	const unsigned char* out = "ls";

	if (libp2p_net_multistream_send(socket_fd, out, strlen((char*)out)) <= 0)
		goto exit;

	// retrieve response
	retVal = libp2p_net_multistream_receive(socket_fd, &response, &response_size);
	if (retVal <= 0)
		goto exit;

	retVal = 1;

	exit:

	return retVal > 0;
}
