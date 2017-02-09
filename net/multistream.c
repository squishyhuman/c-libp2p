#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "libp2p/net/p2pnet.h"
#include "varint.h"

/***
 * An implementation of the libp2p multistream
 */

/**
 * Write to an open multistream host
 * @param socket_fd the socket file descriptor
 * @param data the data to send
 * @param data_length the length of the data
 * @returns the number of bytes written
 */
int libp2p_net_multistream_send(int socket_fd, const unsigned char* data, size_t data_length) {
	int num_bytes = 0;

	if (data_length > 0) { // only do this is if there is something to send
		// first send the size
		unsigned char varint[12];
		size_t varint_size = 0;
		varint_encode(data_length, &varint[0], 12, &varint_size);
		num_bytes = socket_write(socket_fd, (char*)varint, varint_size, 0);
		if (num_bytes == 0)
			return 0;
		// then send the actual data
		num_bytes += socket_write(socket_fd, (char*)data, data_length, 0);
	}

	return num_bytes;
}

/**
 * Read from a multistream socket
 * @param socket_fd the socket file descriptor
 * @param results where to put the results. NOTE: this memory is allocated
 * @param results_size the size of the results in bytes
 * @returns number of bytes received
 */
int libp2p_net_multistream_receive(int socket_fd, char** results, size_t* results_size) {
	int bytes = 0;
	size_t buffer_size = 65535;
	char buffer[buffer_size];
	char* pos = buffer;
	size_t num_bytes_requested = 0, left = 0, already_read = 0;

	// first read the varint
	while(1) {
		unsigned char c;
		bytes = socket_read(socket_fd, (char*)&c, 1, 0);
		pos[0] = c;
		if (c >> 7 == 0) {
			pos[1] = 0;
			num_bytes_requested = varint_decode((unsigned char*)buffer, strlen(buffer), NULL);
			break;
		}
		pos++;
	}
	if (num_bytes_requested <= 0)
		return 0;

	left = num_bytes_requested;
	do {
		bytes = socket_read(socket_fd, &buffer[already_read], left, 0);
		if (bytes < 0) {
			bytes = 0;
			if ( (errno == EAGAIN) || (errno == EWOULDBLOCK)) {
				// do something intelligent
			} else {
				return 0;
			}
		}
		left = left - bytes;
		already_read += bytes;
	} while (left > 0);

	if (already_read != num_bytes_requested)
		return 0;

	// parse the results, removing the leading size indicator
	*results = malloc(num_bytes_requested);
	if (*results == NULL)
		return 0;
	memcpy(*results, buffer, num_bytes_requested);
	*results_size = num_bytes_requested;
	return num_bytes_requested;
}


/**
 * Connect to a multistream host, and this includes the multistream handshaking.
 * @param hostname the host
 * @param port the port
 * @returns the socket file descriptor of the connection, or -1 on error
 */
int libp2p_net_multistream_connect(const char* hostname, int port) {
	int retVal = -1, return_result = -1, socket = -1;
	char* results = NULL;
	size_t results_size;
	size_t num_bytes = 0;

	uint32_t ip = hostname_to_ip(hostname);
	socket = socket_open4();

	// connect
	if (socket_connect4(socket, ip, port) != 0)
		goto exit;

	// send the multistream handshake
	char* protocol_buffer = "/multistream/1.0.0\n";

	num_bytes = libp2p_net_multistream_send(socket, (unsigned char*)protocol_buffer, strlen(protocol_buffer));
	if (num_bytes <= 0)
		goto exit;

	// try to receive the protocol id
	return_result = libp2p_net_multistream_receive(socket, &results, &results_size);
	if (return_result == 0 || results_size < 1)
		goto exit;

	if (strstr(results, "multistream") == NULL)
		goto exit;

	// we are now in the loop, so we can switch to another protocol (i.e. /secio/1.0.0)

	retVal = socket;
	exit:
	if (results != NULL)
		free(results);
	return retVal;
}

