#include <stdlib.h>
#include <string.h>

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

/***
 * Parse the incoming data, removing the size indicator at the front of the array
 * @param incoming the incoming data
 * @param incoming_size the size of the incoming data
 * @param outgoing the buffer to hold the outgoing data, allocated within this function
 * @param outgoing_size the outgoing size
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_net_multistream_parse_results(char* incoming, size_t incoming_size, char** outgoing, size_t* outgoing_size) {
	int retVal = 0;
	if (incoming_size > 0) {
		// TODO: handle this differently
		// read the varint
		// allocate memory
		*outgoing = (char*)malloc(incoming_size - 1);
		if (*outgoing == NULL)
			return 0;
		// copy in the data
		memcpy(*outgoing, &incoming[1], incoming_size - 1);
		*outgoing_size = incoming_size - 1;
		retVal = 1;
	}
	return retVal;
}

/**
 * Read from a multistream socket
 * @param socket_fd the socket file descriptor
 * @param results where to put the results. NOTE: this memory is allocated
 * @param results_size the size of the results in bytes
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_net_multistream_receive(int socket_fd, char** results, size_t* results_size) {
	int bytes = 0;
	size_t buffer_size = 65535;
	char buffer[buffer_size];

	bytes = socket_read(socket_fd, buffer, buffer_size, 0);
	if (bytes == 0)
		return 0;

	// parse the results, removing the leading size indicator
	return libp2p_net_multistream_parse_results(buffer, bytes, results, results_size);
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

