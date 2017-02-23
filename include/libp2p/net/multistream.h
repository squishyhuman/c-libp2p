#pragma once

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
int libp2p_net_multistream_send(int socket_fd, const unsigned char* data, size_t data_length);
/**
 * Read from a multistream socket
 * @param socket_fd the socket file descriptor
 * @param results where to put the results. NOTE: this memory is allocated
 * @param results_size the size of the results in bytes
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_net_multistream_receive(int socket_fd, char** results, size_t* results_size);

/**
 * Connect to a multistream host, and this includes the multistream handshaking.
 * @param hostname the host
 * @param port the port
 * @returns the socket file descriptor of the connection, or -1 on error
 */
int libp2p_net_multistream_connect(const char* hostname, int port);

/**
 * Negotiate the multistream protocol by sending and receiving the protocol id. This is a server side function.
 * Servers should send the protocol ID, and then expect it back.
 * @param fd the socket file descriptor
 * @returns true(1) if the negotiation was successful.
 */
int libp2p_net_multistream_negotiate(int fd);

/**
 * Expect to read a message, and follow its instructions
 * @param fd the socket file descriptor
 * @returns true(1) on success, false(0) if not
 */
int libp2p_net_multistream_handle_message(int fd);

/**
 * Connect to a multistream host, and this includes the multistream handshaking.
 * @param hostname the host
 * @param port the port
 * @returns the socket file descriptor of the connection, or -1 on error
 */
int libp2p_net_multistream_connect(const char* hostname, int port);

