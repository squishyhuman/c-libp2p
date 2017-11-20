/**
 * Header for libp2p/net/server
 */

/***
 * Start a server given the information
 * NOTE: This spins off a thread.
 * @param ip the ip address to attach to
 * @param port the port to use
 * @param protocol_handlers the protocol handlers
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_net_server_start(const char* ip, int port, struct Libp2pVector* protocol_handlers);

/***
 * Shut down the server started by libp2p_net_start_server
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_net_server_stop();
