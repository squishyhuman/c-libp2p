#include <stdlib.h>

#include "libp2p/conn/dialer.h"
#include "libp2p/net/stream.h"
#include "test_helper.h"

int test_dialer_new() {
	int retVal = 0;
	char* peer_id = "QmQSDGgxSVTkHmtT25rTzQtc5C1Yg8SpGK3BTws8YsJ4x3";
	struct PrivateKey* private_key = libp2p_crypto_private_key_new();
	struct Dialer* dialer = libp2p_conn_dialer_new(peer_id, private_key);
	if (dialer == NULL)
		goto exit;
	retVal = 1;
	exit:
	if (dialer != NULL)
		libp2p_conn_dialer_free(dialer);
	if (private_key != NULL)
		libp2p_crypto_private_key_free(private_key);
	return retVal;
}

int test_dialer_dial() {
	int retVal = 0;
	char* config_dir = "/home/parallels/.ipfs/config";
	char* destination_string = "/ip4/192.210.179.217/tcp/4001/";
	char* peer_id = NULL;
	struct PrivateKey* private_key = NULL;
	struct Dialer* dialer = NULL;
	struct MultiAddress* destination_address = NULL;
	struct Connection* conn = NULL;
	char* result = NULL;
	size_t result_size = 0;

	test_helper_get_id_from_config(config_dir, &private_key, &peer_id);
	if (private_key == NULL)
		goto exit;

	dialer = libp2p_conn_dialer_new(peer_id, private_key);
	if (dialer == NULL)
		goto exit;

	destination_address = multiaddress_new_from_string(destination_string);
	if (destination_address == NULL)
		goto exit;

	// now try to dial
	conn = libp2p_conn_dialer_get_connection(dialer, destination_address);
	if (conn == NULL)
		goto exit;

	// clean up resources
	retVal = 1;
	exit:
	if (result != NULL)
		free(result);
	free(peer_id);
	multiaddress_free(destination_address);
	libp2p_conn_dialer_free(dialer);
	libp2p_crypto_private_key_free(private_key);
	libp2p_conn_connection_free(conn);
	return retVal;
}

int test_dialer_dial_multistream() {
	int retVal = 0;
	char* config_dir = "/home/parallels/.ipfs/config";
	char* destination_string = "/ip4/192.210.179.217/tcp/4001/";
	char* peer_id = NULL;
	struct PrivateKey* private_key = NULL;
	struct Dialer* dialer = NULL;
	struct MultiAddress* destination_address = NULL;
	struct Stream* stream = NULL;
	char* result = NULL;
	size_t result_size = 0;

	test_helper_get_id_from_config(config_dir, &private_key, &peer_id);
	if (private_key == NULL)
		goto exit;

	dialer = libp2p_conn_dialer_new(peer_id, private_key);
	if (dialer == NULL)
		goto exit;

	destination_address = multiaddress_new_from_string(destination_string);
	if (destination_address == NULL)
		goto exit;

	// now try to dial
	stream = libp2p_conn_dialer_get_stream(dialer, destination_address, "multistream");
	if (stream == NULL)
		goto exit;
	int socket_descriptor = *((int*)stream->socket_descriptor);
	if ( socket_descriptor < 0 || socket_descriptor > 255) {
		goto exit;
	}

	// now ping

	// clean up resources
	retVal = 1;
	exit:
	if (result != NULL)
		free(result);
	free(peer_id);
	multiaddress_free(destination_address);
	libp2p_conn_dialer_free(dialer);
	libp2p_crypto_private_key_free(private_key);
	if (stream != NULL) {
		struct SessionContext session_context;
		session_context.insecure_stream = stream;
		stream->close(&session_context);
		libp2p_net_multistream_stream_free(stream);
	}
	return retVal;
}
