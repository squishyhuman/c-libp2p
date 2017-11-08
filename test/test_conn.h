#include <stdlib.h>

#include "libp2p/conn/dialer.h"
#include "libp2p/net/stream.h"
#include "test_helper.h"

int test_dialer_new() {
	int retVal = 0;
	char* peer_id = "QmQSDGgxSVTkHmtT25rTzQtc5C1Yg8SpGK3BTws8YsJ4x3";
	struct RsaPrivateKey* private_key = NULL;
	struct Libp2pPeer* peer = libp2p_peer_new();
	peer->id = malloc(strlen(peer_id)+1);
	strcpy(peer->id, peer_id);
	peer->id_size = strlen(peer_id);
	struct Dialer* dialer = libp2p_conn_dialer_new(peer, NULL, private_key);
	if (dialer == NULL)
		goto exit;
	retVal = 1;
	exit:
	libp2p_peer_free(peer);
	libp2p_conn_dialer_free(dialer);
	return retVal;
}

int test_dialer_dial() {
	int retVal = 0;
	char* config_dir = "/home/parallels/.ipfs/config";
	char* destination_string = "/ip4/192.210.179.217/tcp/4001/";
	struct Dialer* dialer = NULL;
	struct MultiAddress* destination_address = NULL;
	struct Stream* stream = NULL;
	char* result = NULL;
	size_t result_size = 0;
	struct Libp2pPeer* peer = libp2p_peer_new();

	test_helper_get_id_from_config(config_dir, NULL, &peer->id);
	if (peer->id == NULL)
		goto exit;
	peer->id_size = strlen((char*)peer->id);

	dialer = libp2p_conn_dialer_new(peer, NULL, NULL);
	if (dialer == NULL)
		goto exit;

	destination_address = multiaddress_new_from_string(destination_string);
	if (destination_address == NULL)
		goto exit;

	// now try to dial
	stream = libp2p_conn_dialer_get_connection(dialer, destination_address);
	if (stream == NULL)
		goto exit;

	// clean up resources
	retVal = 1;
	exit:
	if (result != NULL)
		free(result);
	libp2p_peer_free(peer);
	multiaddress_free(destination_address);
	libp2p_conn_dialer_free(dialer);
	stream->close(stream->stream_context);
	libp2p_stream_free(stream);
	return retVal;
}

int test_dialer_join_swarm() {
	int retVal = 0;

	libp2p_logger_add_class("secio");
	libp2p_logger_add_class("multistream");
	// we need a dialer and a peer
	struct Dialer* dialer = NULL;
	// this is a base64 encoded private key. It makes it easier to test if it is in base64 form
	// these were pulled from the GO version of ipfs
	char* orig_priv_key = "CAASqQkwggSlAgEAAoIBAQCuW+8vGUb2n4xOcfPZLmfVAy6GNJ0sYrD/hVXwxBU1aBas+8lfAuLwYJXPCVBg65wZWYEbbWCevLFjwB/oZyJA1J1g+HohggH8QvuDH164FtSbgyHFip2SPR7oUHgSWRqfKXRJsVW/SPCfEt59S8JH99Q747dU9fvZKpelE9aDLf5yI8nj29TDy3c1RpkxfUwfgnbeoCwsDnakFmVdoSEp3Lnt3JlI05qE0bgvkWAaelcXSNQCmZzDwXeMk9y221FnBkL4Vs3v2lKmjLx+Qr37P/t78T+VxsjnGHPhbZTIMIjwwON6568d0j25Bj9v6biiz8iXzBR4Fmz1CQ0mqU5BAgMBAAECggEAc6EYX/29Z/SrEaLUeiUiSsuPYQUnbrYMd4gvVDpVblOXJiTciJvbcFo9P04H9h6KKO2Ih23j86FjaqmQ/4jV2HSn4hUmuW4EbwzkyzJUmHTbjj5KeTzR/pd2Fc63skNROlg9fFmUagSvPm8/CYziTOP35bfAbyGqYXyzkJA1ZExVVSOi1zGVi+lnlI1fU2Aki5F7W7F/d2AQWsh7NXUwT7e6JP7TL+Gn4bWdn3NvluwAWTMgp6/It8OU1XPgu8OhdpZQWsMBqJwr79KGLbq2SZZXAw8O+ay1JQYmmmvYzwhdDgJwl+MOtf3NiqQWFzZP8RnlHGNcXlLHHPW0FB9H+QKBgQDirtBOqjCtND6m4hEfy6A24GcITYUBg1+AYQ7uM5uZl5u9AyxfG4bPxyrspz3yS0DOV4HNQ88iwmUE8+8ZHCLSY/YIp73Nk4m8t2s46CuI7Y5GrwCnh9xTMwaUrNx4IRTWyR3OxjQtUyrXtPR6uJ83FDenXvNi//Mrzp+myxX4wwKBgQDE6L8qiVA6n9k5dyUxxMUKJqynwPcBeC+wI85gr/9wwlRYDrgMYeH6/D5prZ3N5m8+zugVQQJKLfXBG0i8BRh5xLYFCZnV2O3NwvCdENlZJZrNNoz9jM3yRV+c7OdrclxDiN0bjGEBWv8GHutNFAwuUfMe0TMdfFYpM7gBHjEMqwKBgQCWHwOhNSCrdDARwSFqFyZxcUeKvhvZlrFGigCjS9Y+b6MaF+Ho0ogDTnlk5JUnwyKWBGnYEJI7CNZx40JzNKjzAHRN4xjV7mGHc0k1FLzQH9LbiMY8LMOC7gXrrFcNz4rHe8WbzLN9WNjEpfhK1b3Lcj4xP7ab17mpR1t/0HsqlQKBgQC3S6lYIUZLrCz7b0tyTqbU0jd6WQgVmBlcL5iXLH3uKxd0eQ8eh6diiZhXq0PwPQdlQhmMX12QS8QupAVK8Ltd7p05hzxqcmq7VTHCI8MPVxAI4zTPeVjko2tjmqu5u1TjkO2yDTTnnBs1SWbj8zt7itFz6G1ajzltVTV95OrnzQKBgQDEwZxnJA2vDJEDaJ82CiMiUAFzwsoK8hDvz63kOKeEW3/yESySnUbzpxDEjzYNsK74VaXHKCGI40fDRUqZxU/+qCrFf3xDfYS4r4wfFd2Jh+tn4NzSV/EhIr9KR/ZJW+TvGks+pWUJ3mhjPEvNtlt3M64/j2D0RP2aBQtoSpeezQ==";
	char* orig_peer_id = "QmRKm1d9kSCRpMFtLYpfhhCQ3DKuSSPJa3qn9wWXfwnWnY";
	char* remote_peer_id = "QmRjLCELimPe7aUdYRVNLD7UmB1CiJdJf8HLovKAB4KwmA";
	size_t orig_peer_id_size = strlen(orig_peer_id);
	struct RsaPrivateKey* rsa_private_key = NULL;
	struct PrivateKey* priv = NULL;
	size_t decode_base64_size = 0;
	uint8_t* decode_base64 = NULL;
	struct Libp2pPeer* local_peer = NULL;
	struct Peerstore* peerstore = NULL;
	// we need connection information to an existing ipfs instance
	char* remote_swarm = "/ip4/10.211.55.2/tcp/4001";
	struct Libp2pPeer* remote_peer = NULL;
	struct MultiAddress* remote_ma = NULL;

	// 1) take the private key and turn it back into bytes (decode base 64)
	decode_base64_size = libp2p_crypto_encoding_base64_decode_size(strlen(orig_priv_key));
	decode_base64 = (unsigned char*)malloc(decode_base64_size);
	memset(decode_base64, 0, decode_base64_size);

	if (!libp2p_crypto_encoding_base64_decode((unsigned char*)orig_priv_key, strlen(orig_priv_key), &decode_base64[0], decode_base64_size, &decode_base64_size))
		goto exit;

	if (!libp2p_crypto_private_key_protobuf_decode(decode_base64, decode_base64_size, &priv))
		goto exit;

	rsa_private_key = libp2p_crypto_private_key_to_rsa(priv);

	// 2) make the local peer
	local_peer = libp2p_peer_new();
	local_peer->id = orig_peer_id;
	local_peer->id_size = orig_peer_id_size;
	local_peer->is_local = 1;
	peerstore = libp2p_peerstore_new(local_peer);

	// 3) make the dialer
	dialer = libp2p_conn_dialer_new(local_peer, peerstore, rsa_private_key);

	// 4) make the remote peer
	remote_ma = multiaddress_new_from_string(remote_swarm);
	remote_peer = libp2p_peer_new();
	remote_peer->id_size = strlen(remote_peer_id);
	remote_peer->id = malloc(remote_peer->id_size);
	memcpy(remote_peer->id, remote_peer_id, remote_peer->id_size);
	remote_peer->addr_head = libp2p_utils_linked_list_new();
	remote_peer->addr_head->item = remote_ma;

	// 5) attempt to dial
	if (!libp2p_conn_dialer_join_swarm(dialer, remote_peer, 10))
		goto exit;

	retVal = 1;
	exit:
	if (decode_base64 != NULL)
		free(decode_base64);
	//libp2p_peer_free(local_peer);
	//libp2p_peerstore_free(peerstore);
	//libp2p_conn_dialer_free(dialer);
	//libp2p_crypto_private_key_free(priv);
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
	struct Libp2pPeer* peer = libp2p_peer_new();

	test_helper_get_id_from_config(config_dir, &private_key, &peer->id);
	if (private_key == NULL)
		goto exit;

	peer->id_size = strlen((char*)peer->id);

	dialer = libp2p_conn_dialer_new(peer, NULL, NULL);
	if (dialer == NULL)
		goto exit;

	destination_address = multiaddress_new_from_string(destination_string);
	if (destination_address == NULL)
		goto exit;

	// now try to dial
	stream = libp2p_conn_dialer_get_stream(dialer, peer, "multistream");
	if (stream == NULL)
		goto exit;

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
		stream->close(stream);
		libp2p_net_multistream_stream_free(stream);
	}
	return retVal;
}
