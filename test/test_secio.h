#include <stdlib.h>

#include "libp2p/secio/secio.h"
#include "libp2p/secio/exchange.h"
#include "libp2p/net/multistream.h"
#include "libp2p/net/p2pnet.h"
#include "libp2p/utils/logger.h"

#include "mbedtls/md.h"
#include "mbedtls/cipher.h"
#include "mbedtls/md_internal.h"
#include "mbedtls/aes.h"


void print_stretched_key(struct StretchedKey* key) {
	fprintf(stdout, "cipher key: ");
	if (key == NULL) {
		fprintf(stdout, "NULL\n");
		return;
	}
	for(int i = 0; i < key->cipher_size; i++) {
		fprintf(stdout, "%d ", key->cipher_key[i]);
	}
	fprintf(stdout, "\nIV: ");
	for(int i = 0; i < key->iv_size; i++) {
		fprintf(stdout, "%d ", key->iv[i]);
	}
	fprintf(stdout, "\nMAC: ");
	for(int i = 0; i < key->mac_size; i++) {
		fprintf(stdout, "%d ", key->mac_key[i]);
	}
}

int test_secio_handshake() {

	libp2p_logger_add_class("secio");

	int retVal = 0;
	size_t decode_base64_size = 0;
	unsigned char* decode_base64 = NULL;
	// this is a base64 encoded private key. It makes it easier to test if it is in base64 form
	// these were pulled from the GO version of ipfs
	char* orig_priv_key = "CAASqQkwggSlAgEAAoIBAQCuW+8vGUb2n4xOcfPZLmfVAy6GNJ0sYrD/hVXwxBU1aBas+8lfAuLwYJXPCVBg65wZWYEbbWCevLFjwB/oZyJA1J1g+HohggH8QvuDH164FtSbgyHFip2SPR7oUHgSWRqfKXRJsVW/SPCfEt59S8JH99Q747dU9fvZKpelE9aDLf5yI8nj29TDy3c1RpkxfUwfgnbeoCwsDnakFmVdoSEp3Lnt3JlI05qE0bgvkWAaelcXSNQCmZzDwXeMk9y221FnBkL4Vs3v2lKmjLx+Qr37P/t78T+VxsjnGHPhbZTIMIjwwON6568d0j25Bj9v6biiz8iXzBR4Fmz1CQ0mqU5BAgMBAAECggEAc6EYX/29Z/SrEaLUeiUiSsuPYQUnbrYMd4gvVDpVblOXJiTciJvbcFo9P04H9h6KKO2Ih23j86FjaqmQ/4jV2HSn4hUmuW4EbwzkyzJUmHTbjj5KeTzR/pd2Fc63skNROlg9fFmUagSvPm8/CYziTOP35bfAbyGqYXyzkJA1ZExVVSOi1zGVi+lnlI1fU2Aki5F7W7F/d2AQWsh7NXUwT7e6JP7TL+Gn4bWdn3NvluwAWTMgp6/It8OU1XPgu8OhdpZQWsMBqJwr79KGLbq2SZZXAw8O+ay1JQYmmmvYzwhdDgJwl+MOtf3NiqQWFzZP8RnlHGNcXlLHHPW0FB9H+QKBgQDirtBOqjCtND6m4hEfy6A24GcITYUBg1+AYQ7uM5uZl5u9AyxfG4bPxyrspz3yS0DOV4HNQ88iwmUE8+8ZHCLSY/YIp73Nk4m8t2s46CuI7Y5GrwCnh9xTMwaUrNx4IRTWyR3OxjQtUyrXtPR6uJ83FDenXvNi//Mrzp+myxX4wwKBgQDE6L8qiVA6n9k5dyUxxMUKJqynwPcBeC+wI85gr/9wwlRYDrgMYeH6/D5prZ3N5m8+zugVQQJKLfXBG0i8BRh5xLYFCZnV2O3NwvCdENlZJZrNNoz9jM3yRV+c7OdrclxDiN0bjGEBWv8GHutNFAwuUfMe0TMdfFYpM7gBHjEMqwKBgQCWHwOhNSCrdDARwSFqFyZxcUeKvhvZlrFGigCjS9Y+b6MaF+Ho0ogDTnlk5JUnwyKWBGnYEJI7CNZx40JzNKjzAHRN4xjV7mGHc0k1FLzQH9LbiMY8LMOC7gXrrFcNz4rHe8WbzLN9WNjEpfhK1b3Lcj4xP7ab17mpR1t/0HsqlQKBgQC3S6lYIUZLrCz7b0tyTqbU0jd6WQgVmBlcL5iXLH3uKxd0eQ8eh6diiZhXq0PwPQdlQhmMX12QS8QupAVK8Ltd7p05hzxqcmq7VTHCI8MPVxAI4zTPeVjko2tjmqu5u1TjkO2yDTTnnBs1SWbj8zt7itFz6G1ajzltVTV95OrnzQKBgQDEwZxnJA2vDJEDaJ82CiMiUAFzwsoK8hDvz63kOKeEW3/yESySnUbzpxDEjzYNsK74VaXHKCGI40fDRUqZxU/+qCrFf3xDfYS4r4wfFd2Jh+tn4NzSV/EhIr9KR/ZJW+TvGks+pWUJ3mhjPEvNtlt3M64/j2D0RP2aBQtoSpeezQ==";
	char* orig_peer_id = "QmRKm1d9kSCRpMFtLYpfhhCQ3DKuSSPJa3qn9wWXfwnWnY";
	size_t orig_peer_id_size = strlen(orig_peer_id);
	struct RsaPrivateKey* rsa_private_key = NULL;
	unsigned char hashed[32] = {0};
	size_t final_id_size = 1600;
	unsigned char final_id[final_id_size];

	struct PrivateKey* private_key = NULL;
	struct SessionContext* secure_session = NULL;
	struct Peerstore *peerstore = NULL;
	struct Libp2pPeer* local_peer = NULL;

	// 1) take the private key and turn it back into bytes (decode base 64)
	decode_base64_size = libp2p_crypto_encoding_base64_decode_size(strlen(orig_priv_key));
	decode_base64 = (unsigned char*)malloc(decode_base64_size);
	memset(decode_base64, 0, decode_base64_size);

	if (!libp2p_crypto_encoding_base64_decode((unsigned char*)orig_priv_key, strlen(orig_priv_key), &decode_base64[0], decode_base64_size, &decode_base64_size))
		goto exit;

	if (!libp2p_crypto_private_key_protobuf_decode(decode_base64, decode_base64_size, &private_key))
		goto exit;

	// 2) take the bytes of the private key and turn it back into an RSA private key struct
	//TODO: should verify that this key is RSA
	rsa_private_key = libp2p_crypto_rsa_rsa_private_key_new();
	if (!libp2p_crypto_encoding_x509_der_to_private_key(private_key->data, private_key->data_size, rsa_private_key))
		goto exit;

	// 2b) take the private key and fill in the public key DER
	if (!libp2p_crypto_rsa_private_key_fill_public_key(rsa_private_key))
		goto exit;

	local_peer = libp2p_peer_new();
	peerstore = libp2p_peerstore_new(local_peer);
	secure_session = libp2p_session_context_new();
	//secure_session.host = "www.jmjatlanta.com";
	secure_session->host = "107.170.104.234";
	secure_session->port = 4001;
	secure_session->traffic_type = TCP;
	// connect to host
	secure_session->insecure_stream = libp2p_net_multistream_connect(secure_session->host, secure_session->port);
	if (secure_session->insecure_stream == NULL) {
		libp2p_logger_error("test_secio", "Unable to open multistream to server %s port %d.\n", secure_session->host, secure_session->port);
		goto exit;
	}
	secure_session->default_stream = secure_session->insecure_stream;
	if (*((int*)secure_session->insecure_stream->socket_descriptor) == -1) {
		fprintf(stderr, "test_secio_handshake: Unable to get socket descriptor\n");
		goto exit;
	}

	// attempt to write the protocol, and see what comes back
	char* protocol = "/secio/1.0.0\n";
	int protocol_size = strlen(protocol);
	secure_session->insecure_stream->write(secure_session, (unsigned char*)protocol, protocol_size);

	unsigned char* buffer = NULL;
	size_t bytes_read = 0;
	int timeout = 30;
	secure_session->insecure_stream->read(secure_session, &buffer, &bytes_read, timeout);

	if (!libp2p_secio_handshake(secure_session, rsa_private_key, peerstore)) {
		fprintf(stderr, "test_secio_handshake: Unable to do handshake\n");
		if (secure_session->shared_key != NULL) {
			fprintf(stdout, "Shared key: ");
			for(int i = 0; i < secure_session->shared_key_size; i++)
				fprintf(stdout, "%d ", secure_session->shared_key[i]);
			fprintf(stdout, "\nLocal stretched key: ");
			print_stretched_key(secure_session->local_stretched_key);
			fprintf(stdout, "\nRemote stretched key: ");
			print_stretched_key(secure_session->remote_stretched_key);
			fprintf(stdout, "\n");
		}
		goto exit;
	}

	/*
	fprintf(stdout, "Shared key: ");
	for(int i = 0; i < secure_session.shared_key_size; i++)
		fprintf(stdout, "%d ", secure_session.shared_key[i]);
	fprintf(stdout, "\nLocal stretched key: ");
	print_stretched_key(secure_session.local_stretched_key);
	fprintf(stdout, "\nRemote stretched key: ");
	print_stretched_key(secure_session.remote_stretched_key);
	fprintf(stdout, "\n");
	*/

	// now attempt to do something with it... try to negotiate a multistream
	if (libp2p_net_multistream_negotiate(secure_session) == 0) {
		fprintf(stdout, "Unable to negotiate multistream\n");
		goto exit;
	}

	// now attempt an "ls"
	if (libp2p_net_multistream_write(secure_session, (unsigned char*)"ls\n", 3) == 0) {
		fprintf(stdout, "Unable to send ls to multistream\n");
		goto exit;
	}

	// retrieve the response
	unsigned char* results;
	size_t results_size;
	if (libp2p_net_multistream_read(secure_session, &results, &results_size, 30) == 0) {
		fprintf(stdout, "Unable to read ls results from multistream\n");
		free(results);
		goto exit;
	}

	fprintf(stdout, "Results of ls: %.*s", (int)results_size, results);

	free(results);
	results = NULL;

	retVal = 1;
	exit:
	if (peerstore != NULL)
		libp2p_peerstore_free(peerstore);
	/*
	if (secure_session.insecure_stream != NULL)
		libp2p_net_multistream_stream_free(secure_session.insecure_stream);
	if (secure_session.local_stretched_key != NULL)
		libp2p_crypto_ephemeral_stretched_key_free(secure_session.local_stretched_key);
	if (secure_session.remote_stretched_key != NULL)
		libp2p_crypto_ephemeral_stretched_key_free(secure_session.remote_stretched_key);
	if (secure_session.ephemeral_private_key != NULL)
		libp2p_crypto_ephemeral_key_free(secure_session.ephemeral_private_key);
	if (secure_session.remote_ephemeral_public_key != NULL)
		free(secure_session.remote_ephemeral_public_key);
	if (secure_session.chosen_cipher != NULL)
		free(secure_session.chosen_cipher);
	if (secure_session.chosen_curve != NULL)
		free(secure_session.chosen_curve);
	if (secure_session.chosen_hash != NULL)
		free(secure_session.chosen_hash);
	if (secure_session.shared_key != NULL)
		free(secure_session.shared_key);
	*/
	if (private_key != NULL)
		libp2p_crypto_private_key_free(private_key);
	if (decode_base64 != NULL)
		free(decode_base64);
	if (rsa_private_key != NULL)
		libp2p_crypto_rsa_rsa_private_key_free(rsa_private_key);
	return retVal;
}

int libp2p_secio_encrypt(const struct SessionContext* session, const unsigned char* incoming, size_t incoming_size, unsigned char** outgoing, size_t* outgoing_size);
int libp2p_secio_decrypt(const struct SessionContext* session, const unsigned char* incoming, size_t incoming_size, unsigned char** outgoing, size_t* outgoing_size);

int test_secio_encrypt_decrypt() {
	unsigned char* original = (unsigned char*)"This is a test message";
	int retVal = 0;
	unsigned char* encrypted = NULL;
	size_t encrypted_size = 0;
	unsigned char* results = NULL;
	size_t results_size = 0;
	struct SessionContext secure_session;
	struct StretchedKey stretched_key;

	secure_session.local_stretched_key = &stretched_key;
	secure_session.remote_stretched_key = &stretched_key;

	secure_session.local_stretched_key->cipher_key = (unsigned char*)"abcdefghijklmnopqrstuvwxyzabcdef";
	secure_session.local_stretched_key->cipher_size = 32;
	secure_session.local_stretched_key->mac_size = 40;
	secure_session.local_stretched_key->mac_key = (unsigned char*)"abcdefghijklmnopqrstuvwxyzabcdefghijklmn";
	secure_session.local_stretched_key->iv_size = 16;
	secure_session.local_stretched_key->iv = (unsigned char*)"abcdefghijklmnop";
	secure_session.mac_function = NULL;

	if (!libp2p_secio_encrypt(&secure_session, original, strlen((char*)original), &encrypted, &encrypted_size)) {
		fprintf(stderr, "Unable to encrypt\n");
		goto exit;
	}

	if (!libp2p_secio_decrypt(&secure_session, encrypted, encrypted_size, &results, &results_size)) {
		fprintf(stderr, "Unable to decrypt\n");
		goto exit;
	}

	if (results_size != strlen((char*)original)) {
		fprintf(stderr, "Results size are different. Results size = %lu and original is %lu\n", results_size, strlen((char*)original));
		goto exit;
	}

	if (strncmp((char*)original, (char*)results, strlen( (char*) original)) != 0) {
		fprintf(stderr, "String comparison did not match\n");
		goto exit;
	}

	retVal = 1;
	exit:
	if (results != NULL)
		free(results);
	if (encrypted != NULL)
		free(encrypted);
	return retVal;
}

int test_secio_exchange_protobuf_encode() {
	char* protobuf = NULL;
	size_t protobuf_size = 0, actual_size = 0;
	struct Exchange* exch = libp2p_secio_exchange_new();
	int retVal = 0;

	exch->epubkey_size = 100;
	exch->epubkey = malloc(exch->epubkey_size);
	for(int i = 0; i < exch->epubkey_size; i++) {
		exch->epubkey[i] = i;
	}
	exch->signature_size = 32;
	exch->signature = malloc(exch->signature_size);
	for(int i = 0; i < exch->signature_size; i++) {
		exch->signature[i] = i;
	}

	protobuf_size = libp2p_secio_exchange_protobuf_encode_size(exch);
	protobuf = malloc(protobuf_size);

	libp2p_secio_exchange_protobuf_encode(exch, (unsigned char*)protobuf, protobuf_size, &actual_size);

	if (actual_size > protobuf_size)
		goto exit;

	retVal = 1;
	exit:
	free(protobuf);
	libp2p_secio_exchange_free(exch);
	return retVal;
}


int test_secio_encrypt_like_go() {
	// GO version keys:
	// local keys
	unsigned char keyIv[] = { 233, 20, 188, 79, 55, 204, 132, 231, 82, 167, 63, 211, 74, 253, 20, 109 };
	unsigned char keyMac[] = { 224, 94, 119, 190, 68, 213, 247, 204, 211, 25, 42, 154, 145, 96, 86, 8, 103, 187, 133, 15 };
	unsigned char keyCipher[] = { 137, 132, 0, 154, 131, 200, 29, 70, 88, 158, 170, 177, 220, 101, 113, 212, 98, 180, 25, 96, 15, 208, 210, 204, 167, 161, 238, 207, 229, 69, 83, 29 };

	// with the above keys, the "nonce" below should give the expected result
	unsigned char nonce_string[] = { 253, 17, 36, 85, 95, 130, 6, 14, 184, 204, 131, 114, 143, 245, 74, 51 };
	unsigned char expected_nonce[] = { 71, 244, 156, 168, 60, 181, 227, 199, 116, 155, 82, 29, 7, 237, 234, 27 };
	int incoming_size = 16;

	size_t result_size = 255;
	unsigned char result[result_size];
	memset(result, 0, result_size);

	// do nonce
	mbedtls_aes_context cipher_ctx;
	mbedtls_aes_init(&cipher_ctx);
	if (mbedtls_aes_setkey_enc(&cipher_ctx, keyCipher, 32 * 8)) {
		fprintf(stderr, "Unable to set key for cipher\n");
		return 0;
	}

	size_t nonce_offset = 0;
	unsigned char stream_block[16];
	memset(stream_block, 0, 16);
	if (mbedtls_aes_crypt_ctr(&cipher_ctx, incoming_size, &nonce_offset, keyIv, stream_block, nonce_string, result)) {
		fprintf(stderr, "Unable to update cipher\n");
		return 0;
	}

	// do comparison
	for(int i = 0; i < incoming_size; i++) {
		if (result[i] != expected_nonce[i]) {
			fprintf(stderr, "Nonce: At position %d expected %u but got %u\n", i, expected_nonce[i], result[i]);
			return 0;
		}
	}

	// now try multistream
	result_size = 255;
	memset(result, 0, result_size);
	unsigned char multistream_string[] = { 19, 47, 109, 117, 108, 116, 105, 115, 116, 114, 101, 97, 109, 47, 49, 46, 48, 46, 48, 10 };
	unsigned char expected_multistream[] = { 105, 218, 190, 138, 115, 254, 188, 113, 192, 128, 162, 148, 118, 164, 178, 140, 239, 185, 53, 17 };
	incoming_size = 20;

	if (mbedtls_aes_crypt_ctr(&cipher_ctx, incoming_size, &nonce_offset, keyIv, stream_block, multistream_string, result)) {
		fprintf(stderr, "Unable to update cipher\n");
		return 0;
	}
	mbedtls_aes_free(&cipher_ctx);

	// do comparison
	for(int i = 0; i < incoming_size; i++) {
		if (result[i] != expected_multistream[i]) {
			fprintf(stderr, "Multistream: At position %d expected %d but got %d\n", i, expected_multistream[i], result[i]);
			return 0;
		}
	}

	return 1;
}


/***
 * Attempt to connect to the GO version of secio
 */
int test_secio_handshake_go() {

	libp2p_logger_add_class("secio");

	int retVal = 0;
	size_t decode_base64_size = 0;
	unsigned char* decode_base64 = NULL;
	// this is a base64 encoded private key. It makes it easier to test if it is in base64 form
	// these were pulled from the GO version of ipfs
	char* orig_priv_key = "CAASqQkwggSlAgEAAoIBAQCuW+8vGUb2n4xOcfPZLmfVAy6GNJ0sYrD/hVXwxBU1aBas+8lfAuLwYJXPCVBg65wZWYEbbWCevLFjwB/oZyJA1J1g+HohggH8QvuDH164FtSbgyHFip2SPR7oUHgSWRqfKXRJsVW/SPCfEt59S8JH99Q747dU9fvZKpelE9aDLf5yI8nj29TDy3c1RpkxfUwfgnbeoCwsDnakFmVdoSEp3Lnt3JlI05qE0bgvkWAaelcXSNQCmZzDwXeMk9y221FnBkL4Vs3v2lKmjLx+Qr37P/t78T+VxsjnGHPhbZTIMIjwwON6568d0j25Bj9v6biiz8iXzBR4Fmz1CQ0mqU5BAgMBAAECggEAc6EYX/29Z/SrEaLUeiUiSsuPYQUnbrYMd4gvVDpVblOXJiTciJvbcFo9P04H9h6KKO2Ih23j86FjaqmQ/4jV2HSn4hUmuW4EbwzkyzJUmHTbjj5KeTzR/pd2Fc63skNROlg9fFmUagSvPm8/CYziTOP35bfAbyGqYXyzkJA1ZExVVSOi1zGVi+lnlI1fU2Aki5F7W7F/d2AQWsh7NXUwT7e6JP7TL+Gn4bWdn3NvluwAWTMgp6/It8OU1XPgu8OhdpZQWsMBqJwr79KGLbq2SZZXAw8O+ay1JQYmmmvYzwhdDgJwl+MOtf3NiqQWFzZP8RnlHGNcXlLHHPW0FB9H+QKBgQDirtBOqjCtND6m4hEfy6A24GcITYUBg1+AYQ7uM5uZl5u9AyxfG4bPxyrspz3yS0DOV4HNQ88iwmUE8+8ZHCLSY/YIp73Nk4m8t2s46CuI7Y5GrwCnh9xTMwaUrNx4IRTWyR3OxjQtUyrXtPR6uJ83FDenXvNi//Mrzp+myxX4wwKBgQDE6L8qiVA6n9k5dyUxxMUKJqynwPcBeC+wI85gr/9wwlRYDrgMYeH6/D5prZ3N5m8+zugVQQJKLfXBG0i8BRh5xLYFCZnV2O3NwvCdENlZJZrNNoz9jM3yRV+c7OdrclxDiN0bjGEBWv8GHutNFAwuUfMe0TMdfFYpM7gBHjEMqwKBgQCWHwOhNSCrdDARwSFqFyZxcUeKvhvZlrFGigCjS9Y+b6MaF+Ho0ogDTnlk5JUnwyKWBGnYEJI7CNZx40JzNKjzAHRN4xjV7mGHc0k1FLzQH9LbiMY8LMOC7gXrrFcNz4rHe8WbzLN9WNjEpfhK1b3Lcj4xP7ab17mpR1t/0HsqlQKBgQC3S6lYIUZLrCz7b0tyTqbU0jd6WQgVmBlcL5iXLH3uKxd0eQ8eh6diiZhXq0PwPQdlQhmMX12QS8QupAVK8Ltd7p05hzxqcmq7VTHCI8MPVxAI4zTPeVjko2tjmqu5u1TjkO2yDTTnnBs1SWbj8zt7itFz6G1ajzltVTV95OrnzQKBgQDEwZxnJA2vDJEDaJ82CiMiUAFzwsoK8hDvz63kOKeEW3/yESySnUbzpxDEjzYNsK74VaXHKCGI40fDRUqZxU/+qCrFf3xDfYS4r4wfFd2Jh+tn4NzSV/EhIr9KR/ZJW+TvGks+pWUJ3mhjPEvNtlt3M64/j2D0RP2aBQtoSpeezQ==";
	char* orig_peer_id = "QmRKm1d9kSCRpMFtLYpfhhCQ3DKuSSPJa3qn9wWXfwnWnY";
	size_t orig_peer_id_size = strlen(orig_peer_id);
	struct RsaPrivateKey* rsa_private_key = NULL;
	unsigned char hashed[32] = {0};
	size_t final_id_size = 1600;
	unsigned char final_id[final_id_size];

	struct PrivateKey* private_key = NULL;
	struct SessionContext* secure_session = libp2p_session_context_new();
	struct Peerstore *peerstore = NULL;
	struct Libp2pPeer* local_peer = NULL;

	// 1) take the private key and turn it back into bytes (decode base 64)
	decode_base64_size = libp2p_crypto_encoding_base64_decode_size(strlen(orig_priv_key));
	decode_base64 = (unsigned char*)malloc(decode_base64_size);
	memset(decode_base64, 0, decode_base64_size);

	if (!libp2p_crypto_encoding_base64_decode((unsigned char*)orig_priv_key, strlen(orig_priv_key), &decode_base64[0], decode_base64_size, &decode_base64_size))
		goto exit;

	if (!libp2p_crypto_private_key_protobuf_decode(decode_base64, decode_base64_size, &private_key))
		goto exit;

	// 2) take the bytes of the private key and turn it back into an RSA private key struct
	//TODO: should verify that this key is RSA
	rsa_private_key = libp2p_crypto_rsa_rsa_private_key_new();
	if (!libp2p_crypto_encoding_x509_der_to_private_key(private_key->data, private_key->data_size, rsa_private_key))
		goto exit;

	// 2b) take the private key and fill in the public key DER
	if (!libp2p_crypto_rsa_private_key_fill_public_key(rsa_private_key))
		goto exit;

	local_peer = libp2p_peer_new();
	peerstore = libp2p_peerstore_new(local_peer);
	//secure_session.host = "www.jmjatlanta.com";
	secure_session->host = "10.211.55.2";
	secure_session->port = 4001;
	secure_session->traffic_type = TCP;
	// connect to host
	secure_session->insecure_stream = libp2p_net_multistream_connect(secure_session->host, secure_session->port);
	secure_session->default_stream = secure_session->insecure_stream;
	if (*((int*)secure_session->insecure_stream->socket_descriptor) == -1) {
		fprintf(stderr, "test_secio_handshake: Unable to get socket descriptor\n");
		goto exit;
	}

	// attempt to write the protocol, and see what comes back
	char* protocol = "/secio/1.0.0\n";
	int protocol_size = strlen(protocol);
	secure_session->insecure_stream->write(secure_session, (unsigned char*)protocol, protocol_size);

	unsigned char* buffer = NULL;
	size_t bytes_read = 0;
	int timeout = 30;
	secure_session->insecure_stream->read(secure_session, &buffer, &bytes_read, timeout);

	if (!libp2p_secio_handshake(secure_session, rsa_private_key, peerstore)) {
		fprintf(stderr, "test_secio_handshake: Unable to do handshake\n");
		if (secure_session->shared_key != NULL) {
			fprintf(stdout, "Shared key: ");
			for(int i = 0; i < secure_session->shared_key_size; i++)
				fprintf(stdout, "%d ", secure_session->shared_key[i]);
			fprintf(stdout, "\nLocal stretched key: ");
			print_stretched_key(secure_session->local_stretched_key);
			fprintf(stdout, "\nRemote stretched key: ");
			print_stretched_key(secure_session->remote_stretched_key);
			fprintf(stdout, "\n");
		}
		goto exit;
	}

	/*
	fprintf(stdout, "Shared key: ");
	for(int i = 0; i < secure_session.shared_key_size; i++)
		fprintf(stdout, "%d ", secure_session.shared_key[i]);
	fprintf(stdout, "\nLocal stretched key: ");
	print_stretched_key(secure_session.local_stretched_key);
	fprintf(stdout, "\nRemote stretched key: ");
	print_stretched_key(secure_session.remote_stretched_key);
	fprintf(stdout, "\n");
	*/

	// now attempt to do something with it... try to negotiate a multistream
	if (libp2p_net_multistream_negotiate(secure_session) == 0) {
		fprintf(stdout, "Unable to negotiate multistream\n");
		goto exit;
	}

	// now attempt an "ls"
	if (libp2p_net_multistream_write(secure_session, (unsigned char*)"ls\n", 3) == 0) {
		fprintf(stdout, "Unable to send ls to multistream\n");
		goto exit;
	}

	// retrieve the response
	unsigned char* results;
	size_t results_size;
	if (libp2p_net_multistream_read(secure_session, &results, &results_size, 30) == 0) {
		fprintf(stdout, "Unable to read ls results from multistream\n");
		free(results);
		goto exit;
	}

	fprintf(stdout, "Results of ls: %.*s", (int)results_size, results);

	free(results);
	results = NULL;

	retVal = 1;
	exit:
	if (private_key != NULL)
		libp2p_crypto_private_key_free(private_key);
	if (decode_base64 != NULL)
		free(decode_base64);
	if (rsa_private_key != NULL)
		libp2p_crypto_rsa_rsa_private_key_free(rsa_private_key);
	if (peerstore != NULL)
		libp2p_peerstore_free(peerstore);
	return retVal;
}
