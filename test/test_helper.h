#include <stdlib.h>
#include <stdio.h>

#include "libp2p/crypto/key.h"

void read_file(char* path, char** contents) {
	FILE* fd = fopen(path, "r");
	fseek(fd, 0L, SEEK_END);
	size_t num_bytes = ftell(fd);
	rewind(fd);
	*contents = malloc(num_bytes);
	fread(*contents, 1, num_bytes, fd);
	fclose(fd);
	return;
}

struct PrivateKey* base64ToPrivateKey(char* base64) {
	int retVal = 0;
	size_t decode_base64_size = 0;
	unsigned char* decode_base64 = NULL;
	struct PrivateKey* out = NULL;

	// 1) take the private key and turn it back into bytes (decode base 64)
	decode_base64_size = libp2p_crypto_encoding_base64_decode_size(strlen(base64));
	decode_base64 = (unsigned char*)malloc(decode_base64_size);
	if (decode_base64 == NULL)
		goto exit;
	memset(decode_base64, 0, decode_base64_size);

	if (!libp2p_crypto_encoding_base64_decode((unsigned char*)base64, strlen(base64), &decode_base64[0], decode_base64_size, &decode_base64_size))
		goto exit;

	if (!libp2p_crypto_private_key_protobuf_decode(decode_base64, decode_base64_size, &out))
		goto exit;

	retVal = 1;
	exit:
	if (retVal != 1) {
		libp2p_crypto_private_key_free(out);
		out = NULL;
	}
	if (decode_base64 != NULL)
		free(decode_base64);
	return out;
}

int test_helper_get_id_from_config(char* path, struct PrivateKey** private_ptr, char** peer_ptr) {
	int retVal = 0;
	char* contents = NULL;
	char* ptr = NULL;
	char* end = NULL;
	int length = 0;
	read_file(path, &contents);
	if (contents == NULL)
		goto exit;

	// peer id
	ptr = strstr(contents, "PeerID");
	if (ptr == NULL)
		goto exit;

	ptr = strstr(ptr, "Qm");
	if (ptr == NULL)
		goto exit;

	end = strstr(ptr, "\"");

	length = end - ptr;
	*peer_ptr = malloc(length + 1);
	if (*peer_ptr == NULL)
		goto exit;
	memcpy(*peer_ptr, ptr, length);
	(*peer_ptr)[length] = 0;

	// private key
	ptr = strstr(contents, "PrivKey\":");
	if (ptr == NULL)
		goto exit;
	ptr += 9;
	ptr = strstr(ptr, "\"");
	ptr++;

	end = strstr(ptr, "\"");
	end[0] = 0;

	// turn the encoded private key into a struct
	*private_ptr = base64ToPrivateKey(ptr);

	retVal = 1;
	exit:
	if (contents != NULL)
		free(contents);
	return retVal;
}
