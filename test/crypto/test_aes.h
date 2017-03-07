#pragma once

#include <stdlib.h>
#include <string.h>

#include "libp2p/crypto/aes.h"

int test_aes() {
	char key[32];
	char iv[17] = "ae287j789wcqe46a";
	char iv_original[17] = "ae287j789wcqe46a";
	unsigned char* encrypted = NULL;
	size_t output_size = 0;
	char* input = "inc the null, this is 40 bytes of data";
	unsigned char* unencrypted = NULL;
	size_t input_size = 40;
	int retVal = 0;

	if (libp2p_crypto_aes_key_generate(key) != 1)
		goto exit;

	if (libp2p_crypto_aes_encrypt(key, iv, input, input_size, &encrypted, &output_size) != 1)
		goto exit;

	if (output_size != 48)
		goto exit;

	if (encrypted == NULL)
		goto exit;

	if (libp2p_crypto_aes_decrypt(key, iv_original, encrypted, output_size, &unencrypted, &output_size) != 1)
		goto exit;

	if (output_size != 48)
		goto exit;

	if (strncmp(input, unencrypted, input_size) != 0)
		goto exit;

	retVal = 1;
	exit:
	if (encrypted != NULL)
		free(encrypted);
	if (unencrypted != NULL)
		free(unencrypted);
	return retVal;
}
