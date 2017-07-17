#pragma once

#include "libp2p/crypto/sha256.h"

int test_crypto_hashing_sha256() {
	int array_length = 255;
	char test_array[array_length];

	for(int i = 0; i < array_length; i++) {
		int j = i % 255;
		test_array[i] = i;
	}

	char result_mac1[32];
	char result_mac2[32];

	libp2p_crypto_hashing_sha256((unsigned char*)&test_array[0], array_length, (unsigned char*)&result_mac1[0]);
	libp2p_crypto_hashing_sha256((unsigned char*)&test_array[0], array_length, (unsigned char*)&result_mac2[0]);

	if (memcmp(result_mac1, result_mac2, 32) != 0)
		return 0;
	return 1;
}
