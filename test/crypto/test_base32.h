#include "libp2p/crypto/encoding/base32.h"

int test_crypto_encoding_base32_encode() {
	size_t input_size = 1000;
	unsigned char input[input_size];
	int minus = 0;
	for(int i = 0; i < input_size; i++) {
		if (input_size > 0 && input_size % 255 == 0) {
			minus += 255;
		}
		input[i] = input_size - minus;
	}

	size_t results_size = libp2p_crypto_encoding_base32_encode_size(input_size);
	unsigned char results[results_size];
	int retVal = libp2p_crypto_encoding_base32_encode(input, input_size, &results[0], &results_size);
	if (retVal == 0)
		return 0;
	return 1;

}
