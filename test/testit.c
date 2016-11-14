
#include <stdio.h>


#include "crypto/test_rsa.h"
#include "crypto/test_base58.h"
#include "test_mbedtls.h"

int testit(const char* name, int (*func)(void)) {
	printf("Testing %s...\n", name);
	int retVal = func();
	if (retVal)
		printf("%s success!\n", name);
	else
		printf("** Uh oh! %s failed.**\n", name);
	return retVal;
}

int main(int argc, char** argv) {
	testit("test_public_der_to_private_der", test_public_der_to_private_der);
	testit("test_mbedtls_varint_128_binary", test_mbedtls_varint_128_binary);
	testit("test_mbedtls_varint_128_string", test_mbedtls_varint_128_string);
	testit("test_crypto_rsa_private_key_der", test_crypto_rsa_private_key_der);
	testit("test_crypto_rsa_public_key_to_peer_id", test_crypto_rsa_public_key_to_peer_id);
	testit("test_crypto_x509_der_to_private2", test_crypto_x509_der_to_private2);
	testit("test_crypto_x509_der_to_private", test_crypto_x509_der_to_private);
	//testit("test_multihash_encode", test_multihash_encode);
	//testit("test_multihash_decode", test_multihash_decode);
	//testit("test_multihash_base58_encode_decode", test_multihash_base58_encode_decode);
	//testit("test_multihash_base58_decode", test_multihash_base58_decode);
	//testit("test_multihash_size", test_multihash_size);
	testit("test_base58_encode_decode", test_base58_encode_decode);
	testit("test_base58_size", test_base58_size);
	testit("test_base58_max_size", test_base58_max_size);
	testit("test_base58_peer_address", test_base58_peer_address);
	//testit("test_mbedtls_pk_write_key_der", test_mbedtls_pk_write_key_der);
	return 1;
}

