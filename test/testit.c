#include <stdio.h>

#include "crypto/test_aes.h"
#include "crypto/test_rsa.h"
#include "crypto/test_base58.h"
#include "crypto/test_base32.h"
#include "crypto/test_key.h"
#include "crypto/test_ephemeral.h"
#include "crypto/test_mac.h"
#include "test_secio.h"
#include "test_mbedtls.h"
#include "test_multistream.h"
#include "test_conn.h"
#include "test_record.h"
#include "test_peer.h"
#include "libp2p/utils/logger.h"

const char* names[] = {
		"test_public_der_to_private_der",
		"test_mbedtls_varint_128_binary",
		"test_mbedtls_varint_128_string",
		"test_crypto_rsa_private_key_der",
		"test_crypto_rsa_signing",
		"test_crypto_rsa_public_key_to_peer_id",
		"test_crypto_x509_der_to_private2",
		"test_crypto_x509_der_to_private",
		"test_crypto_hashing_sha256",
		//"test_multihash_encode",
		//"test_multihash_decode",
		//"test_multihash_base58_encode_decode",
		//"test_multihash_base58_decode",
		//"test_multihash_size",
		"test_base58_encode_decode",
		"test_base58_size",
		"test_base58_max_size",
		"test_base58_peer_address",
		//"test_mbedtls_pk_write_key_der",
		//"test_crypto_rsa_sign",
		"test_crypto_encoding_base32_encode",
		"test_protobuf_private_key",
		"test_secio_handshake",
		"test_secio_encrypt_decrypt",
		"test_secio_exchange_protobuf_encode",
		"test_multistream_connect",
		"test_multistream_get_list",
		"test_ephemeral_key_generate",
		"test_ephemeral_key_sign",
		"test_dialer_new",
		"test_dialer_dial",
		"test_dialer_dial_multistream",
		"test_record_protobuf",
		"test_record_make_put_record",
		"test_record_peer_protobuf",
		"test_record_message_protobuf",
		"test_peer",
		"test_peer_protobuf",
		"test_peerstore",
		"test_aes"
};

int (*funcs[])(void) = {
		test_public_der_to_private_der,
		test_mbedtls_varint_128_binary,
		test_mbedtls_varint_128_string,
		test_crypto_rsa_private_key_der,
		test_crypto_rsa_signing,
		test_crypto_rsa_public_key_to_peer_id,
		test_crypto_x509_der_to_private2,
		test_crypto_x509_der_to_private,
		test_crypto_hashing_sha256,
		//test_multihash_encode,
		//test_multihash_decode,
		//test_multihash_base58_encode_decode,
		//test_multihash_base58_decode,
		//test_multihash_size,
		test_base58_encode_decode,
		test_base58_size,
		test_base58_max_size,
		test_base58_peer_address,
		//test_mbedtls_pk_write_key_der,
		//test_crypto_rsa_sign,
		test_crypto_encoding_base32_encode,
		test_protobuf_private_key,
		test_secio_handshake,
		test_secio_encrypt_decrypt,
		test_secio_exchange_protobuf_encode,
		test_multistream_connect,
		test_multistream_get_list,
		test_ephemeral_key_generate,
		test_ephemeral_key_sign,
		test_dialer_new,
		test_dialer_dial,
		test_dialer_dial_multistream,
		test_record_protobuf,
		test_record_make_put_record,
		test_record_peer_protobuf,
		test_record_message_protobuf,
		test_peer,
		test_peer_protobuf,
		test_peerstore,
		test_aes
};

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
	int counter = 0;
	int tests_ran = 0;
	char* test_wanted;
	int only_one = 0;
	if(argc > 1) {
		only_one = 1;
		if (argv[1][0] == '\'') { // some shells put quotes around arguments
			argv[1][strlen(argv[1])-1] = 0;
			test_wanted = &(argv[1][1]);
		}
		else
			test_wanted = argv[1];
	}
	int array_length = sizeof(funcs) / sizeof(funcs[0]);
	int array2_length = sizeof(names) / sizeof(names[0]);
	if (array_length != array2_length) {
		printf("Test arrays are not of the same length. Funcs: %d, Names: %d\n", array_length, array2_length);
	}
	for (int i = 0; i < array_length; i++) {
		if (only_one) {
			const char* currName = names[i];
			if (strcmp(currName, test_wanted) == 0) {
				tests_ran++;
				counter += testit(names[i], funcs[i]);
			}
		}
		else
			if (!only_one) {
				tests_ran++;
				counter += testit(names[i], funcs[i]);
			}
	}

	if (tests_ran == 0)
		printf("***** No tests found *****\n");
	else {
		if (tests_ran - counter > 0) {
			printf("***** There were %d failed test(s) (%d successful) *****\n", tests_ran - counter, counter);
		} else {
			printf("All %d tests passed\n", tests_ran);
		}
	}
	libp2p_logger_free();
	return 1;
}

