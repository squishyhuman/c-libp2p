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
#include "test_yamux.h"
#include "test_net.h"
#include "libp2p/utils/logger.h"

struct test {
	int index;
	const char* name;
	int (*func)(void);
	int part_of_suite;
	struct test* next;
};

struct test* first_test = NULL;
struct test* last_test = NULL;

int testit(const char* name, int (*func)(void)) {
	fprintf(stderr, "TESTING %s...\n", name);
	int retVal = func();
	if (retVal)
		fprintf(stderr, "%s success!\n", name);
	else
		fprintf(stderr, "** Uh oh! %s failed.**\n", name);
	return retVal == 0;
}

int tear_down_test_collection() {
	struct test* current_test = first_test;
	while (current_test != NULL) {
		struct test* next_test = current_test->next;
		free(current_test);
		current_test = next_test;
	}
	return 1;
}

int add_test(const char* name, int (*func)(void), int part_of_suite) {
	// create a new test
	struct test* t = (struct test*) malloc(sizeof(struct test));
	t->name = name;
	t->func = func;
	t->part_of_suite = part_of_suite;
	t->next = NULL;
	if (last_test == NULL)
		t->index = 0;
	else
		t->index = last_test->index + 1;
	// place it in the collection
	if (first_test == NULL) {
		first_test = t;
	} else {
		last_test->next = t;
	}
	last_test = t;
	if (last_test == NULL)
		return 0;
	return last_test->index;
}

int build_test_collection() {
	add_test("test_public_der_to_private_der", test_public_der_to_private_der, 1);
	add_test("test_mbedtls_varint_128_binary", test_mbedtls_varint_128_binary, 1);
	add_test("test_mbedtls_varint_128_string", test_mbedtls_varint_128_string,1);
	add_test("test_crypto_rsa_private_key_der", test_crypto_rsa_private_key_der, 1);
	add_test("test_crypto_rsa_signing", test_crypto_rsa_signing, 1);
	add_test("test_crypto_rsa_public_key_to_peer_id", test_crypto_rsa_public_key_to_peer_id,1);
	add_test("test_crypto_x509_der_to_private2", test_crypto_x509_der_to_private2, 1);
	add_test("test_crypto_x509_der_to_private", test_crypto_x509_der_to_private,1);
	add_test("test_crypto_hashing_sha256", test_crypto_hashing_sha256,1);
	//add_test("test_multihash_encode", func,1);
	//add_test("test_multihash_decode", func,1);
	//add_test("test_multihash_base58_encode_decode", func,1);
	//add_test("test_multihash_base58_decode", func,1);
	//add_test("test_multihash_size", func,1);
	add_test("test_base58_encode_decode", test_base58_encode_decode,1);
	add_test("test_base58_size", test_base58_size,1);
	add_test("test_base58_max_size", test_base58_max_size,1);
	add_test("test_base58_peer_address", test_base58_peer_address,1);
	//add_test("test_mbedtls_pk_write_key_der", func,1);
	//add_test("test_crypto_rsa_sign", func,1);
	add_test("test_crypto_encoding_base32_encode", test_crypto_encoding_base32_encode,1);
	add_test("test_protobuf_private_key", test_protobuf_private_key,1);
	add_test("test_secio_handshake", test_secio_handshake,1);
	add_test("test_secio_handshake_go", test_secio_handshake_go,1);
	add_test("test_secio_encrypt_decrypt", test_secio_encrypt_decrypt,1);
	add_test("test_secio_exchange_protobuf_encode", test_secio_exchange_protobuf_encode,1);
	add_test("test_secio_encrypt_like_go", test_secio_encrypt_like_go,1);
	add_test("test_multistream_connect", test_multistream_connect,1);
	add_test("test_multistream_get_list", test_multistream_get_list,1);
	add_test("test_ephemeral_key_generate", test_ephemeral_key_generate,1);
	add_test("test_ephemeral_key_sign", test_ephemeral_key_sign,1);
	add_test("test_dialer_new", test_dialer_new,1);
	add_test("test_dialer_dial", test_dialer_dial,1);
	add_test("test_dialer_join_swarm", test_dialer_join_swarm, 1);
	add_test("test_dialer_dial_multistream", test_dialer_dial_multistream,1);
	add_test("test_record_protobuf", test_record_protobuf,1);
	add_test("test_record_make_put_record", test_record_make_put_record,1);
	add_test("test_record_peer_protobuf", test_record_peer_protobuf,1);
	add_test("test_record_message_protobuf", test_record_message_protobuf,1);
	add_test("test_peer", test_peer,1);
	add_test("test_peer_protobuf", test_peer_protobuf,1);
	add_test("test_peerstore", test_peerstore,1);
	add_test("test_aes", test_aes, 1);
	add_test("test_yamux_stream_new", test_yamux_stream_new, 1);
	add_test("test_yamux_identify", test_yamux_identify, 1);
	add_test("test_yamux_incoming_protocol_request", test_yamux_incoming_protocol_request, 1);
	add_test("test_net_server_startup_shutdown", test_net_server_startup_shutdown, 1);
	add_test("test_yamux_client_server_connect", test_yamux_client_server_connect, 1);
	return 1;
};

/**
 * Pull the next test name from the command line
 * @param the count of arguments on the command line
 * @param argv the command line arguments
 * @param arg_number the current argument we want
 * @returns a null terminated string of the next test or NULL
 */
char* get_test(int argc, char** argv, int arg_number) {
	char* retVal = NULL;
	char* ptr = NULL;
	if (argc > arg_number) {
		ptr = argv[arg_number];
		if (ptr[0] == '\'')
			ptr++;
		retVal = ptr;
		ptr = strchr(retVal, '\'');
		if (ptr != NULL)
			ptr[0] = 0;
	}
	return retVal;
}

struct test* get_test_by_index(int index) {
	struct test* current = first_test;
	while (current != NULL && current->index != index) {
		current = current->next;
	}
	return current;
}

struct test* get_test_by_name(const char* name) {
	struct test* current = first_test;
	while (current != NULL && strcmp(current->name, name) != 0) {
		current = current->next;
	}
	return current;
}

/**
 * run certain tests or run all
 */
int main(int argc, char** argv) {
	int counter = 0;
	int tests_ran = 0;
	char* test_name_wanted = NULL;
	int certain_tests = 0;
	int current_test_arg = 1;
	if(argc > 1) {
		certain_tests = 1;
	}
	build_test_collection();
	if (certain_tests) {
		// certain tests were passed on the command line
		test_name_wanted = get_test(argc, argv, current_test_arg);
		while (test_name_wanted != NULL) {
			struct test* t = get_test_by_name(test_name_wanted);
			if (t != NULL) {
				tests_ran++;
				counter += testit(t->name, t->func);
			}
			test_name_wanted = get_test(argc, argv, ++current_test_arg);
		}
	} else {
		// run all tests that are part of this test suite
		struct test* current = first_test;
		while (current != NULL) {
			if (current->part_of_suite) {
				tests_ran++;
				counter += testit(current->name, current->func);
			}
			current = current->next;
		}
	}
	if (tests_ran == 0)
		fprintf(stderr, "***** No tests found *****\n");
	else {
		if (counter > 0) {
			fprintf(stderr, "***** There were %d failed (out of %d) test(s) *****\n", counter, tests_ran);
		} else {
			fprintf(stderr, "All %d tests passed\n", tests_ran);
		}
	}
	tear_down_test_collection();
	libp2p_logger_free();
	fclose(stdin);
	fclose(stdout);
	fclose(stderr);
	return 1;
}
