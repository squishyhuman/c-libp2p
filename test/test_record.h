#include <stdlib.h>

#include "libp2p/record/record.h"
#include "libp2p/record/message.h"
#include "libp2p/peer/peer.h"
#include "multiaddr/multiaddr.h"

int setval(char** result, size_t* result_size, char* in) {
	*result = malloc(strlen(in) + 1);
	if (*result == NULL)
		return 0;
	strcpy(*result, in);
	if (result_size != NULL)
		*result_size = strlen(in);
	return 1;
}

struct Libp2pRecord* test_record_create() {
	struct Libp2pRecord* record = libp2p_record_new();
	if (record != NULL) {
		setval(&record->key, &record->key_size, "Key");
		setval((char**)&record->value, &record->value_size, "Value");
		setval(&record->author, &record->author_size, "Author");
		setval((char**)&record->signature, &record->signature_size, "Signature");
		setval(&record->time_received, &record->time_received_size, "Time_Received");
	}
	return record;
}

int test_record_protobuf() {
	struct Libp2pRecord* record = test_record_create();
	struct Libp2pRecord* results = NULL;
	struct MultiAddress *ma = NULL, *ma_results = NULL;
	size_t protobuf_size = 0;
	char* protobuf = NULL;
	int retVal =  0;

	// protobuf, unprotobuf
	protobuf_size = libp2p_record_protobuf_encode_size(record);
	protobuf = (unsigned char*)malloc(protobuf_size);
	if (!libp2p_record_protobuf_encode(record, protobuf, protobuf_size, &protobuf_size))
		goto exit;

	if (!libp2p_record_protobuf_decode(protobuf, protobuf_size, &results))
		goto exit;

	if (record->key_size != results->key_size
			|| record->value_size != results->value_size
			|| record->author_size != results->author_size
			|| record->signature_size != results->signature_size
			|| record->time_received_size != results->time_received_size)
		goto exit;
	if (strcmp(record->key, results->key) != 0)
		goto exit;
	if (strncmp(record->value, results->value, results->value_size) != 0)
		goto exit;
	if (strncmp(record->author, results->author, results->author_size) != 0)
		goto exit;
	if (strncmp(record->signature, results->signature, results->signature_size) != 0)
		goto exit;
	if (strncmp(record->time_received, results->time_received, results->time_received_size) != 0)
		goto exit;

	retVal = 1;
	exit:
	if (protobuf != NULL)
		free (protobuf);
	libp2p_record_free(record);
	if (results != NULL)
		libp2p_record_free(results);
	return retVal;
}

int test_record_make_put_record() {
	int retVal = 0;
	char* protobuf = NULL;
	size_t protobuf_size = 0;
	struct RsaPrivateKey* rsa_private_key = NULL;
	struct RsaPublicKey rsa_public_key;
	char* record_key = "Record Key";
	unsigned char* record_value = (unsigned char*)"Record Value";
	size_t record_value_length = strlen((char*)record_value);
	struct Libp2pRecord* results = NULL;
	char* signature_buffer = NULL;
	size_t signature_buffer_length = 0;

	// generate keys

	rsa_public_key.der = NULL;
	rsa_public_key.der_length = 0;

	rsa_private_key = libp2p_crypto_rsa_rsa_private_key_new();
	if (rsa_private_key == NULL)
		goto exit;

	if (!libp2p_crypto_rsa_generate_keypair(rsa_private_key, 2048))
		goto exit;

	rsa_public_key.der = rsa_private_key->public_key_der;
	rsa_public_key.der_length = rsa_private_key->public_key_length;

	// sign and protobuf
	if (libp2p_record_make_put_record(&protobuf, &protobuf_size, rsa_private_key, record_key, record_value, record_value_length, 1) != 0)
		goto exit;

	// unprotobuf and test
	if (!libp2p_record_protobuf_decode(protobuf, protobuf_size, &results))
		goto exit;

	if (strcmp(record_key, results->key) != 0)
		goto exit;
	if (strncmp(record_value, results->value, results->value_size) != 0)
		goto exit;
	if (results->key_size != strlen(record_key)
			|| results->value_size != record_value_length)
		goto exit;

	// verify signature
	signature_buffer_length = results->key_size + results->value_size + results->author_size;
	signature_buffer = malloc(signature_buffer_length);
	strncpy(&signature_buffer[0], results->key, results->key_size);
	strncpy(&signature_buffer[results->key_size], results->value, results->value_size);
	strncpy(&signature_buffer[results->key_size + results->value_size], results->author, results->author_size);
	if (!libp2p_crypto_rsa_verify(&rsa_public_key, signature_buffer, signature_buffer_length, results->signature))
		goto exit;

	// cleanup
	retVal = 1;
	exit:

	if (signature_buffer != NULL)
		free(signature_buffer);
	if (protobuf != NULL)
		free(protobuf);
	if (results != NULL)
		libp2p_record_free(results);
	if (rsa_private_key != NULL)
		libp2p_crypto_rsa_rsa_private_key_free(rsa_private_key);

	return retVal;
}

int test_record_peer_protobuf() {
	struct Libp2pPeer* peer = NULL;
	struct MultiAddress* multi_addr1 = NULL;
	struct MultiAddress* multi_addr2 = NULL;
	int retVal = 0;
	unsigned char* protobuf = NULL;
	size_t protobuf_size = 0;
	struct Libp2pPeer* result = NULL;

	// make multiaddress
	multi_addr1 = multiaddress_new_from_string("/ip4/127.0.0.1/tcp/4001");

	// make peer
	peer = libp2p_peer_new();
	peer->connection_type = CONNECTION_TYPE_CAN_CONNECT;
	peer->id = malloc(7);
	strcpy(peer->id, "ABC123");
	peer->id_size = strlen(peer->id);
	peer->addr_head = libp2p_utils_linked_list_new();
	peer->addr_head->item = multi_addr1;

	// protobuf
	protobuf_size = libp2p_peer_protobuf_encode_size(peer);
	protobuf = (unsigned char*)malloc(protobuf_size);
	if (protobuf == NULL)
		goto exit;
	if (!libp2p_peer_protobuf_encode(peer, protobuf, protobuf_size, &protobuf_size))
		goto exit;

	// unprotobuf
	if (!libp2p_peer_protobuf_decode(protobuf, protobuf_size, &result))
		goto exit;

	// check results
	if (!strncmp(peer->id, result->id, peer->id_size) == 0)
		goto exit;

	if (peer->id_size != result->id_size
			|| peer->connection_type != result->connection_type)
		goto exit;

	// check multiaddress
	multi_addr2 = (struct MultiAddress*)result->addr_head->item;
	if (multi_addr1->bsize != multi_addr2->bsize)
		goto exit;
	if (strncmp(multi_addr1->bytes, multi_addr2->bytes, multi_addr2->bsize) != 0)
		goto exit;

	// cleanup
	retVal = 1;
	exit:
	if (peer != NULL) {
		libp2p_peer_free(peer);
		// above gets rid of below...
		multi_addr1 = NULL;
	}
	if (multi_addr1 != NULL)
		multiaddress_free(multi_addr1);
	if (protobuf != NULL)
		free(protobuf);
	if (result != NULL)
		libp2p_peer_free(result);
	return retVal;
}

int test_record_message_protobuf() {
	int retVal = 0;
	struct Libp2pPeer* closer_peer = NULL;
	struct Libp2pMessage* message = NULL;
	struct Libp2pMessage* result = NULL;
	struct MultiAddress *ma_result = NULL;
	char* buffer = NULL;
	size_t buffer_len = 0;

	// construct message
	closer_peer = libp2p_peer_new();
	closer_peer->connection_type = CONNECTION_TYPE_CAN_CONNECT;
	closer_peer->id = malloc(7);
	strcpy(closer_peer->id, "ABC123");
	closer_peer->id_size = strlen(closer_peer->id);
	closer_peer->addr_head = libp2p_utils_linked_list_new();
	closer_peer->addr_head->item = multiaddress_new_from_string("/ip4/127.0.0.1/tcp/4001/ipfs/QmW8CYQuoJhgfxTeNVFWktGFnTRzdUAimerSsHaE4rUXk8/");

	message = libp2p_message_new();
	message->closer_peer_head = libp2p_utils_linked_list_new();
	message->closer_peer_head->item = closer_peer;
	message->cluster_level_raw = 1;
	message->key = malloc(7);
	strcpy(message->key, "ABC123");
	message->key_size = 6;
	message->message_type = MESSAGE_TYPE_ADD_PROVIDER;
	message->record = test_record_create();

	// protobuf
	buffer_len = libp2p_message_protobuf_encode_size(message);
	buffer = malloc(buffer_len);
	if (!libp2p_message_protobuf_encode(message, buffer, buffer_len, &buffer_len))
		goto exit;

	// decode
	if (!libp2p_message_protobuf_decode(buffer, buffer_len, &result))
		goto exit;

	// check results
	if (result->cluster_level_raw != 1)
		goto exit;

	ma_result = ((struct Libp2pPeer*)result->closer_peer_head->item)->addr_head->item;

	if (strcmp(ma_result->string, ((struct MultiAddress*)closer_peer->addr_head->item)->string) != 0) {
		fprintf(stderr, "MultiAddress strings do not match\n");
		goto exit;
	}

	// cleanup
	retVal = 1;
	exit:
	if (message != NULL)
		libp2p_message_free(message);
	if (buffer != NULL)
		free(buffer);
	if (result != NULL)
		libp2p_message_free(result);
	return retVal;
}
