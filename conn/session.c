#include <stdlib.h>
#include <string.h>
#include "multiaddr/multiaddr.h"
#include "libp2p/conn/session.h"
#include "libp2p/net/stream.h"

struct SessionContext* libp2p_session_context_new() {
	struct SessionContext* context = (struct SessionContext*) malloc(sizeof(struct SessionContext));
	if (context != NULL) {
		context->aes_decode_nonce_offset = 0;
		memset(&context->aes_decode_stream_block[0], 0, 16);
		context->aes_encode_nonce_offset = 0;
		memset(&context->aes_encode_stream_block[0], 0, 16);
		context->chosen_cipher = NULL;
		context->chosen_curve = NULL;
		context->chosen_hash = NULL;
		context->datastore = NULL;
		context->default_stream = NULL;
		context->ephemeral_private_key = NULL;
		context->filestore = NULL;
		context->host = NULL;
		context->insecure_stream = NULL;
		memset(&context->local_nonce[0], 0, 16);
		context->local_stretched_key = NULL;
		context->mac_function = NULL;
		context->port = 0;
		context->remote_ephemeral_public_key = NULL;
		context->remote_ephemeral_public_key_size = 0;
		context->remote_key.data_size = 0;
		context->remote_key.data = NULL;
		context->remote_key.type = KEYTYPE_INVALID;
		memset(&context->remote_nonce[0], 0, 16);
		context->remote_peer_id = NULL;
		context->remote_stretched_key = NULL;
		context->secure_stream = NULL;
		context->shared_key = NULL;
		context->shared_key_size = 0;
		context->traffic_type = TCP;
	}
	return context;
}

int libp2p_session_context_free(struct SessionContext* context) {
	if (context != NULL) {
		if (context->default_stream != NULL)
			context->default_stream->close(context);
		context->default_stream = NULL;
		context->insecure_stream = NULL;
		context->secure_stream = NULL;
		free(context);
	}
	return 1;
}

int libp2p_session_context_compare_streams(const struct Stream* a, const struct Stream* b) {
	if (a == NULL && b == NULL)
		return 0;
	if (a == NULL && b != NULL)
		return -1;
	if (a != NULL && b == NULL)
		return 1;
	return multiaddress_compare(a->address, b->address);
}

int libp2p_session_context_compare_remote_key(const struct PublicKey* a, const struct PublicKey* b) {
	if (a == NULL && b == NULL)
		return 0;
	if (a == NULL && b != NULL)
		return -1;
	if (a != NULL && b == NULL)
		return 1;
	int total = b->data_size - a->data_size;
	if (total != 0)
		return total;
	for(size_t i = 0; i < b->data_size; i++) {
		total = b->data[i] - a->data[i];
		if (total != 0)
			return total;
	}
	return 0;
}

int libp2p_session_context_compare(const struct SessionContext* a, const struct SessionContext* b) {
	int total = 0;
	if (a == NULL && b == NULL)
		return 0;
	if (a == NULL && b != NULL)
		return -1;
	if (a != NULL && b == NULL)
		return 1;
	// streams
	total = libp2p_session_context_compare_streams(a->default_stream, b->default_stream);
	if (total != 0)
		return total;
	// remote key
	total = libp2p_session_context_compare_remote_key(&a->remote_key, &b->remote_key);
	return total;
}
