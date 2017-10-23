#include <stdlib.h>
#include <string.h>
#include "multiaddr/multiaddr.h"
#include "libp2p/crypto/ephemeral.h"
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
		context->last_comm_epoch = 0;
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
		if (context->chosen_cipher != NULL) {
			free(context->chosen_cipher);
			context->chosen_cipher = NULL;
		}
		if (context->chosen_curve != NULL) {
			free(context->chosen_curve);
			context->chosen_curve = NULL;
		}
		if (context->chosen_hash != NULL) {
			free(context->chosen_hash);
			context->chosen_hash = NULL;
		}
		if (context->shared_key != NULL) {
			free(context->shared_key);
			context->shared_key = NULL;
		}
		if (context->remote_peer_id != NULL) {
			free(context->remote_peer_id);
			context->remote_peer_id = NULL;
		}
		if (context->remote_ephemeral_public_key != NULL) {
			free(context->remote_ephemeral_public_key);
			context->remote_ephemeral_public_key = NULL;
		}
		if (context->local_stretched_key != NULL) {
			libp2p_crypto_ephemeral_stretched_key_free(context->local_stretched_key);
			context->local_stretched_key = NULL;
		}
		if (context->remote_stretched_key != NULL) {
			libp2p_crypto_ephemeral_stretched_key_free(context->remote_stretched_key);
			context->remote_stretched_key = NULL;
		}
		if (context->ephemeral_private_key != NULL) {
			libp2p_crypto_ephemeral_key_free(context->ephemeral_private_key);
			context->ephemeral_private_key = NULL;
		}
		free(context);
	}
	return 1;
}

/***
 * Attempt to lock a stream for personal use. Does not block.
 * @param stream the stream to lock
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_stream_try_lock(struct Stream* stream) {
	if (stream == NULL)
		return 0;
	if (pthread_mutex_trylock(stream->socket_mutex) == 0)
		return 1;
	return 0;
}

/***
 * Attempt to lock a stream for personal use. Blocks until the lock is acquired
 * @param stream the stream to lock
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_stream_lock(struct Stream* stream) {
	if (stream == NULL)
		return 0;
	if (pthread_mutex_lock(stream->socket_mutex) == 0)
		return 1;
	return 0;
}

/***
 * Attempt to unlock the mutex for this stream
 * @param stream the stream to unlock
 * @returns true(1) on success, false(0) otherwise
 */
int libp2p_stream_unlock(struct Stream* stream) {
	if (stream == NULL)
		return 0;
	if (pthread_mutex_unlock(stream->socket_mutex) == 0)
		return 1;
	return 0;
}

/***
 * Create a new StreamMessage struct
 * @returns a StreamMessage struct
 */
struct StreamMessage* libp2p_stream_message_new() {
	struct StreamMessage* out = (struct StreamMessage*) malloc(sizeof(struct StreamMessage));
	if (out != NULL) {
		out->data = NULL;
		out->data_size = 0;
		out->error_number = 0;
	}
	return out;
}

/**
 * free resources of a StreamMessage struct
 * @param msg the StreamMessage to free
 */
void libp2p_stream_message_free(struct StreamMessage* msg) {
	if (msg != NULL) {
		if (msg->data != NULL) {
			free(msg->data);
			msg->data = NULL;
		}
		free(msg);
		msg = NULL;
	}
}

/****
 * Make a copy of a SessionContext
 * @param original the original
 * @returns a copy of the original, or NULL on error
 */
struct SessionContext* libp2p_session_context_copy(const struct SessionContext* original) {
	struct SessionContext* new_ctx = libp2p_session_context_new();
	if (new_ctx != NULL) {
		new_ctx->aes_decode_nonce_offset = original->aes_decode_nonce_offset;
		memcpy(new_ctx->aes_decode_stream_block, original->aes_decode_stream_block, 16);
		new_ctx->aes_encode_nonce_offset = original->aes_encode_nonce_offset;
		memcpy(new_ctx->aes_encode_stream_block, original->aes_encode_stream_block, 16);
		new_ctx->chosen_cipher = (char*) malloc(strlen(original->chosen_cipher) + 1);
		strcpy(new_ctx->chosen_cipher, original->chosen_cipher);
		new_ctx->chosen_curve = (char*) malloc(strlen(original->chosen_curve) + 1);
		strcpy(new_ctx->chosen_curve, original->chosen_curve);
		new_ctx->chosen_hash = (char*) malloc(strlen(original->chosen_hash) + 1);
		strcpy(new_ctx->chosen_hash, original->chosen_hash);
		// TODO: Copy everything else
	}
	return new_ctx;
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

