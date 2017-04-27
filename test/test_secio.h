#include <stdlib.h>

#include "libp2p/secio/secio.h"
#include "libp2p/secio/exchange.h"
#include "libp2p/net/multistream.h"
#include "libp2p/net/p2pnet.h"
#include "libp2p/utils/logger.h"

int test_secio_handshake() {
	int retVal = 0;
	size_t decode_base64_size = 0;
	unsigned char* decode_base64 = NULL;
	// this is a base64 encoded private key. It makes it easier to test if it is in base64 form
	// these were pulled from the GO version of ipfs
	char* orig_priv_key = "CAASpwkwggSjAgEAAoIBAQCo+BYd213u8PNHNcnXZ6TcUc7oXEoCtWL12XJEFqAiC7emadkp+WtujmuR993L6uCRPU/+mNXIvetodMQ5GORq0MxsPlKFNuVuqHS4PCdWYYFKeel4QsG17T3XMo72Kxm7/pQ1Dbs6tzWD4Ie4Zsa7ziyffjeak1/EExkFf0AKtj4UdXErNRI5gZhkDnWp6Si117Z2VVTslE+kKXWpLK0RYZ4w8DhhZa+ykt2tleOOJt8ocJ3s3yVZQxOafL1lwA8f10VEEeJLPGKJ1Y7mmW7OJhLmrq9tvdTLhum1H5kdYu/pheCm5b6/NSGKS+XbQztu5zedsKSPHsOlYhxYu3GJAgMBAAECggEAZIz93Fam14Jbw4ymyKDM4q9sSapiAKqgcV0tOoecU6ZVa5qhuPDMlcX7DapLOwZTDRtHd2LMFeGvLUIPY0sE4uvOOrv7r3qznd5xVxG09xqfLgrOfNp9HB5KJr3XhXawocclu0yolpBgMFJ1ca73pNtUgrVBsaLx4mTbBwJqwfQpQb/Xdkrdgc663bwXkSl4vApwhZGzi5CFJ6SFC6l6fMKoteWM1ay5e2VCfxi/1g41EINkrqm+QPWhy11bo21ScozxiFiywcxQ8Huo+I5GDHI5EUfIHP97NSRG24/IDSebxsGTukMdpLmiiwizV7hHP2eDlikHAhxBBAF2GkbkAQKBgQDg69jPHrETvHGlKjlEDE8sYQUrwpmGLHfsfZYqBxcz65jPYFAypG4icIU6f8Uhz9c42jLEBssNPT8LyLl2uY467hZZA2SkeWKS66Vi5wBGTN5qOBWUejhzTx8UzasYroWl/0RqFZhU9Xhwg4YqT9X8jYw5mXyOMLatp/d/Y96p0QKBgQDAUQodQZc9yc7olsmNvbuHZtBA+VndKCokFOuJ6YLRK69AL7y6n6eUjne6JqcEIKDC7vr33ryuOdFI+zNzMsdYykE8xcg2c5itWRqG7EdMxgR1dYLUqGC5ustRM/mmhmRzW8DXy88sS+vM4U84yPKv/rfeKAoYgE722R0kkpQCOQKBgQCKfm63yiw6/NP1YXR1hCbUKsFmWqLxzTvisMngAxG0dKNZPfLj2/+80RAYH0ihMztQ1Hph3dT1x/qkJOqeQk9j1eqI0OANrniWAueJaLfwkbB6MyKGlGNiDRwUUTfDMOM2fWIA+F8eITASB8p7D0GyCu6HIQ1i+HfjogNxu2sFoQKBgE4ZGthiqH6JE6NUiKks4ZjM4clg+WNcSjC45iXtVBiJevO/7w6Cg1VKvcg0piKA9Yfz8Kr0Iv9Fr33JtU0U0+t0xyVc1D94lgnfY2xjS1kcGPdyLx0Y+56xApwJVVqQvP4zxo5bz9gXRLzAyqEuyY87C4QGEoN8p5SK+tC9TanRAoGAbC+uVaBtqRqv3LY16+H58BW8lVfN+8dqtBOWluM2uImB1qL2EbKk0X/OChz3Dgzef5VTox6nHcMyYPwXLirS9aIYPggjdpDTjfbWPxUcwYmIB1U++F/mRk1IeDgl9g7t/OlPMg4snxQGEzMPPDVrj/KeLEKv5x+T5yFZ/y+8xNo=";
	char* orig_peer_id = "QmZigcoDKaAafGSwot2tchJarCafxKapoRmnYTrZ69ckjb";
	size_t orig_peer_id_size = strlen(orig_peer_id);
	struct RsaPrivateKey* rsa_private_key = NULL;
	unsigned char hashed[32] = {0};
	size_t final_id_size = 1600;
	unsigned char final_id[final_id_size];

	struct PrivateKey* private_key = NULL;
	struct SessionContext secure_session = {0};

	// 1) take the private key and turn it back into bytes (decode base 64)
	decode_base64_size = libp2p_crypto_encoding_base64_decode_size(strlen(orig_priv_key));
	decode_base64 = (unsigned char*)malloc(decode_base64_size);
	memset(decode_base64, 0, decode_base64_size);

	if (!libp2p_crypto_encoding_base64_decode((unsigned char*)orig_priv_key, strlen(orig_priv_key), &decode_base64[0], decode_base64_size, &decode_base64_size))
		goto exit;

	if (!libp2p_crypto_private_key_protobuf_decode(decode_base64, decode_base64_size, &private_key))
		goto exit;

	// 2) take the bytes of the private key and turn it back into an RSA private key struct
	//TODO: should verify that this key is RSA
	rsa_private_key = libp2p_crypto_rsa_rsa_private_key_new();
	if (!libp2p_crypto_encoding_x509_der_to_private_key(private_key->data, private_key->data_size, rsa_private_key))
		goto exit;

	// 2b) take the private key and fill in the public key DER
	if (!libp2p_crypto_rsa_private_key_fill_public_key(rsa_private_key))
		goto exit;

	secure_session.host = "www.jmjatlanta.com";
	//secure_session.host = "127.0.0.1";
	secure_session.port = 4001;
	secure_session.traffic_type = TCP;
	// connect to host
	secure_session.insecure_stream = libp2p_net_multistream_connect(secure_session.host, secure_session.port);
	if (*((int*)secure_session.insecure_stream->socket_descriptor) == -1) {
		fprintf(stderr, "test_secio_handshake: Unable to get socket descriptor\n");
		goto exit;
	}


	if (!libp2p_secio_handshake(&secure_session, rsa_private_key, 0)) {
		fprintf(stderr, "test_secio_handshake: Unable to do handshake\n");
		goto exit;
	}

	retVal = 1;
	exit:
	if (secure_session.insecure_stream != NULL)
		libp2p_net_multistream_stream_free(secure_session.insecure_stream);
	if (secure_session.local_stretched_key != NULL)
		libp2p_crypto_ephemeral_stretched_key_free(secure_session.local_stretched_key);
	if (secure_session.remote_stretched_key != NULL)
		libp2p_crypto_ephemeral_stretched_key_free(secure_session.remote_stretched_key);
	if (secure_session.ephemeral_private_key != NULL)
		libp2p_crypto_ephemeral_key_free(secure_session.ephemeral_private_key);
	if (secure_session.remote_ephemeral_public_key != NULL)
		free(secure_session.remote_ephemeral_public_key);
	if (secure_session.chosen_cipher != NULL)
		free(secure_session.chosen_cipher);
	if (secure_session.chosen_curve != NULL)
		free(secure_session.chosen_curve);
	if (secure_session.chosen_hash != NULL)
		free(secure_session.chosen_hash);
	if (secure_session.shared_key != NULL)
		free(secure_session.shared_key);
	if (private_key != NULL)
		libp2p_crypto_private_key_free(private_key);
	if (decode_base64 != NULL)
		free(decode_base64);
	if (rsa_private_key != NULL)
		libp2p_crypto_rsa_rsa_private_key_free(rsa_private_key);
	return retVal;
}

int libp2p_secio_encrypt(const struct SessionContext* session, const unsigned char* incoming, size_t incoming_size, unsigned char** outgoing, size_t* outgoing_size);
int libp2p_secio_decrypt(const struct SessionContext* session, const unsigned char* incoming, size_t incoming_size, unsigned char** outgoing, size_t* outgoing_size);

int test_secio_encrypt_decrypt() {
	unsigned char* original = "This is a test message";
	int retVal = 0;
	unsigned char* encrypted = NULL;
	size_t encrypted_size = 0;
	unsigned char* results = NULL;
	size_t results_size = 0;
	struct SessionContext secure_session;
	struct StretchedKey stretched_key;

	secure_session.local_stretched_key = &stretched_key;
	secure_session.remote_stretched_key = &stretched_key;

	secure_session.local_stretched_key->cipher_key = (unsigned char*)"abcdefghijklmnopqrstuvwxyzabcdef";
	secure_session.local_stretched_key->cipher_size = 32;
	secure_session.local_stretched_key->mac_size = 40;
	secure_session.local_stretched_key->mac_key = "abcdefghijklmnopqrstuvwxyzabcdefghijklmn";
	secure_session.local_stretched_key->iv_size = 16;
	secure_session.local_stretched_key->iv = "abcdefghijklmnop";
	secure_session.mac_function = NULL;

	if (!libp2p_secio_encrypt(&secure_session, original, strlen((char*)original), &encrypted, &encrypted_size)) {
		fprintf(stderr, "Unable to encrypt\n");
		goto exit;
	}

	if (!libp2p_secio_decrypt(&secure_session, encrypted, encrypted_size, &results, &results_size)) {
		fprintf(stderr, "Unable to decrypt\n");
		goto exit;
	}

	if (results_size != strlen((char*)original)) {
		fprintf(stderr, "Results size are different. Results size = %lu and original is %lu\n", results_size, strlen((char*)original));
		goto exit;
	}

	if (strncmp(original, results, strlen( (char*) original)) != 0) {
		fprintf(stderr, "String comparison did not match\n");
		goto exit;
	}

	retVal = 1;
	exit:
	if (results != NULL)
		free(results);
	if (encrypted != NULL)
		free(encrypted);
	return retVal;
}

int test_secio_exchange_protobuf_encode() {
	char* protobuf = NULL;
	size_t protobuf_size = 0, actual_size = 0;
	struct Exchange* exch = libp2p_secio_exchange_new();
	int retVal = 0;

	exch->epubkey_size = 100;
	exch->epubkey = malloc(exch->epubkey_size);
	for(int i = 0; i < exch->epubkey_size; i++) {
		exch->epubkey[i] = i;
	}
	exch->signature_size = 32;
	exch->signature = malloc(exch->signature_size);
	for(int i = 0; i < exch->signature_size; i++) {
		exch->signature[i] = i;
	}

	protobuf_size = libp2p_secio_exchange_protobuf_encode_size(exch);
	protobuf = malloc(protobuf_size);

	libp2p_secio_exchange_protobuf_encode(exch, protobuf, protobuf_size, &actual_size);

	if (actual_size > protobuf_size)
		goto exit;

	retVal = 1;
	exit:
	free(protobuf);
	libp2p_secio_exchange_free(exch);
	return retVal;
}
