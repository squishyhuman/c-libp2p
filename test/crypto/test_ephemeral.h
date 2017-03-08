#include <stdlib.h>

#include "libp2p/crypto/ephemeral.h"
/**
 * Try to generate an ephemeral private key
 */
int test_ephemeral_key_generate() {
	int retVal = 0;
	struct EphemeralPrivateKey* private_key;

	if (!libp2p_crypto_ephemeral_keypair_generate("P-256", &private_key))
		goto exit;

	if (private_key->secret_key <= 0 || private_key->public_key->x <= 0 || private_key->public_key->y <= 0)
		goto exit;

	retVal = 1;
	exit:
	libp2p_crypto_ephemeral_key_free(private_key);
	return retVal;
}

/**
 * RSA Sign an ephemeral public key
 */
int test_ephemeral_key_sign() {
	int retVal = 0;
	struct EphemeralPrivateKey* e_private_key;
	char* orig_priv_key = "CAASpwkwggSjAgEAAoIBAQCo+BYd213u8PNHNcnXZ6TcUc7oXEoCtWL12XJEFqAiC7emadkp+WtujmuR993L6uCRPU/+mNXIvetodMQ5GORq0MxsPlKFNuVuqHS4PCdWYYFKeel4QsG17T3XMo72Kxm7/pQ1Dbs6tzWD4Ie4Zsa7ziyffjeak1/EExkFf0AKtj4UdXErNRI5gZhkDnWp6Si117Z2VVTslE+kKXWpLK0RYZ4w8DhhZa+ykt2tleOOJt8ocJ3s3yVZQxOafL1lwA8f10VEEeJLPGKJ1Y7mmW7OJhLmrq9tvdTLhum1H5kdYu/pheCm5b6/NSGKS+XbQztu5zedsKSPHsOlYhxYu3GJAgMBAAECggEAZIz93Fam14Jbw4ymyKDM4q9sSapiAKqgcV0tOoecU6ZVa5qhuPDMlcX7DapLOwZTDRtHd2LMFeGvLUIPY0sE4uvOOrv7r3qznd5xVxG09xqfLgrOfNp9HB5KJr3XhXawocclu0yolpBgMFJ1ca73pNtUgrVBsaLx4mTbBwJqwfQpQb/Xdkrdgc663bwXkSl4vApwhZGzi5CFJ6SFC6l6fMKoteWM1ay5e2VCfxi/1g41EINkrqm+QPWhy11bo21ScozxiFiywcxQ8Huo+I5GDHI5EUfIHP97NSRG24/IDSebxsGTukMdpLmiiwizV7hHP2eDlikHAhxBBAF2GkbkAQKBgQDg69jPHrETvHGlKjlEDE8sYQUrwpmGLHfsfZYqBxcz65jPYFAypG4icIU6f8Uhz9c42jLEBssNPT8LyLl2uY467hZZA2SkeWKS66Vi5wBGTN5qOBWUejhzTx8UzasYroWl/0RqFZhU9Xhwg4YqT9X8jYw5mXyOMLatp/d/Y96p0QKBgQDAUQodQZc9yc7olsmNvbuHZtBA+VndKCokFOuJ6YLRK69AL7y6n6eUjne6JqcEIKDC7vr33ryuOdFI+zNzMsdYykE8xcg2c5itWRqG7EdMxgR1dYLUqGC5ustRM/mmhmRzW8DXy88sS+vM4U84yPKv/rfeKAoYgE722R0kkpQCOQKBgQCKfm63yiw6/NP1YXR1hCbUKsFmWqLxzTvisMngAxG0dKNZPfLj2/+80RAYH0ihMztQ1Hph3dT1x/qkJOqeQk9j1eqI0OANrniWAueJaLfwkbB6MyKGlGNiDRwUUTfDMOM2fWIA+F8eITASB8p7D0GyCu6HIQ1i+HfjogNxu2sFoQKBgE4ZGthiqH6JE6NUiKks4ZjM4clg+WNcSjC45iXtVBiJevO/7w6Cg1VKvcg0piKA9Yfz8Kr0Iv9Fr33JtU0U0+t0xyVc1D94lgnfY2xjS1kcGPdyLx0Y+56xApwJVVqQvP4zxo5bz9gXRLzAyqEuyY87C4QGEoN8p5SK+tC9TanRAoGAbC+uVaBtqRqv3LY16+H58BW8lVfN+8dqtBOWluM2uImB1qL2EbKk0X/OChz3Dgzef5VTox6nHcMyYPwXLirS9aIYPggjdpDTjfbWPxUcwYmIB1U++F/mRk1IeDgl9g7t/OlPMg4snxQGEzMPPDVrj/KeLEKv5x+T5yFZ/y+8xNo=";
	char* orig_peer_id = "QmZigcoDKaAafGSwot2tchJarCafxKapoRmnYTrZ69ckjb";
	struct RsaPrivateKey* rsa_private_key = NULL;
	size_t decode_base64_size = 0;
	unsigned char* decode_base64 = NULL;
	unsigned char* result;
	size_t result_size;

	// build the RSA key

	struct PrivateKey* r_private_key = NULL;

	// 1) take the private key and turn it back into bytes (decode base 64)
	decode_base64_size = libp2p_crypto_encoding_base64_decode_size(strlen(orig_priv_key));
	decode_base64 = (unsigned char*)malloc(decode_base64_size);
	memset(decode_base64, 0, decode_base64_size);

	if (!libp2p_crypto_encoding_base64_decode((unsigned char*)orig_priv_key, strlen(orig_priv_key), &decode_base64[0], decode_base64_size, &decode_base64_size))
		goto exit;

	if (!libp2p_crypto_private_key_protobuf_decode(decode_base64, decode_base64_size, &r_private_key))
		goto exit;

	// 2) take the bytes of the private key and turn it back into an RSA private key struct
	//TODO: should verify that this key is RSA
	rsa_private_key = libp2p_crypto_rsa_rsa_private_key_new();
	if (!libp2p_crypto_encoding_x509_der_to_private_key(r_private_key->data, r_private_key->data_size, rsa_private_key))
		goto exit;

	// 2b) take the private key and fill in the public key DER
	if (!libp2p_crypto_rsa_private_key_fill_public_key(rsa_private_key))
		goto exit;


	if (!libp2p_crypto_ephemeral_keypair_generate("P-256", &e_private_key))
		goto exit;

	// print the ephemeral public key bytes
	fprintf(stdout, "Public Key Bytes: ");
	for(int i = 0; i < e_private_key->public_key->bytes_size; i++) {
		fprintf(stdout, "%02x", e_private_key->public_key->bytes[i]);
	}
	fprintf(stdout, "\n");

	// attempt to sign
	libp2p_crypto_rsa_sign(rsa_private_key, e_private_key->public_key->bytes, e_private_key->public_key->bytes_size, &result, &result_size);

	retVal = 1;
	exit:
	libp2p_crypto_ephemeral_key_free(e_private_key);
	if (result != NULL)
		free(result);
	libp2p_crypto_rsa_rsa_private_key_free(rsa_private_key);
	if (decode_base64 != NULL)
		free(decode_base64);
	if (r_private_key != NULL)
		libp2p_crypto_private_key_free(r_private_key);
	return retVal;
}
