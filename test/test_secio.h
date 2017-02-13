#include <stdlib.h>

#include "libp2p/secio/secio.h"
#include "libp2p/net/multistream.h"


int test_secio_handshake() {
	int retVal = 0;
	size_t decode_base64_size = 0;
	unsigned char* decode_base64 = NULL;
	// this is a base64 encoded private key. It makes it easier to test if it is in base64 form
	// these were pulled from the GO version of ipfs
	char* orig_priv_key = "CAASpwkwggSjAgEAAoIBAQCwfp3DpbTP/nD1R+1PcP7nDOV9MEDiLUoNf9cBVhWGefJT0ES81do1COwLXiD/k7gAHJu197F7AfFYKt+NQu6jpCDC/uRtK0M0MpeDGI0LV1oz0rKLTN79zQwKDHFimWCmNyOZRLfR3PF5TgLc0qiFOZw9WwYNJkohu6k6yVMDJiy3l/+K5Vdw9VVyz7mRulXdDvEMxccraKaTvjLAUNFjiqm5Zs3hrcZszuuP2RhcpZU40kuWDtyN9TAEge0NfhS5Fj7GtgQsHWJ4RxTdebHkQmX49ltI/nIw9TxGIVcA50g7eF/3a3zZtkh48JadbHiT2Mfr6SPXl0328gyg7v7tAgMBAAECggEABGlFvCwaFtC/NgI0NjYWyOOToMth88U6AphdYVUreI73tYyRCz81EvpEHAygOoMQqEAOzD+CmhZ0V8XKjJdNq51gjD8eqnPYXCefjdFBRTVLtdvgRocHU8SaNm4VL2ex+LWMGDqVdZNWHbgLbkV9nMbR1t69ifqZA7rTAfsiLgPtneu4kGjrO1nr+uFC0srch2o0stmiqxmcGOrkD9x2kXkw33O8wTSyBp3+STlTOehePuUqEho9BXdT7b2nXC8MNdTCekG9f3oUeKsK9pxH7ZlG3yUOBoM0mEm/N7BrPfJnQbogomUapWOpssWKSz0LCpKuy4El3mFpua0jmd3nAQKBgQDWvVHj44gSecjsrWH/QpMIn8W/ISXfJRxJKrdVBRC5Ey0h3wdLnF6Olz4kuD7KurPOWNR+IKaLzOWxZdX79aQn+oY8lB+UCM+0w1TWJeSWBUYATPtUU4xpKdD6YZ8ksOdgZ4hbn9VD49uu/SJUPVNGV+eHibnvdR+/sFJuHTAb4QKBgQDSaBd1V7z5R6NK8373QNMDHZnSa2qH8uAGvoSuajYGgcpAzDY3aueQFpQS66scrZK6zLQyOQgtyrIg/hKbeP+vV5LGBirzOtAH7Kko5BYeY/SCXOkHBsHhuPGyghqWl6KR2Vj8cjJZFCAiUvoqf3Ws0vW58kp/KgDCnlKGmgQkjQKBgDPYi7/4vG6xhqhWCDYIDdXkNWs7BpjErfqgXJkjWvFERv5Jicpgm5fTvkZBUa/CugzU96DoIy3Xr5FQJATsPtEENIrFvIYSRou/KWl2xqTN6yPBcmDetyTg2rrI/RJvv71P4eU1RtlYVz79kN9D2yo9qQHZZ9H/tkWivZQmaeohAoGAIafa0L9HEAzAdvW6AmzRE/eBKmJaOQLFiO6ipI+CssnCA1lm9rhX7/lcmCYwSbcN+GlUDZCH2WNJ2PMrIMlbBL4aUSidaCipLAtUB6FsVFIiw1N/Rsty6ds+dhJPlHUO4QuGK2NM4GjStwrUz0VyGkHoYmT6O5sJYhgXFUa/kOUCgYEAv1VGeX6EPsFgp+FKM1Q/8MYi7PPpSUI2fqMhnwe36u7UdNYa3Ismmo/ipfCw7DdX5qRcUh44PodTp4Zwp67Bd2KRzEAZmMvIurzclQB7VWUT7pB7yfbO9bjBUVbPTagjiqb30zq9A4kt+B/0MSPxa/Kh8EkgI02Jqh2Q97Ij4sc=";
	char* orig_peer_id = "QmYm3WdMQqqQuEyCWmRVNEjtXjhGhyRRNshdvqV7YLGvpA";
	size_t orig_peer_id_size = strlen(orig_peer_id);
	struct RsaPrivateKey* rsa_private_key = NULL;
	unsigned char hashed[32] = {0};
	size_t final_id_size = 1600;
	unsigned char final_id[final_id_size];

	struct PrivateKey* private_key = NULL;
	struct SecureSession secure_session = {0};

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

	secure_session.host = "10.0.1.9";
	secure_session.port = 4001;
	secure_session.traffic_type = TCP;
	// connect to host
	secure_session.socket_descriptor = libp2p_net_multistream_connect(secure_session.host, secure_session.port);
	if (secure_session.socket_descriptor == -1) {
		fprintf(stderr, "test_secio_handshake: Unable to get socket descriptor\n");
		goto exit;
	}

	if (!libp2p_secio_handshake(&secure_session, rsa_private_key)) {
		fprintf(stderr, "test_secio_handshake: Unable to do handshake\n");
		goto exit;
	}

	retVal = 1;
	exit:
	if (secure_session.ephemeral_public_key != NULL)
		free(secure_session.ephemeral_public_key);
	if (secure_session.chosen_cipher != NULL)
		free(secure_session.chosen_cipher);
	if (secure_session.chosen_curve != NULL)
		free(secure_session.chosen_curve);
	if (secure_session.chosen_hash != NULL)
		free(secure_session.chosen_hash);
	if (private_key != NULL)
		libp2p_crypto_private_key_free(private_key);
	if (decode_base64 != NULL)
		free(decode_base64);
	if (rsa_private_key != NULL)
		libp2p_crypto_rsa_rsa_private_key_free(rsa_private_key);
	return retVal;
}
