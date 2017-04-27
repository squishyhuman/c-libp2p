#include <stdio.h>

#include "libp2p/crypto/key.h"


int test_protobuf_private_key() {
	int retVal = 0;
	size_t decode_base64_size = 0;
	unsigned char* decode_base64;
	// this is a base64 encoded private key. It makes it easier to test if it is in base64 form
	// these were pulled from the GO version of ipfs
	char* orig_priv_key = "CAASqgkwggSmAgEAAoIBAQD0a4RI+bF/ov7IVOGSJ8dQfnK1DwM0gwVuJAd+3LXxIZEPZzsKIKia0TojDbTdLvOJ23wsaojTF/4bSzBK5otdAz8YSgez4vTRUV5pUqvCkK0dSJJ1DHTdrFUwvzlXuKbwNbvWyzjmKfeaE9a9YLzhrUIUTRvKyqhZXr++vMy3hw4fdtGUTJWeiqmoIuJWIZ1748Ff6LjcP7TdG7OvY4q+U9ilEJYdF4aM+TJY193zKp0GNWohunuVrtOUnL9VQaSSDbvGdFS1Mg9iCN6kRBQTHVQvFzvuEw/Y2LvoPH3yFG1zj6bDLWfOBhegy/6Zi6fi4E1UfgJNFN1sjWF+gZoHAgMBAAECggEBALTqBD9zuoMsJYQo99IT6X7WKZeE5i1vMYzF1Fp9iZpS6ylIkrW7WLFHXs3lblMtVoxazn2d2WrOXoLbU4KNROhy57fVy//FZMqufMBetc3NAqYjOmyy7KnLzj7Hu+0HO2GflEq3n4UV2TTNrGv+d7BfawLV1FV1TcjgzfKjkq/gMDCTPMgfT7lcF4TGSqv6Pgudp8RRn/R7EKOx+I8/XkJsZWP3XJ0zj4ciqDmKrX2j7wZMT8CH/8wfyg4NGk1+TN4xBB2CXgulIWJg5yhzu+JgbGnHEL/Ga+i40XJe+RnlKDpjQ+ZFyrOkmHpIldasjWNGFeKwLjzrDQfyDRwex5ECgYEA+fFGJ+zbi2YJwHDO/44PmvcoCWpho0ah7y+O5/LEVROTYEoNRqodLet+z+LMKDq/o2qTNaYJLiDGMBZzhqyJIFR5ZJ5MhgLloY1gL8s0a7KMWDbh7giiWSu5zqhB3Du8Tom+8bYZUxOL4zhzCGrFitRqiEIIjy1/c5qyRQZaZx8CgYEA+lf6tdO6kKiAOxm7sdZ3rEl4UGFY+tEqgivKwurLRIor0XDfhCKr1hCfsZggpR8SMLfjCuNEgKbceofcKMa8OtyDbMPRz0mYNkCELTUYA+r8Ib/LvleQApMcLn+TDNwEnGlglSrrF33RVAUK+i/WfSXUvZRVpLQpRmdAqHjJeBkCgYEA0+Zz/iFXOGW32slJFWxRWqYz8VeZk52saGY/l/I/9Yj1J2tgugo7VtUS3BiB0ZGNK3SNfaxYmBz9KYO/Sew5DYnQqTdz1SHboQ2FAMAcnznutlNBVFdJnKPvkX8g5yBV05gApFgoPECUFn2jOP2coMjZ0M97Bjgil9YNUWvDdS0CgYEA4beFs3+tzVRAGgl/tD7dNBgiRMchBTSmkSuO6+PrVmcGTxboUSk5qg7fDa9Ob9LuAcMrENwNHbpVPJ1WoeVePewpC14bxDxk4zWUd3ZRquaqYnud5obor4mYdUxNd+DAv447qQNDaLDmlkzdsuqDB9+eSzh9Z72RIYtjPwN5E7ECgYEAsbqkMZXfK1tTRfduX+7KOlPMfcSr29X6nuDglcna4dHec6FAOzp3xL2722nnFt6gygc7pErrm0m0Wd/6BMTb4T3+GYwkDiMjM2CsTZYjpzrUri/VfRR509rScxHVR0/1PTFWN0K0+VZbEAyXDbbs4opq40tW0dWtcKxaNlimMw8=";
	struct PrivateKey* private_key = NULL;
	struct RsaPrivateKey rsa_private_key = {0};
	char* orig_peer_id = "QmbTyKkUuv6yaSpTuCFq1Ft6Q3g4wTtFJk1BLGMPRdAEP8";
	size_t orig_peer_id_size = strlen(orig_peer_id);
	unsigned char hashed[32];
	unsigned char *final_id;


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
	if (!libp2p_crypto_encoding_x509_der_to_private_key(private_key->data, private_key->data_size, &rsa_private_key))
		goto exit;

	// 2b) take the private key and fill in the public key DER
	if (!libp2p_crypto_rsa_private_key_fill_public_key(&rsa_private_key))
		goto exit;

	// 3) grab the public key, hash it, then base58 it
	struct PublicKey public_key;
	public_key.type = KEYTYPE_RSA;
	public_key.data_size = rsa_private_key.public_key_length;
	public_key.data = rsa_private_key.public_key_der;
	if (!libp2p_crypto_public_key_to_peer_id(&public_key, (char**)&final_id ))
		goto exit;

	// 4) compare results
	if (orig_peer_id_size != strlen((char*)final_id))
		goto exit;

	if (strncmp(orig_peer_id, (char*)final_id, strlen(final_id)) != 0)
		goto exit;

	retVal = 1;
	exit:
	if (decode_base64 != NULL)
		free(decode_base64);
	if (private_key != NULL)
		libp2p_crypto_private_key_free(private_key);
	if (rsa_private_key.der != NULL)
		free(rsa_private_key.der);
	if (rsa_private_key.public_key_der != NULL)
		free(rsa_private_key.public_key_der);
	if (final_id != NULL)
		free(final_id);
	return retVal;
}
