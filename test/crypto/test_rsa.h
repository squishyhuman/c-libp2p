#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libp2p/crypto/rsa.h"
#include "libp2p/crypto/encoding/base64.h"
#include "libp2p/crypto/encoding/x509.h"
#include "libp2p/crypto/peerutils.h"
#include "libp2p/crypto/key.h"

void free_private_key_ders(struct RsaPrivateKey* pk) {
	if (pk->der != NULL)
		free(pk->der);
	if (pk->public_key_der != NULL)
		free(pk->public_key_der);
}

/**
 * make sure we can get a DER formatted result
 */
int test_crypto_rsa_private_key_der() {
	int retVal = 0;
	struct RsaPrivateKey private_key;
	libp2p_crypto_rsa_generate_keypair(&private_key, 2048);
	
	if (private_key.der_length == 0)
		goto exit;
	if (private_key.der == NULL)
		goto exit;

	retVal = 1;
	exit:
	free_private_key_ders(&private_key);

	return retVal;
}

int test_crypto_x509_der_to_private2() {
	int retVal = 0;
	// this is an example private key. The type is not added. Therefore, it is not compatible with the go version
	char* der = "MIIEogIBAAKCAQEAmpDhRGecWN+MwfxW9UqsyEsZwnROHb2hCRBUATh7e0thgyi5Te6lT9x2++89x1sC7B9Egma1AJvY7BinIJYeFiOwzkKDe6/JxCle6TmLtCO1qmb8aGOIlu8NzO3L8EjcriYcgp0J5sZn5I3B4iU6q78u5jJQFpi2V7wsasanmfFwfF9ZUSxAnuwkcRkuhGnp5sBauHsQ4dn3IaiutiZDxPsAdxQyXX0SdrB4ew72UVAI2UsMAj5fRYy3plrsV/zZsGpeT6SDJI28weqOoSGvLzYaowf583MrH8O8dFoOWfXHq8hXy6qCDFOa7UYICCkb4QU9SLP7embmtfnB5/bVKwIDAQABAoIBADAwGwsIgmXyzB9uXG386gFH6LAHMpNzG1GIFaiLw3Oc/Lm3aI4zaLaNNUs2Ozx7011qIiHFg4i9DdQNm409QAQG/IhRlExrcawGeeCcYEG5IFoP4YFqBpuHy/Wn7XzsOmDQ4PKXow6frKREzb2Dfdcts6Fw7icdVTvlHrPrWzVS4azROsKy1spaCG7gYGd968f14Q2NBJmmlO75+dhjliI+cmMq5TaEvuCilXfSK4v6RWRGx+Mjl+ATSN1V7ksgzYsjNE15fdguxVWEIW5x5IsrpVviZdfGsDNWGsW9upoHoP118i2HKgrHRgbNcvTvWN/vCqJ/wDGz2FkYaa/3sYECgYEA9mBkSMW/Uc6m9/FNqlsEqCKLryI3ksxW9Ea6pHQ2p79gXYnlKuBLs7VdOA4XBIbV1vQdxjwJfojOdG7DmjklXYf+AYL/x26NSTszVV5feIIfR1jko67izBjeahPdizmpgQDFstgfdsc6vMKsbamvHzlZjpWeyanBz1t6OFPB8KUCgYEAoJpw2JB3o6ws4dASsSs4gthusY7e1Gcp0d7z8ZH0o8Rk2jxnQZuKHFUNnLY+qwxb6CP4zCpMMeGwuBVTapCE+7UkzUEk5GKmEgtO5G4Eu2yJFib1aGITlDnvxRkDOUGMSc/PVB5TnpdF9qXYbaJoLCziRzzgPJ9HWItnPuYudY8CgYB4mZZ9SM7t7IoutB+gVA1jgAWAJO+vG/c0e6rA9WILmtJA908GPeTQguaumbcKsDXckoJAlwLOvYjR1aZJx89SiU78znMF3EesoR3vm9J/2rIU6p6AwQqjfUjiA/deP0uJqicb9E7yhXNrEp/0ziq6zgfYk8S2UjJcnhqll9pHQQKBgGdoyfxHmSFD/Wowpbh6Edr+LNgbHBM7kcvWeNA0oIbKL/3tIrc1xUnU4fzjw5ozTQI+FzaujX0YysbcxGc7QsUnr9iRd4WulyvLKDMhO97KVcJzt1RMwjqQy3fnURIOyJvGOML6+/CDisLzqlV9WwIGrHQeGGwwSqoSqJnxcDy1AoGAMVmdK7mTMBtayUXRpthNCUmRAubaUKAjhKYm0j7ciPKWmo+mBHITbUshti07HqYeqxZE3LAIw/j0nowPsf4HIOxc69E+ZQqvETQwGyCwyHKJNYSFJi3tkHzCGEoP0/k9l6Fu8Qqcs1xhNQu8AcjQ1QL17rs/r9N44GKS2iXI+PY=";
	size_t b64_length = libp2p_crypto_encoding_base64_decode_size(strlen(der));
	unsigned char buffer[b64_length];
	unsigned char* b = buffer;
	size_t ultimate_length;
	if (!libp2p_crypto_encoding_base64_decode((unsigned char*)der, strlen(der), b, b64_length, &ultimate_length))
		goto exit;
	// we now have the bytes
	struct RsaPrivateKey private_key = {0};
	if (!libp2p_crypto_encoding_x509_der_to_private_key(b, ultimate_length, &private_key))
		goto exit;
	if (private_key.D <= 0)
		goto exit;

	retVal = 1;
	exit:
	free_private_key_ders(&private_key);
	return retVal;
}

int test_crypto_x509_der_to_private() {
	int retVal = 0;
	// this is a base64 encoded string from the go version of ipfs
	char* der = "CAASpwkwggSjAgEAAoIBAQDTDJBWjDzS/HxDNOHazvzH2bu9CPMVHUrrvKRdBUM5ansL6/CC3MVZ6HVm4O6QHRapN6EF2CbrTgI4KBOXIL125Xo8MlROnyfXYk3O5q2tgwL/MbW8kXjtkyCfBak7MUoLOdLU7Svg0gkl3l+uDAiDcCLnwJVcFfq9ch6z4wMOhYJqE5dtx0uXxn6IuKWl1B69FTvBXCc0thw8Rw54b941FDcsBH5ttV9mRNCJym3poZ5qalNgXlxoIIB+PUx5QD+aq7KMJdpAX8HkapBntCOahP/QUceRmma0grlZLeYkH6/oi/hIrM6se3KUZ+F6tBuDFys8UAZy/X2BCUbKjbxtAgMBAAECggEANWfQfpYuLhXGPBt9q6kFPm1SnJtPJ+CpvM2XqhJS2IyhZnrl+bd0GTRBwS7aL42s1lVFYf04nAK5fQxnKK8YQqX/MIxr2RldM5ukpN6qxGWKtJkXrAgD2dqJPrRoBpqKahzPxSHfIJ0Fw5dqDtjsrpYJvyt0oEDPmnDuZAbmFx4sJqnesPNhKxtRMBx1+yxGVuRVJjHcqAgqPqwNiuoMEaYMY+G9yzT6vza8ovCpbX7BBIgM5fAT9PD8TBG//Vu9THvj/ZomiVG2qv6RL0qQyVb+DUzPZz1amBsSvahtXCl72jA3JwAZ943RxSR66P934S0ashkVwLUi46z/EAbJ4QKBgQDojGIO07BEVL2+7VxlGL9XGZQp4Y3qlhh2zDDQGwkCq/KQ+BdNYWitPwqRl9GqFLgpmeQIhyHTOa/IThx+AXGKVQ24ROH+skUs4IbO6R3qY7BKtb5lkZE/Yln09x70BBngUYAzh/rtnsXO3cl1x2XDDqUbCwlGcDAs8Jh/6UnvQwKBgQDoVSQs7Uq9MJCGIUM2bixX89tHzSxq5mn9wMD3/XRVfT5Ua8YkYBuzcmlcT39N7L5BwuyFqX3Vi7lv/Ya/qaQP6XkrZ8W1OAaTlYewfE5ZgknJqSpXcNWhABKeNmqndvqyQ/8HNCv/j8AdraGB2DGO57Xso5J0CQ43W/U9+QIyjwKBgHLL2hw3o+wXaRO3WMUPUmVM2zdRgR0suybp5a7Vqb0H5NZrohUw4NulIzJ8H6Q2VjMzJL6Q9sGu2HepF6ecTtBa7ErqtiVlG4Dr1aCOs5XhYEWBMlwxX+JKSt4Cn+UVoTB7Cy5lEhn7JurX0Xuy0ylXMWoIKKv89cs5eg6quzTBAoGAaq9eEztLjKCWXOE9SetBdYnG8aunb9cqaJlwgu/h0bfXPVDYBbAUSEyLURY4MQI7Q1tM3Pu9iqfEmUZj7/LoIV5mg6X9RX/alT6etk3+dF+9nlqN1OU9U9cCtZ/rTcb2y5EptJcidRH/eCFY/pTV/PcttOJPx/S4kHcroC+N8MUCgYEA6DA5QHxHfNN6Nxv+pEzy2DIxFe9RrBxS+KPBsra1C8jgdeMf4EmfU0Nox92V0q0bRrD5ztqQwSONI0hSRb1iiMWR6MuFnAFajUJfASjjIlZ6nIQjQslI7vjlvYyyHS/p/Codxap+yJlTLWwVEOXp2D9pWwiMq1xEyf0TH1BosvM=";
	size_t b64_length = libp2p_crypto_encoding_base64_decode_size(strlen(der));
	unsigned char buffer[b64_length];
	unsigned char* b = buffer;
	size_t ultimate_length;
	if (!libp2p_crypto_encoding_base64_decode((unsigned char*)der, strlen(der), b, b64_length, &ultimate_length))
		goto exit;
	// we now have the bytes, but we must strip off the type (5 bytes)
	struct RsaPrivateKey* private_key = libp2p_crypto_rsa_rsa_private_key_new();
	int bytesToStrip = 5;
	if (!libp2p_crypto_encoding_x509_der_to_private_key(&b[bytesToStrip], ultimate_length-bytesToStrip, private_key))
		goto exit;
	retVal = private_key->D > 0;
	exit:
	libp2p_crypto_rsa_rsa_private_key_free(private_key);
	return retVal;
}

void printKey(unsigned char* in, size_t in_size) {
	for (int i = 0; i < in_size; i++) {
		fprintf(stdout, "%02x ", in[i]);
	}
	fprintf(stdout, "\n");
	return;
}

int test_public_der_to_private_der() {
	int retVal = 0;
	struct RsaPrivateKey private_key;
	size_t public_der_temp_length = 0;
	size_t public_der_temp_length2 = 0;

	if (!libp2p_crypto_rsa_generate_keypair(&private_key, 2048)) {
		fprintf(stderr, "Unable to generate keypair\n");
		return 0;
	}
	if (private_key.der_length == 0) {
		fprintf(stderr, "Private Key's DER length should not be zero\n");
		return 0;
	}
	if (private_key.der == NULL) {
		fprintf(stderr, "Private Key's DER should not be null\n");
		return 0;
	}

	// copy the public DER to a temporary area, then erase it, then try to generate it again.
	public_der_temp_length = private_key.public_key_length;
	unsigned char public_der_temp[private_key.public_key_length];
	memcpy(public_der_temp, private_key.public_key_der, private_key.public_key_length);

	free(private_key.public_key_der);
	private_key.public_key_length = 0;

	if (!libp2p_crypto_rsa_private_key_fill_public_key(&private_key)) {
		fprintf(stderr, "Fill_public_key returned FALSE\n");
		return 0;
	}

	if (public_der_temp_length != private_key.public_key_length) {
		fprintf(stderr, "Public key's lengths do not match\n");
		return 0;
	}

	public_der_temp_length2 = private_key.public_key_length;
	unsigned char public_der_temp2[public_der_temp_length2];
	memcpy(public_der_temp2, private_key.public_key_der, public_der_temp_length2);

	free(private_key.public_key_der);
	private_key.public_key_length = 0;

	if (!libp2p_crypto_rsa_private_key_fill_public_key(&private_key)) {
		fprintf(stderr, "Filling Public key 2 failed\n");
		return 0;
	}

	if (public_der_temp_length != public_der_temp_length2) {
		fprintf(stderr, "The 2 public key lengths do not match: %lu vs %lu\n", public_der_temp_length, public_der_temp_length2);
		return 0;
	}

	for(int i = 0; i < public_der_temp_length2; i++) {
		if ( ((unsigned char)private_key.public_key_der[i]) != public_der_temp2[i]) {
			fprintf(stderr, "Key mismatch at position %d. 1 is %02x and the other is %02x\n", i, private_key.public_key_der[i], public_der_temp2[i]);
			return 0;
		}
	}

	retVal = 1;
	exit:
	if (private_key.der != NULL)
		free(private_key.der);
	if (private_key.public_key_der != NULL)
		free(private_key.public_key_der);
	return retVal;
}

int test_crypto_rsa_public_key_to_peer_id() {
	int retVal = 0;
	struct RsaPrivateKey private_key = {0};
	char* final_id = NULL;
	// this is the base64 encoded private key from the config file
	//char* orig_priv_key = "CAASpwkwggSjAgEAAoIBAQDTDJBWjDzS/HxDNOHazvzH2bu9CPMVHUrrvKRdBUM5ansL6/CC3MVZ6HVm4O6QHRapN6EF2CbrTgI4KBOXIL125Xo8MlROnyfXYk3O5q2tgwL/MbW8kXjtkyCfBak7MUoLOdLU7Svg0gkl3l+uDAiDcCLnwJVcFfq9ch6z4wMOhYJqE5dtx0uXxn6IuKWl1B69FTvBXCc0thw8Rw54b941FDcsBH5ttV9mRNCJym3poZ5qalNgXlxoIIB+PUx5QD+aq7KMJdpAX8HkapBntCOahP/QUceRmma0grlZLeYkH6/oi/hIrM6se3KUZ+F6tBuDFys8UAZy/X2BCUbKjbxtAgMBAAECggEANWfQfpYuLhXGPBt9q6kFPm1SnJtPJ+CpvM2XqhJS2IyhZnrl+bd0GTRBwS7aL42s1lVFYf04nAK5fQxnKK8YQqX/MIxr2RldM5ukpN6qxGWKtJkXrAgD2dqJPrRoBpqKahzPxSHfIJ0Fw5dqDtjsrpYJvyt0oEDPmnDuZAbmFx4sJqnesPNhKxtRMBx1+yxGVuRVJjHcqAgqPqwNiuoMEaYMY+G9yzT6vza8ovCpbX7BBIgM5fAT9PD8TBG//Vu9THvj/ZomiVG2qv6RL0qQyVb+DUzPZz1amBsSvahtXCl72jA3JwAZ943RxSR66P934S0ashkVwLUi46z/EAbJ4QKBgQDojGIO07BEVL2+7VxlGL9XGZQp4Y3qlhh2zDDQGwkCq/KQ+BdNYWitPwqRl9GqFLgpmeQIhyHTOa/IThx+AXGKVQ24ROH+skUs4IbO6R3qY7BKtb5lkZE/Yln09x70BBngUYAzh/rtnsXO3cl1x2XDDqUbCwlGcDAs8Jh/6UnvQwKBgQDoVSQs7Uq9MJCGIUM2bixX89tHzSxq5mn9wMD3/XRVfT5Ua8YkYBuzcmlcT39N7L5BwuyFqX3Vi7lv/Ya/qaQP6XkrZ8W1OAaTlYewfE5ZgknJqSpXcNWhABKeNmqndvqyQ/8HNCv/j8AdraGB2DGO57Xso5J0CQ43W/U9+QIyjwKBgHLL2hw3o+wXaRO3WMUPUmVM2zdRgR0suybp5a7Vqb0H5NZrohUw4NulIzJ8H6Q2VjMzJL6Q9sGu2HepF6ecTtBa7ErqtiVlG4Dr1aCOs5XhYEWBMlwxX+JKSt4Cn+UVoTB7Cy5lEhn7JurX0Xuy0ylXMWoIKKv89cs5eg6quzTBAoGAaq9eEztLjKCWXOE9SetBdYnG8aunb9cqaJlwgu/h0bfXPVDYBbAUSEyLURY4MQI7Q1tM3Pu9iqfEmUZj7/LoIV5mg6X9RX/alT6etk3+dF+9nlqN1OU9U9cCtZ/rTcb2y5EptJcidRH/eCFY/pTV/PcttOJPx/S4kHcroC+N8MUCgYEA6DA5QHxHfNN6Nxv+pEzy2DIxFe9RrBxS+KPBsra1C8jgdeMf4EmfU0Nox92V0q0bRrD5ztqQwSONI0hSRb1iiMWR6MuFnAFajUJfASjjIlZ6nIQjQslI7vjlvYyyHS/p/Codxap+yJlTLWwVEOXp2D9pWwiMq1xEyf0TH1BosvM=";
	char* orig_priv_key = "CAASqgkwggSmAgEAAoIBAQD0a4RI+bF/ov7IVOGSJ8dQfnK1DwM0gwVuJAd+3LXxIZEPZzsKIKia0TojDbTdLvOJ23wsaojTF/4bSzBK5otdAz8YSgez4vTRUV5pUqvCkK0dSJJ1DHTdrFUwvzlXuKbwNbvWyzjmKfeaE9a9YLzhrUIUTRvKyqhZXr++vMy3hw4fdtGUTJWeiqmoIuJWIZ1748Ff6LjcP7TdG7OvY4q+U9ilEJYdF4aM+TJY193zKp0GNWohunuVrtOUnL9VQaSSDbvGdFS1Mg9iCN6kRBQTHVQvFzvuEw/Y2LvoPH3yFG1zj6bDLWfOBhegy/6Zi6fi4E1UfgJNFN1sjWF+gZoHAgMBAAECggEBALTqBD9zuoMsJYQo99IT6X7WKZeE5i1vMYzF1Fp9iZpS6ylIkrW7WLFHXs3lblMtVoxazn2d2WrOXoLbU4KNROhy57fVy//FZMqufMBetc3NAqYjOmyy7KnLzj7Hu+0HO2GflEq3n4UV2TTNrGv+d7BfawLV1FV1TcjgzfKjkq/gMDCTPMgfT7lcF4TGSqv6Pgudp8RRn/R7EKOx+I8/XkJsZWP3XJ0zj4ciqDmKrX2j7wZMT8CH/8wfyg4NGk1+TN4xBB2CXgulIWJg5yhzu+JgbGnHEL/Ga+i40XJe+RnlKDpjQ+ZFyrOkmHpIldasjWNGFeKwLjzrDQfyDRwex5ECgYEA+fFGJ+zbi2YJwHDO/44PmvcoCWpho0ah7y+O5/LEVROTYEoNRqodLet+z+LMKDq/o2qTNaYJLiDGMBZzhqyJIFR5ZJ5MhgLloY1gL8s0a7KMWDbh7giiWSu5zqhB3Du8Tom+8bYZUxOL4zhzCGrFitRqiEIIjy1/c5qyRQZaZx8CgYEA+lf6tdO6kKiAOxm7sdZ3rEl4UGFY+tEqgivKwurLRIor0XDfhCKr1hCfsZggpR8SMLfjCuNEgKbceofcKMa8OtyDbMPRz0mYNkCELTUYA+r8Ib/LvleQApMcLn+TDNwEnGlglSrrF33RVAUK+i/WfSXUvZRVpLQpRmdAqHjJeBkCgYEA0+Zz/iFXOGW32slJFWxRWqYz8VeZk52saGY/l/I/9Yj1J2tgugo7VtUS3BiB0ZGNK3SNfaxYmBz9KYO/Sew5DYnQqTdz1SHboQ2FAMAcnznutlNBVFdJnKPvkX8g5yBV05gApFgoPECUFn2jOP2coMjZ0M97Bjgil9YNUWvDdS0CgYEA4beFs3+tzVRAGgl/tD7dNBgiRMchBTSmkSuO6+PrVmcGTxboUSk5qg7fDa9Ob9LuAcMrENwNHbpVPJ1WoeVePewpC14bxDxk4zWUd3ZRquaqYnud5obor4mYdUxNd+DAv447qQNDaLDmlkzdsuqDB9+eSzh9Z72RIYtjPwN5E7ECgYEAsbqkMZXfK1tTRfduX+7KOlPMfcSr29X6nuDglcna4dHec6FAOzp3xL2722nnFt6gygc7pErrm0m0Wd/6BMTb4T3+GYwkDiMjM2CsTZYjpzrUri/VfRR509rScxHVR0/1PTFWN0K0+VZbEAyXDbbs4opq40tW0dWtcKxaNlimMw8=";
	// this is the peer id from the config file
	//char* orig_peer_id = "QmRskXriTSRjAftYX7QG1i1jAhouz5AHaLYZKNhEWRu5Fq";
	char* orig_peer_id = "QmbTyKkUuv6yaSpTuCFq1Ft6Q3g4wTtFJk1BLGMPRdAEP8";
	size_t orig_peer_id_size = strlen(orig_peer_id);
	// if we take the private key, retrieve the public key, hash it, we should come up with the peer id

	// 1) take the private key and turn it back into bytes (decode base 64)
	size_t decode_base64_size = libp2p_crypto_encoding_base64_decode_size(strlen(orig_priv_key));
	unsigned char decode_base64[decode_base64_size];
	memset(decode_base64, 0, decode_base64_size);
	unsigned char* ptr = decode_base64;

	if (!libp2p_crypto_encoding_base64_decode((unsigned char*)orig_priv_key, strlen(orig_priv_key), ptr, decode_base64_size, &decode_base64_size)) {
		goto exit;
	}

	// the first 5 bytes [0-4] are protobuf metadata before the DER encoded private key
	// byte 0 is "Tag 1 which is a varint"
	// byte 1 is the value of the varint
	// byte 2 is "Tag 2 which is a type 2, length delimited field"
	// bytes 3 & 4 is a varint with the value of 1191, which is the number of bytes that follow

	// 2) take the bytes of the private key and turn it back into a private key struct
	if (!libp2p_crypto_encoding_x509_der_to_private_key(&decode_base64[5], decode_base64_size - 5, &private_key))
		goto exit;

	// 2b) take the private key and fill in the public key DER
	if (!libp2p_crypto_rsa_private_key_fill_public_key(&private_key))
		goto exit;

	// 3) grab the public key, hash it, then base58 it
	struct PublicKey public_key;
	public_key.type = KEYTYPE_RSA;
	public_key.data_size = private_key.public_key_length;
	public_key.data = private_key.public_key_der;
	if (!libp2p_crypto_public_key_to_peer_id(&public_key, &final_id ))
		goto exit;

	// 4) compare results
	if (orig_peer_id_size != strlen(final_id))
		goto exit;

	if (strncmp(orig_peer_id, (char*)final_id, strlen(final_id)) != 0)
		goto exit;

	retVal = 1;
	exit:
	if (private_key.der != NULL)
		free(private_key.der);
	if (private_key.public_key_der != NULL)
		free(private_key.public_key_der);
	if (final_id != NULL)
		free(final_id);

	return retVal;
}

int test_crypto_rsa_signing() {
	// generate a public and private key pair
	struct RsaPrivateKey* private_key = libp2p_crypto_rsa_rsa_private_key_new();
	libp2p_crypto_rsa_generate_keypair(private_key, 2048);

	struct RsaPublicKey public_key;
	public_key.der = private_key->public_key_der;
	public_key.der_length = private_key->public_key_length;

	// generate some bytes to test with
	size_t num_bytes = 1000;
	unsigned char bytes[num_bytes];
	int val = 0;
	for (size_t i = 0; i < num_bytes; i++) {
		if (val > 255)
			val = 0;
		bytes[i] = val;
		val++;
	}

	unsigned char *result = NULL;
	size_t result_size;

	// sign the buffer
	if (libp2p_crypto_rsa_sign(private_key, bytes, num_bytes, &result, &result_size) == 0) {
		if (result != NULL)
			free(result);
		return 0;
	}

	// verify the signature
	if (libp2p_crypto_rsa_verify(&public_key, bytes, num_bytes, result) == 0) {
		free(result);
		return 0;
	}
	free(result);
	libp2p_crypto_rsa_rsa_private_key_free(private_key);

	return 1;
}
