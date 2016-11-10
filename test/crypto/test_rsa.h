//
//  test_rsa.h
//  libp2p_xcode
//
//  Created by John Jones on 11/3/16.
//  Copyright © 2016 JMJAtlanta. All rights reserved.
//

#ifndef test_rsa_h
#define test_rsa_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libp2p/crypto/rsa.h"
#include "libp2p/crypto/encoding/base64.h"
#include "libp2p/crypto/encoding/x509.h"

/**
 * make sure we can get a DER formatted result
 */
int test_crypto_rsa_private_key_der() {

	struct RsaPrivateKey private_key;
	libp2p_crypto_rsa_generate_keypair(&private_key, 2048);
	
	if (private_key.der_length == 0)
		return 0;
	if (private_key.der == NULL)
		return 0;
	return 1;
}

int test_crypto_x509_der_to_private2() {
	// this is an example private key. The type is not added. Therefore, it is not compatible with the go version
	char* der = "MIIEogIBAAKCAQEAmpDhRGecWN+MwfxW9UqsyEsZwnROHb2hCRBUATh7e0thgyi5Te6lT9x2++89x1sC7B9Egma1AJvY7BinIJYeFiOwzkKDe6/JxCle6TmLtCO1qmb8aGOIlu8NzO3L8EjcriYcgp0J5sZn5I3B4iU6q78u5jJQFpi2V7wsasanmfFwfF9ZUSxAnuwkcRkuhGnp5sBauHsQ4dn3IaiutiZDxPsAdxQyXX0SdrB4ew72UVAI2UsMAj5fRYy3plrsV/zZsGpeT6SDJI28weqOoSGvLzYaowf583MrH8O8dFoOWfXHq8hXy6qCDFOa7UYICCkb4QU9SLP7embmtfnB5/bVKwIDAQABAoIBADAwGwsIgmXyzB9uXG386gFH6LAHMpNzG1GIFaiLw3Oc/Lm3aI4zaLaNNUs2Ozx7011qIiHFg4i9DdQNm409QAQG/IhRlExrcawGeeCcYEG5IFoP4YFqBpuHy/Wn7XzsOmDQ4PKXow6frKREzb2Dfdcts6Fw7icdVTvlHrPrWzVS4azROsKy1spaCG7gYGd968f14Q2NBJmmlO75+dhjliI+cmMq5TaEvuCilXfSK4v6RWRGx+Mjl+ATSN1V7ksgzYsjNE15fdguxVWEIW5x5IsrpVviZdfGsDNWGsW9upoHoP118i2HKgrHRgbNcvTvWN/vCqJ/wDGz2FkYaa/3sYECgYEA9mBkSMW/Uc6m9/FNqlsEqCKLryI3ksxW9Ea6pHQ2p79gXYnlKuBLs7VdOA4XBIbV1vQdxjwJfojOdG7DmjklXYf+AYL/x26NSTszVV5feIIfR1jko67izBjeahPdizmpgQDFstgfdsc6vMKsbamvHzlZjpWeyanBz1t6OFPB8KUCgYEAoJpw2JB3o6ws4dASsSs4gthusY7e1Gcp0d7z8ZH0o8Rk2jxnQZuKHFUNnLY+qwxb6CP4zCpMMeGwuBVTapCE+7UkzUEk5GKmEgtO5G4Eu2yJFib1aGITlDnvxRkDOUGMSc/PVB5TnpdF9qXYbaJoLCziRzzgPJ9HWItnPuYudY8CgYB4mZZ9SM7t7IoutB+gVA1jgAWAJO+vG/c0e6rA9WILmtJA908GPeTQguaumbcKsDXckoJAlwLOvYjR1aZJx89SiU78znMF3EesoR3vm9J/2rIU6p6AwQqjfUjiA/deP0uJqicb9E7yhXNrEp/0ziq6zgfYk8S2UjJcnhqll9pHQQKBgGdoyfxHmSFD/Wowpbh6Edr+LNgbHBM7kcvWeNA0oIbKL/3tIrc1xUnU4fzjw5ozTQI+FzaujX0YysbcxGc7QsUnr9iRd4WulyvLKDMhO97KVcJzt1RMwjqQy3fnURIOyJvGOML6+/CDisLzqlV9WwIGrHQeGGwwSqoSqJnxcDy1AoGAMVmdK7mTMBtayUXRpthNCUmRAubaUKAjhKYm0j7ciPKWmo+mBHITbUshti07HqYeqxZE3LAIw/j0nowPsf4HIOxc69E+ZQqvETQwGyCwyHKJNYSFJi3tkHzCGEoP0/k9l6Fu8Qqcs1xhNQu8AcjQ1QL17rs/r9N44GKS2iXI+PY=";
	size_t b64_length = libp2p_crypto_encoding_base64_decode_length((unsigned char*)der, strlen(der));
	unsigned char buffer[b64_length];
	unsigned char* b = buffer;
	size_t ultimate_length;
	int retVal = libp2p_crypto_encoding_base64_decode((unsigned char*)der, strlen(der), b, b64_length, &ultimate_length);
	if (retVal == 0)
		return 0;
	// we now have the bytes
	struct RsaPrivateKey private_key = {0};
	retVal = libp2p_crypto_encoding_x509_der_to_private_key(b, ultimate_length, &private_key);
	if (retVal == 0)
		return 0;
	return private_key.D > 0;
}

int test_crypto_x509_der_to_private() {
	// this is a base64 encoded string from the go version of ipfs
	char* der = "CAASpwkwggSjAgEAAoIBAQDTDJBWjDzS/HxDNOHazvzH2bu9CPMVHUrrvKRdBUM5ansL6/CC3MVZ6HVm4O6QHRapN6EF2CbrTgI4KBOXIL125Xo8MlROnyfXYk3O5q2tgwL/MbW8kXjtkyCfBak7MUoLOdLU7Svg0gkl3l+uDAiDcCLnwJVcFfq9ch6z4wMOhYJqE5dtx0uXxn6IuKWl1B69FTvBXCc0thw8Rw54b941FDcsBH5ttV9mRNCJym3poZ5qalNgXlxoIIB+PUx5QD+aq7KMJdpAX8HkapBntCOahP/QUceRmma0grlZLeYkH6/oi/hIrM6se3KUZ+F6tBuDFys8UAZy/X2BCUbKjbxtAgMBAAECggEANWfQfpYuLhXGPBt9q6kFPm1SnJtPJ+CpvM2XqhJS2IyhZnrl+bd0GTRBwS7aL42s1lVFYf04nAK5fQxnKK8YQqX/MIxr2RldM5ukpN6qxGWKtJkXrAgD2dqJPrRoBpqKahzPxSHfIJ0Fw5dqDtjsrpYJvyt0oEDPmnDuZAbmFx4sJqnesPNhKxtRMBx1+yxGVuRVJjHcqAgqPqwNiuoMEaYMY+G9yzT6vza8ovCpbX7BBIgM5fAT9PD8TBG//Vu9THvj/ZomiVG2qv6RL0qQyVb+DUzPZz1amBsSvahtXCl72jA3JwAZ943RxSR66P934S0ashkVwLUi46z/EAbJ4QKBgQDojGIO07BEVL2+7VxlGL9XGZQp4Y3qlhh2zDDQGwkCq/KQ+BdNYWitPwqRl9GqFLgpmeQIhyHTOa/IThx+AXGKVQ24ROH+skUs4IbO6R3qY7BKtb5lkZE/Yln09x70BBngUYAzh/rtnsXO3cl1x2XDDqUbCwlGcDAs8Jh/6UnvQwKBgQDoVSQs7Uq9MJCGIUM2bixX89tHzSxq5mn9wMD3/XRVfT5Ua8YkYBuzcmlcT39N7L5BwuyFqX3Vi7lv/Ya/qaQP6XkrZ8W1OAaTlYewfE5ZgknJqSpXcNWhABKeNmqndvqyQ/8HNCv/j8AdraGB2DGO57Xso5J0CQ43W/U9+QIyjwKBgHLL2hw3o+wXaRO3WMUPUmVM2zdRgR0suybp5a7Vqb0H5NZrohUw4NulIzJ8H6Q2VjMzJL6Q9sGu2HepF6ecTtBa7ErqtiVlG4Dr1aCOs5XhYEWBMlwxX+JKSt4Cn+UVoTB7Cy5lEhn7JurX0Xuy0ylXMWoIKKv89cs5eg6quzTBAoGAaq9eEztLjKCWXOE9SetBdYnG8aunb9cqaJlwgu/h0bfXPVDYBbAUSEyLURY4MQI7Q1tM3Pu9iqfEmUZj7/LoIV5mg6X9RX/alT6etk3+dF+9nlqN1OU9U9cCtZ/rTcb2y5EptJcidRH/eCFY/pTV/PcttOJPx/S4kHcroC+N8MUCgYEA6DA5QHxHfNN6Nxv+pEzy2DIxFe9RrBxS+KPBsra1C8jgdeMf4EmfU0Nox92V0q0bRrD5ztqQwSONI0hSRb1iiMWR6MuFnAFajUJfASjjIlZ6nIQjQslI7vjlvYyyHS/p/Codxap+yJlTLWwVEOXp2D9pWwiMq1xEyf0TH1BosvM=";
	size_t b64_length = libp2p_crypto_encoding_base64_decode_length((unsigned char*)der, strlen(der));
	unsigned char buffer[b64_length];
	unsigned char* b = buffer;
	size_t ultimate_length;
	int retVal = libp2p_crypto_encoding_base64_decode((unsigned char*)der, strlen(der), b, b64_length, &ultimate_length);
	if (retVal == 0)
		return 0;
	// we now have the bytes, but we must strip off the type (5 bytes)
	struct RsaPrivateKey private_key = {0};
	int bytesToStrip = 5;
	retVal = libp2p_crypto_encoding_x509_der_to_private_key(&b[bytesToStrip], ultimate_length-bytesToStrip, &private_key);
	if (retVal == 0)
		return 0;
	return private_key.D > 0;
}



#endif /* test_rsa_h */
