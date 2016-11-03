//
//  rsa.h
//  c-libp2p
//
//  Created by John Jones on 11/3/16.
//  Copyright © 2016 JMJAtlanta. All rights reserved.
//

#ifndef rsa_h
#define rsa_h

struct RsaPublicKey {
	unsigned long long modulus;
	unsigned long long exponent;
};

struct CRTValue {
	unsigned long long exponent;
	unsigned long long coefficient;
	unsigned long long r;
};

struct PrecomputedValues {
	unsigned long long dp;
	unsigned long long dq;
	unsigned long long q_inv;
	struct CRTValue** crt_values;
};

struct RsaPrivateKey {
	struct RsaPublicKey public_key;
	unsigned long long private_exponent;
	unsigned long long prime1;
	unsigned long long prime2;
	struct PrecomputedValues precomputed_values;
};

/**
 * generate a new private key
 * @param private_key the new private key
 * @param num_bits_for_keypair the size of the key (1024 minimum)
 * @returns true(1) on success
 */
int crypto_rsa_generate_keypair(struct RsaPrivateKey* private_key, unsigned long num_bits_for_keypair);


#endif /* rsa_h */
