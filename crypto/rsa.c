//
//  rsa.c
//  c-libp2p
//
//  Created by John Jones on 11/3/16.
//  Copyright © 2016 JMJAtlanta. All rights reserved.
//

#include <stdio.h>
#include <string.h>

#include "libp2p/crypto/rsa.h"

// mbedtls stuff
#include "mbedtls/config.h"
#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"
#include "mbedtls/x509.h"
#include "mbedtls/rsa.h"
#include "mbedtls/asn1write.h"

/**
 * Take an rsa context and turn it into a der formatted byte stream.
 * NOTE: the stream starts from the right. So there could be a lot of padding in front.
 * Pay attention to the returned size to cut the padding.
 * @param rsa the rsa key to encode
 * @param buf where to put the bytes
 * @param size the max size of the buffer. The actual size used is returned in this value
 * @returns true(1) on success, else 0
 */
int libp2p_crypto_rsa_write_key_der( mbedtls_rsa_context *rsa, unsigned char *buf, size_t* size )
{
    int ret;
    unsigned char *c = buf + *size;
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->QP ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->DQ ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->DP ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->Q ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->P ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->D ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->E ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->N ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_int( &c, buf, 0 ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ) );

    *size = len;
    return 1;
}

/***
 * Generate an RSA keypair of a certain size, and place the results in the struct
 * @param private_key where to put the results
 * @param num_bits_for_keypair the number of bits for the key, 1024 is the minimum
 * @returns true(1) on success
 */
int crypto_rsa_generate_keypair(struct RsaPrivateKey* private_key, unsigned long num_bits_for_keypair) {
	
	mbedtls_rsa_context rsa;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	
	int exponent = 65537;
	int retVal = 1;
	
	unsigned char* buffer;

	const char *pers = "rsa_genkey";
	
	// initialize mbedtls structs
	mbedtls_ctr_drbg_init( &ctr_drbg );
	mbedtls_entropy_init( &entropy );
	
	// seed the routines
	if( ( retVal = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
									  (const unsigned char *) pers,
									  strlen( pers ) ) ) != 0 )
	{
		retVal = 0;
		goto exit;
	}
	
	// initialize the rsa struct
	mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
	
	// finally, generate the key
	if( ( retVal = mbedtls_rsa_gen_key( &rsa, mbedtls_ctr_drbg_random, &ctr_drbg, (unsigned int)num_bits_for_keypair,
									   exponent ) ) != 0 )
	{
		retVal = 0;
		goto exit;
	}
	retVal = 1;
	
	// fill in values of structures
	private_key->D = *(rsa.D.p);
	private_key->DP = *(rsa.DP.p);
	private_key->DQ = *(rsa.DQ.p);
	private_key->E = *(rsa.E.p);
	private_key->N = *(rsa.N.p);
	private_key->P = *(rsa.P.p);
	private_key->Q = *(rsa.Q.p);
	private_key->QP = *(rsa.QP.p);

	size_t buffer_size = 1600;
	buffer = malloc(sizeof(char) * buffer_size);
	retVal = libp2p_crypto_rsa_write_key_der(&rsa, buffer, &buffer_size);
	if (retVal == 0)
		return 0;

	// allocate memory for the der
	private_key->der = malloc(sizeof(char) * buffer_size);
	private_key->der_length = buffer_size;
	// add in the der to the buffer
	memcpy(private_key->der, &buffer[1600-buffer_size], buffer_size);

	//TODO: Add the peer id
	
exit:
	if (buffer != NULL)
		free(buffer);
	mbedtls_rsa_free( &rsa );
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );
	
	return retVal;
}

/***
 * Free resources used by RsaPrivateKey
 * @param private_key the resources
 * @returns 0
 */
int crypto_rsa_rsa_private_key_free(struct RsaPrivateKey* private_key) {
	if (private_key->der != NULL)
		free(private_key->der);
}

