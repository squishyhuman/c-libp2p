//
//  x509.c
//  libp2p_xcode
//
//  Created by John Jones on 11/7/16.
//  Copyright © 2016 JMJAtlanta. All rights reserved.
//

#include <stdio.h>
#include <string.h>

#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/ctr_drbg.h"

#include "libp2p/crypto/encoding/x509.h"

/**
 * public methods
 */

/**
 * convert a RSA Private Key to an array of bytes in DER format
 * @param private_key the private key
 * @param bytes where to put the resultant bytes
 * @returns true(1) on success
 */
int libp2p_crypto_encoding_x509_private_key_to_der(struct RsaPrivateKey* private_key, unsigned char* bytes[1600]) {

	// get everything setup
	mbedtls_pk_context ctx;
	mbedtls_pk_init( &ctx);
	
	mbedtls_pk_setup( &ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
	
	mbedtls_rsa_context* rsa = mbedtls_pk_rsa( ctx );
	
	// set the values in the context
	mbedtls_mpi N;
	mbedtls_mpi_init(&N);
	mbedtls_mpi_lset(&N, private_key->prime1);
	
	mbedtls_mpi E;
	mbedtls_mpi_init(&E);
	mbedtls_mpi_lset(&E, private_key->private_exponent);
	
	rsa->N = N;
	rsa->E = E;
	rsa->len = ( mbedtls_mpi_bitlen(&rsa->N ) + 7) >> 3;
	
	// now write to DER
	mbedtls_pk_write_key_der(&ctx, *bytes, 1600);
	
	mbedtls_mpi_free(&N);
	mbedtls_mpi_free(&E);
	mbedtls_rsa_free(rsa);
	mbedtls_pk_free(&ctx);
	
	return 1;
}

int libp2p_crypto_encoding_x509_der_to_private_key(unsigned char* der, size_t der_length, struct RsaPrivateKey* private_key) {
	mbedtls_pk_context ctx;
	mbedtls_pk_init(&ctx);
	
	mbedtls_pk_parse_key(&ctx, der, der_length, NULL, 0);
	return 1;
}
