#include <stdio.h>
#include <stdlib.h>
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
	mbedtls_mpi_lset(&N, private_key->N);
	
	mbedtls_mpi E;
	mbedtls_mpi_init(&E);
	mbedtls_mpi_lset(&E, private_key->E);

	mbedtls_mpi Q;
	mbedtls_mpi_init(&Q);
	mbedtls_mpi_lset(&Q, private_key->Q);
	
	rsa->N = N;
	rsa->E = E;
	rsa->Q = Q;
	rsa->len = ( mbedtls_mpi_bitlen(&rsa->N ) + 7) >> 3;
	
	// now write to DER
	mbedtls_pk_write_key_der(&ctx, *bytes, 1600);
	
	mbedtls_mpi_free(&N);
	mbedtls_mpi_free(&E);
	mbedtls_mpi_free(&Q);
	mbedtls_rsa_free(rsa);
	mbedtls_pk_free(&ctx);
	
	return 1;
}

/***
 * Parse a DER bytestring into a RsaPrivateKey struct
 * @param der the incoming bytestring
 * @param der_length the length of the bytestring
 * @param private_key the RsaPrivateKey to fill
 * @returns true(1) on success
 */
int libp2p_crypto_encoding_x509_der_to_private_key(unsigned char* der, size_t der_length, struct RsaPrivateKey* private_key) {
	mbedtls_pk_context ctx;
	mbedtls_pk_init(&ctx);
	
	int retVal = mbedtls_pk_parse_key(&ctx, der, der_length, NULL, 0);

	if (retVal >= 0) {
		// parse the results into the structure
		mbedtls_rsa_context* rsa = mbedtls_pk_rsa(ctx);
		private_key->D = *(rsa->D.p);
		private_key->DP = *(rsa->DP.p);
		private_key->DQ = *(rsa->DQ.p);
		private_key->E = *(rsa->E.p);
		private_key->N = *(rsa->N.p);
		private_key->P = *(rsa->P.p);
		private_key->Q = *(rsa->Q.p);
		private_key->QP = *(rsa->QP.p);

		// now put the public DER format in.
		private_key->der = malloc(sizeof(char) * der_length);
		if (private_key->der == NULL)
			return 0;
		memcpy(private_key->der, der, der_length);
		private_key->der_length = der_length;

		//NOTE: the public DER stuff is done in rsa.c
	}

	mbedtls_pk_free(&ctx);

	return retVal >= 0;
}
