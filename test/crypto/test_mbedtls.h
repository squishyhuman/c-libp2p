/**
 * These are mainly functions to reverse engineer some of the
 * mbedtls stuff to make sure we're storing and retrieving
 * something that mbedtls can use
 */

#include <string.h>

#include "mbedtls/asn1write.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

// taken from mbedtls/programs/pkwrite.c
int mbedtls_pk_write_key_der( mbedtls_rsa_context *rsa, unsigned char *buf, size_t size )
{
    int ret;
    unsigned char *c = buf + size;
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

    return( (int) len );
}

int mbedtls_generate_key(mbedtls_rsa_context* ctx) {
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	int exponent = 65537;
	int retVal = 1;

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


	// finally, generate the key
	if( ( retVal = mbedtls_rsa_gen_key( ctx, mbedtls_ctr_drbg_random, &ctr_drbg, (unsigned int)2046,
									   exponent ) ) != 0 )
	{
		retVal = 0;
		goto exit;
	}
	retVal = 1;

exit:

	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );

	return retVal;

}

int test_mbedtls_pk_write_key_der() {
	// generate private key
	mbedtls_rsa_context key;
	mbedtls_rsa_init( &key, MBEDTLS_RSA_PKCS_V15, 0 );

	mbedtls_generate_key(&key);
	// write it out in a section of memory in der format
	size_t size = 1600;
	unsigned char buf[size];
	memset(buf, 0, size);
	int retVal = mbedtls_pk_write_key_der(&key, buf, size);
	// examine it
	printf("Size: %d\n", retVal);
	for(int i = retVal-1; i < size; i++)
		printf("%02x", buf[i]);
	printf("\n");
	// use it
	// free it
	mbedtls_rsa_free( &key );
	return 1;
}
