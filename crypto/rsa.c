#include <stdio.h>
#include <string.h>

#include "libp2p/crypto/key.h"
#include "libp2p/crypto/rsa.h"
#include "libp2p/crypto/sha256.h"

// mbedtls stuff
#include "mbedtls/config.h"
#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"
#include "mbedtls/x509.h"
#include "mbedtls/rsa.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"

struct PrivateKey* libp2p_crypto_rsa_to_private_key(struct RsaPrivateKey* in) {
	struct PrivateKey* out = libp2p_crypto_private_key_new();
	if (out != NULL) {
		out->data = (unsigned char*)malloc(in->der_length);
		if (out->data == NULL) {
			libp2p_crypto_private_key_free(out);
			return NULL;
		}
		memcpy(out->data, in->der, in->der_length);
		out->data_size = in->der_length;
		out->type = KEYTYPE_RSA;
	}
	return out;
}

/**
 * Take an rsa context and turn it into a der formatted byte stream.
 * NOTE: the stream starts from the right. So there could be a lot of padding in front.
 * Pay attention to the returned size to cut the padding.
 * @param rsa the rsa key to encode
 * @param buf where to put the bytes
 * @param size the max size of the buffer. The actual size used is returned in this value
 * @returns true(1) on success, else 0
 */
int libp2p_crypto_rsa_write_private_key_der( mbedtls_rsa_context *rsa, unsigned char *buf, size_t* size )
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

/**
 * Take a context and turn it into a der formatted byte stream.
 * @param key the key
 * @param buf the buffer to be filled
 * @param size the max size of the buffer. The actual size used is returned in this value
 * @returns true(1) on success, else false(0)
 */
int libp2p_crypto_rsa_write_public_key_der( mbedtls_pk_context *key, unsigned char *buf, size_t* size )
{
    int ret;
    unsigned char *c;
    size_t len = 0, par_len = 0, oid_len;
    const char *oid;

    c = buf + *size;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_pk_write_pubkey( &c, buf, key ) );

    if( c - buf < 1 ) // buffer is too small
        return 0;

    /*
     *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *       algorithm            AlgorithmIdentifier,
     *       subjectPublicKey     BIT STRING }
     */
    *--c = 0;
    len += 1;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_BIT_STRING ) );

    if( ( ret = mbedtls_oid_get_oid_by_pk_alg( mbedtls_pk_get_type( key ),
                                       &oid, &oid_len ) ) != 0 )
    {
        return 0;
    }

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_algorithm_identifier( &c, buf, oid, oid_len,
                                                        par_len ) );

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
int libp2p_crypto_rsa_generate_keypair(struct RsaPrivateKey* private_key, unsigned long num_bits_for_keypair) {
	
	mbedtls_rsa_context rsa;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	
	int exponent = 65537;
	int retVal = 0;
	
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
		goto exit;
	}
	
	// initialize the rsa struct
	mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
	
	// finally, generate the key
	if( mbedtls_rsa_gen_key( &rsa, mbedtls_ctr_drbg_random, &ctr_drbg, (unsigned int)num_bits_for_keypair,
									   exponent ) != 0 )
	{
		goto exit;
	}
	
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
	if (!libp2p_crypto_rsa_write_private_key_der(&rsa, buffer, &buffer_size))
		goto exit;

	// allocate memory for the private key der
	private_key->der_length = buffer_size;
	private_key->der = malloc(sizeof(char) * buffer_size);
	// add in the der to the buffer
	memcpy(private_key->der, &buffer[1600-buffer_size], buffer_size);

	if (!libp2p_crypto_rsa_private_key_fill_public_key(private_key))
		goto exit;

	retVal = 1;
	exit:
	mbedtls_rsa_free( &rsa );
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );
	if (buffer != NULL)
		free(buffer);
	if (retVal == 0) {
		// anything allocated should be cleaned up, as we're erroring out
		libp2p_crypto_rsa_rsa_private_key_free(private_key);
		private_key = NULL;
	}

	return retVal;
}

/**
 * Use the private key DER to fill in the public key DER
 * @param private_key the private key to use
 * @reutrns true(1) on success
 */
int libp2p_crypto_rsa_private_key_fill_public_key(struct RsaPrivateKey* private_key) {
	// first build the rsa context
	mbedtls_pk_context ctx;
	mbedtls_pk_init(&ctx);
	mbedtls_pk_parse_key(&ctx, (unsigned char*)private_key->der, private_key->der_length, NULL, 0);

	// buffer
	size_t buffer_size = 1600;
	unsigned char buffer[buffer_size];
	memset(buffer, 0, buffer_size);

	// generate public key der
	int retVal = libp2p_crypto_rsa_write_public_key_der(&ctx, buffer, &buffer_size);
	mbedtls_pk_free(&ctx);
	if (retVal == 0) {
		return 0;
	}

	// allocate memory for the public key der
	private_key->public_key_length = buffer_size;
	private_key->public_key_der = malloc(sizeof(char) * buffer_size);
	if (private_key->public_key_der == NULL) {
		return 0;
	}

	//copy it into the struct
	memcpy(private_key->public_key_der, &buffer[1600-buffer_size], buffer_size);

	return 1;
}

struct RsaPrivateKey* libp2p_crypto_rsa_rsa_private_key_new() {
	struct RsaPrivateKey* out = (struct RsaPrivateKey*)malloc(sizeof(struct RsaPrivateKey));
	if (out != NULL) {
		out->D = 0;
		out->DP = 0;
		out->DQ = 0;
		out->E = 0;
		out->N = 0;
		out->P = 0;
		out->Q = 0;
		out->QP = 0;
		out->der = NULL;
		out->public_key_length = 0;
		out->public_key_der = NULL;
		out->public_key_length = 0;
	}
	return out;
}

/***
 * Free resources used by RsaPrivateKey
 * @param private_key the resources
 * @returns true(1)
 */
int libp2p_crypto_rsa_rsa_private_key_free(struct RsaPrivateKey* private_key) {
	if (private_key != NULL) {
		if (private_key->der != NULL)
			free(private_key->der);
		if (private_key->public_key_der != NULL)
			free(private_key->public_key_der);
		free(private_key);
	}
	return 1;
}

/**
 * sign a message
 * @param private_key the private key
 * @param message the message to be signed
 * @param message_length the length of message
 * @param result the resultant signature. Note: should be pre-allocated and be the size of the private key (i.e. 2048 bit key can store a sig in 256 bytes)
 * @returns true(1) on success, otherwise false(0)
 */
int libp2p_crypto_rsa_sign(struct RsaPrivateKey* private_key, const char* message, size_t message_length, unsigned char** result, size_t* result_size) {
	unsigned char hash[32] = {0};
	int retVal = 0;
	char* pers = "libp2p crypto rsa sign";
	mbedtls_pk_context private_context = {0};
	mbedtls_entropy_context entropy = {0};
	mbedtls_ctr_drbg_context ctr_drbg = {0};
	unsigned char* der = NULL;
	int der_allocated = 0;

	// hash the incoming message
	libp2p_crypto_hashing_sha256(message, message_length, hash);

	// put a null terminator on the key (if ncessary)
	if (private_key->der[private_key->der_length-1] != 0) {
		der = (unsigned char*)malloc(private_key->der_length + 1);
		if (der == NULL)
			goto exit;
		der_allocated = 1;
		memcpy(der, private_key->der, private_key->der_length);
		der[private_key->der_length] = 0;
	} else {
		der = private_key->der;
	}
	// make a pk_context from the private key
	mbedtls_pk_init(&private_context);
	if (mbedtls_pk_parse_key(&private_context, der, private_key->der_length, NULL, 0) != 0)
		goto exit;

	// get just the RSA portion of the context
	mbedtls_rsa_context* ctx = mbedtls_pk_rsa(private_context);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	mbedtls_entropy_init( &entropy );

	// seed the routines
	if(  mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen( pers ) )  != 0 )
		goto exit;


	*result_size = ctx->len;
	*result = (unsigned char*)malloc(*result_size);
	// sign
	retVal = mbedtls_rsa_rsassa_pkcs1_v15_sign(ctx,
			mbedtls_ctr_drbg_random,
			&ctr_drbg,
			MBEDTLS_RSA_PRIVATE,
			MBEDTLS_MD_SHA256,
            32,
            hash,
            *result );
	//retVal = mbedtls_rsa_private(ctx, mbedtls_ctr_drbg_random, &ctr_drbg, hash, result);
	if (retVal != 0) {
		retVal = 0;
		goto exit;
	}
	retVal = 1;
	// cleanup
	exit:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_pk_free(&private_context);
	if (der_allocated)
		free(der);
	return retVal;
}

/**
 * verify a signature
 *@param public_key the public key to use
 *@param  message the message to compare to the signature
 *@param  message_length the length of the message
 *@param  signature the signature that was given
 *@returns true(1) if the signature matches the SHA2-256 hash of message, false(0) otherwise
 */
int libp2p_crypto_rsa_verify(struct RsaPublicKey* public_key, const unsigned char* message, size_t message_length, const unsigned char* signature) {

	// hash the message
	unsigned char output[32];
	libp2p_crypto_hashing_sha256(message, message_length, output);

	// make a pk_context from the public key
	mbedtls_pk_context public_context;
	mbedtls_pk_init(&public_context);
	mbedtls_pk_parse_public_key(&public_context, (unsigned char*)public_key->der, public_key->der_length);

	mbedtls_rsa_context* ctx = mbedtls_pk_rsa(public_context);
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);

	int retVal = mbedtls_rsa_rsassa_pkcs1_v15_verify(ctx, // the rsa public key has to be in the context
			NULL, // random number generator, but not needed because this is not a private key
			NULL, //mbedtls_ctr_drbg_random, // random number generator
			MBEDTLS_RSA_PUBLIC, // mode RSA_PUBLIC or RSA_PRIVATE
			MBEDTLS_MD_SHA256, // type of message digest
			32, // ignored because we know it from the parameter previous
			output, signature); // the actual signature to compare

	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_pk_free(&public_context);

	return retVal == 0;
}






