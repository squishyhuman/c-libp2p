#ifndef _SHA1_H
#define _SHA1_H

#include <inttypes.h>
#include <string.h>

typedef struct {
	uint32_t state[5];
	uint32_t count[2];
	uint8_t  buffer[64];
} SHA1_CTX;

#define SHA1_DIGEST_SIZE 20

void SHA1_Init(SHA1_CTX* context);
void SHA1_Update(SHA1_CTX* context, const uint8_t* data, const size_t len);
void SHA1_Final(SHA1_CTX* context, uint8_t digest[SHA1_DIGEST_SIZE]);

/***
 * Hash the input using SHA1
 * @param input the input to hash
 * @param input_length the length of the input
 * @param output where the output is placed, should be 40 bytes in width
 * @returns the number of bytes written, or 0 on error
 */
int libp2p_crypto_hashing_sha1(const unsigned char* input, size_t input_length, unsigned char* output);

#endif /* _SHA1_H */
