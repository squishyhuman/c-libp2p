#include <stdlib.h>
#include <string.h>

#include "mh/multihash.h"
#include "mh/hashes.h"
#include "libp2p/crypto/encoding/base58.h"
#include "libp2p/crypto/sha256.h"
//#include "libp2p/crypto/key.h"

/**
 * base58 encode a string NOTE: this also puts the prefix 'Qm' in front as the ID is a multihash
 * @param pointyaddr where the results will go
 * @param rezbuflen the length of the results buffer. It will also put how much was used here
 * @param ID_BUF the input text (usually a SHA256 hash)
 * @param ID_BUF_SIZE the input size (normally a SHA256, therefore 32 bytes)
 * @returns true(1) on success
 */
int PrettyID(unsigned char * pointyaddr, size_t* rezbuflen,unsigned char * ID_BUF, size_t ID_BUF_SIZE)//b58 encoded ID buf
{
	int returnstatus = 0;

	unsigned char temp_buffer[*rezbuflen];

	memset(temp_buffer, 0, *rezbuflen);

	// wrap the base58 into a multihash
	int retVal = mh_new(temp_buffer, MH_H_SHA2_256, ID_BUF, ID_BUF_SIZE);
	if (retVal < 0)
		return 0;

	// base58 the multihash
	returnstatus = libp2p_crypto_encoding_base58_encode(temp_buffer, strlen((char*)temp_buffer), &pointyaddr, rezbuflen);
	if(returnstatus == 0)
		return 0;

	return 1;
}


/****
 * Make a SHA256 hash of what is usually the DER formatted private key.
 * @param result where to store the result. Should be 32 chars long
 * @param texttohash the text to hash. A DER formatted public key
 * @param text_size the size of the text
 */
/*
void ID_FromPK_non_null_terminated(char * result,unsigned char * texttohash, size_t text_size)
{

	libp2p_crypto_hashing_sha256(texttohash, text_size, (unsigned char*)result);
}
*/

/****
 * Make a SHA256 hash of what is usually the DER formatted private key.
 * @param result where to store the result. Should be 32 chars long
 * @param texttohash a null terminated string of the text to hash
 */
/*
void ID_FromPK(char * result,unsigned char * texttohash)
{
   ID_FromPK_non_null_terminated(result,texttohash,strlen((char*)texttohash));
}
*/
