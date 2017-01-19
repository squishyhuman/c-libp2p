#include <string.h>
#include <stdlib.h>

#include "libp2p/crypto/rsa.h"
#include "libp2p/record/record.h"
#include "protobuf.h"
#include "mh/hashes.h"
#include "mh/multihash.h"

// libp2p_record_make_put_record creates and signs a dht record for the given key/value pair
int libp2p_record_make_put_record (char* record, struct RsaPrivateKey* sk, char* key, char* value, size_t vlen, int sign)
{
    char *pkh;
    int pkh_len;
    size_t len = 0, l;

    record = malloc(RECORD_BUFSIZE);

    if (record) {
        memset (record, '\0', len);
        if (!protobuf_encode_string (1, WIRETYPE_LENGTH_DELIMITED, key, record, RECORD_BUFSIZE, &l)) {
            free (record);
            return -1;
        }
        len += l;
        if (!protobuf_encode_length_delimited (2, WIRETYPE_LENGTH_DELIMITED, value, vlen, record+len, RECORD_BUFSIZE-len, &l)) {
            free (record);
            return -1;
        }
        len += l;
        pkh_len = mh_new_length(MH_H_SHA2_256, sk->public_key_length);
        pkh = malloc(pkh_len);
        if (!pkh) {
            free (record);
            return -1;
        }
        if (mh_new(pkh, MH_H_SHA2_256, sk->public_key_der, sk->public_key_length)) {
            free (pkh);
            free (record);
            return -1;
        }
        if (!protobuf_encode_length_delimited (3, WIRETYPE_LENGTH_DELIMITED, pkh, pkh_len, record+len, RECORD_BUFSIZE-len, &l)) {
            free (pkh);
            free (record);
            return -1;
        }
        len += l;
        if (sign) {
            //TODO: missing signature function at libp2p-crypto ?
            //sign(sk, signature, record, len);
            //proto encode signature.
            free (pkh);
            free (record);
            return -1; // not implemented.
        }
    }
    return 0; // sucess.
}
