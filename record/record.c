#include <string.h>
#include <stdlib.h>

#include "libp2p/crypto/rsa.h"
#include "libp2p/record/record.h"
#include "protobuf.h"
#include "mh/hashes.h"
#include "mh/multihash.h"

// libp2p_record_make_put_record creates and signs a dht record for the given key/value pair
int libp2p_record_make_put_record (char** record, size_t *rec_size, struct RsaPrivateKey* sk, char* key, char* value, size_t vlen, int sign)
{
    char *pkh, *p;
    int pkh_len;
    size_t len = 0, l;

    *record = NULL; *rec_size = 0;
    p = malloc(RECORD_BUFSIZE);

    if (p) {
        memset (p, '\0', len);
        if (!protobuf_encode_string (1, WIRETYPE_LENGTH_DELIMITED, key, p, RECORD_BUFSIZE, &l)) {
            free (p);
            return -1;
        }
        len += l;
        if (!protobuf_encode_length_delimited (2, WIRETYPE_LENGTH_DELIMITED, value, vlen, p+len, RECORD_BUFSIZE-len, &l)) {
            free (p);
            return -1;
        }
        len += l;
        pkh_len = mh_new_length(MH_H_SHA2_256, sk->public_key_length);
        pkh = malloc(pkh_len);
        if (!pkh) {
            free (p);
            return -1;
        }
        if (mh_new(pkh, MH_H_SHA2_256, sk->public_key_der, sk->public_key_length)) {
            free (pkh);
            free (p);
            return -1;
        }
        if (!protobuf_encode_length_delimited (3, WIRETYPE_LENGTH_DELIMITED, pkh, pkh_len, p+len, RECORD_BUFSIZE-len, &l)) {
            free (pkh);
            free (p);
            return -1;
        }
        free (pkh);
        len += l;
        if (sign) {
            //TODO: missing signature function at libp2p-crypto ?
            //sign(sk, signature, p, len);
            //proto encode signature.
            free (pkh);
            free (p);
            return -1; // not implemented.
        }
    }
    *record = realloc(p, len); // Reduces memory used for just what is needed.
    if (*record) {
        *rec_size = len;
    } else {
        free (p);
        return -1;
    }
    return 0; // sucess.
}
