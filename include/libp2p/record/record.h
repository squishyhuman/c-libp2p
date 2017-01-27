#ifndef LIBP2P_RECORD_H
    #define LIBP2P_RECORD_H

    #define RECORD_BUFSIZE 4096

    int libp2p_record_make_put_record (char** record, size_t *rec_size, struct RsaPrivateKey* sk, char* key, char* value, size_t vlen, int sign);
#endif // LIBP2P_RECORD_H
