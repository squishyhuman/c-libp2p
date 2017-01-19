#ifndef LIBP2P_RECORD_H
    #define LIBP2P_RECORD_H

    #define RECORD_BUFSIZE 1024

    int libp2p_record_make_put_record (char* record, struct RsaPrivateKey* sk, char* key, char* value, size_t vlen, int sign);
#endif // LIBP2P_RECORD_H
