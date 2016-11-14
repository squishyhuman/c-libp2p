//
//  x509.h
//  libp2p_xcode
//
//  Created by John Jones on 11/7/16.
//  Copyright © 2016 JMJAtlanta. All rights reserved.
//

#ifndef __LIBP2P_CRYPTO_ENCODING_X509_H__
#define __LIBP2P_CRYPTO_ENCODING_X509_H__

#include "libp2p/crypto/rsa.h"

int libp2p_crypto_encoding_x509_private_key_to_der(struct RsaPrivateKey* private_key, unsigned char* bytes[1600]);

int libp2p_crypto_encoding_x509_der_to_private_key(unsigned char* der, size_t der_length, struct RsaPrivateKey* private_key);

#endif /* x509_h */