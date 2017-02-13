#include <stdlib.h>

#include "libp2p/conn/dialer.h"

int test_dialer_new() {
	struct PrivateKey* private_key = NULL;
	struct Dialer* dialer = libp2p_conn_dialer_new("ABC", private_key);
	if (dialer == NULL)
		return 0;
	libp2p_conn_dialer_free(dialer);
	return 1;
}
