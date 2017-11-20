#include <stdio.h>
#include "libp2p/net/server.h"

int test_net_server_startup_shutdown() {

	libp2p_net_server_start("127.0.0.1", 1234, NULL);
	sleep(5);
	libp2p_net_server_stop();
	return 1;
}
