#include <stdlib.h>
/**
 * A central repository for parsing Multiaddress structs
 */

#include "libp2p/utils/multiaddress.h"

/**
 * This is a hack to get ip4/tcp working
 * TODO: this should be moved further down in the networking stack and generified for different multiaddresses
 * This makes too many assumptions
 * @param address the multiaddress to parse
 * @param ip the first IP address in the multiaddress
 * @param port the first port in the multiaddress
 * @returns true(1) on success, false(0) on failure
 */
int libp2p_utils_multiaddress_parse_ip4_tcp(const struct MultiAddress* address, char** ip, int* port) {
	// the incoming address is not what was expected
	if (strncmp(address->string, "/ip4/", 5) != 0)
		return 0;
	if (strstr(address->string, "/tcp/") == NULL)
		return 0;
	// ip
	char* str = malloc(strlen(address->string));
	if (str == NULL)
		return 0;
	strcpy(str, &address->string[5]); // gets rid of /ip4/
	char* pos = strchr(str, '/');
	pos[0] = 0;
	*ip = malloc(strlen(str) + 1);
	strcpy(*ip, str);
	free(str);
	// port
	str = strstr(address->string, "/tcp/");
	str += 5;
	*port = atoi(str);
	return 1;
}
