#include <stdlib.h>
#include <string.h>
#include <ctype.h>

char *libp2p_utils_url_encode(char *src)
{
	const char *hex = "0123456789abcdef";
	char *p, *dst = malloc (strlen(src) * 3);

	if (!dst) return NULL;

	for(p = dst ; *src ; src++ ) {
		if( isalnum(*src)){
			*p++ = *src;
		} else {
			*p++ = '%';
			*p++ = hex[*src >> 4];
			*p++ = hex[*src & 15];
		}
	}
        *p++ = '\0';
	return realloc(dst, (size_t) (p - dst));
}

int h2b(int c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	} else if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	} else if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
 	return 0; // ?
}

char *libp2p_utils_url_decode(char *src)
{
	char *p, *dst = malloc (strlen(src) + 1);

	for(p = dst ; *src ; src++ ) {
		if(*src != '%'){
			*p++ = *src;
		} else {
			*p    = h2b(*(++src)) << 4;
			*p++ |= h2b(*(++src)) & 15;
		}
	}
        *p++ = '\0';
	return realloc(dst, (size_t) (p - dst));
}
