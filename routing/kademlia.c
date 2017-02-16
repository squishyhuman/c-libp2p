/* For crypt */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/signal.h>
#include <libp2p/crypto/sha256.h>
#include <dht.h>

#define MAX_BOOTSTRAP_NODES 20
static struct sockaddr_storage bootstrap_nodes[MAX_BOOTSTRAP_NODES];
static int num_bootstrap_nodes = 0;

/* The call-back function is called by the DHT whenever something
   interesting happens.  Right now, it only happens when we get a new value or
   when a search completes, but this may be extended in future versions. */
static void
callback(void *closure,
         int event,
         const unsigned char *info_hash,
         const void *data, size_t data_len)
{
    switch (event) {
        case DHT_EVENT_VALUES:
        case DHT_EVENT_VALUES6:
            printf("Received %d values.\n", (int)(data_len / 6));
            break;
        case DHT_EVENT_SEARCH_DONE:
        case DHT_EVENT_SEARCH_DONE6:
            printf("Search done.\n");
            break;
        default:
            break;
    }
}

/* Functions called by the DHT. */

int dht_blacklisted (const struct sockaddr *sa, int salen)
{
    return 0;
}

/* We need to provide a reasonably strong cryptographic hashing function.
   libp2p_crypto_hashing_sha256 */
void dht_hash (void *hash_return, int hash_size,
               const void *v1, int len1,
               const void *v2, int len2,
               const void *v3, int len3)
{
    int len = len1 + len2 + len3;
    char *in, out[32];

    if (!hash_return || hash_size==0 || len==0) {
        return; // invalid param.
    }

    in = malloc (len);

    if (in) {
        memcpy(in, v1, len1);
        memcpy(in+len1, v2, len2);
        memcpy(in+len1+len2, v3, len3);
        if ( libp2p_crypto_hashing_sha256 (in, len, out) ) {
            if (hash_size > sizeof(out)) {
                memset ((char*)hash_return + sizeof(out), 0, hash_size - sizeof(out));
                hash_size = sizeof(out);
            }
            memcpy(hash_return, out, hash_size);
        }
        free (in);
    }
}

int dht_random_bytes (void *buf, size_t size)
{
    int fd, rc, save;
    size_t len = 0;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return fd;
    }

    while (len < size) {
        rc = read (fd, buf + len, size - len);
        if (rc < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue; // not fatal, try again.
            }
            if (errno == EWOULDBLOCK && len > 0) {
                rc = len;
            }

            break; // fail.
        }
        len += rc;
    }

    if (len > 0 && rc >= 0) {
        rc = len;
    }

    save = errno;
    close(fd);
    errno = save;

    return rc;
}
