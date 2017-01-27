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
#include <libp2p/crypto/sha1.h>
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
   SHA-1 code adapted from https://github.com/mwarning/KadNode */
void dht_hash (void *hash_return, int hash_size,
               const void *v1, int len1,
               const void *v2, int len2,
               const void *v3, int len3)
{
    SHA1_CTX ctx;
    uint8_t digest[SHA1_DIGEST_SIZE];

    SHA1_Init (&ctx);
    if (v1) SHA1_Update (&ctx, v1, len1);
    if (v2) SHA1_Update (&ctx, v2, len2);
    if (v3) SHA1_Update (&ctx, v3, len3);
    SHA1_Final (&ctx, digest);

    if (hash_size > SHA1_DIGEST_SIZE) {
        memset ((char*)hash_return + SHA1_DIGEST_SIZE, 0, hash_size - SHA1_DIGEST_SIZE);
        hash_size = SHA1_DIGEST_SIZE;
    }
    memcpy(hash_return, digest, hash_size);
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
