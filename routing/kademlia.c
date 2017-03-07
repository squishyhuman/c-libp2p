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
#include <pthread.h>
#include <libp2p/crypto/sha256.h>
#include <dht.h>

#define MAX_BOOTSTRAP_NODES 20
static struct sockaddr_storage bootstrap_nodes[MAX_BOOTSTRAP_NODES];
static int num_bootstrap_nodes = 0;

pthread_t pth;
time_t tosleep = 0;
int ksock = -1;
int net_family = 0;
volatile int searching = 0; // search lock, -1 to busy, 0 to free, 1 to running.
volatile char hash[20];     // hash to be search or announce.
volatile int announce_port = 0;
volatile int closing = 0;

struct bs_list {
    char *ip;
    uint16_t port;
} bootstrap_list[] = {
    { "127.0.0.1", 1234 },
    { "127.0.0.1", 4321 }
};

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

void *kademlia_thread (void *ptr)
{
    int rc;
    struct timeval tv;
    fd_set readfds;
    char buf[4096];
    struct sockaddr from;
    socklen_t fromlen;

    for(;;) {
        tv.tv_sec = tosleep;
        tv.tv_usec = random() % 1000000;

        FD_ZERO(&readfds);
        FD_SET(ksock, &readfds);
        rc = select(ksock + 1, &readfds, NULL, NULL, &tv);
        if(rc < 0) {
            if(errno != EINTR) {
                perror("select");
                sleep(1);
            }
        }

        if(rc > 0 && FD_ISSET(ksock, &readfds)) {
            fromlen = sizeof(from);
            rc = recvfrom(ksock, buf, sizeof(buf) - 1, 0,
                          (struct sockaddr*)&from, &fromlen);
            buf[rc] = '\0';
            rc = dht_periodic(buf, rc, (struct sockaddr*)&from, fromlen,
                              &tosleep, callback, NULL);
        } else {
            rc = dht_periodic(NULL, 0, NULL, 0, &tosleep, callback, NULL);
        }
        if(rc < 0) {
            if(errno == EINTR) {
                continue;
            } else {
                perror("dht_periodic");
                if(rc == EINVAL || rc == EFAULT)
                    abort();
                tosleep = 1;
            }
        }

        /* This is how you trigger a search for a torrent hash.  If port
           (the second argument) is non-zero, it also performs an announce.
           Since peers expire announced data after 30 minutes, it's a good
           idea to reannounce every 28 minutes or so. */
        if(searching > 0) {
            unsigned char h[sizeof hash];
            int i;
            for (i = 0 ; i < sizeof hash ; i++) {
                h[i] = hash[i]; // Copy hash array to new array so can call
                                // dht_search without volatile variable.
            }
            dht_search(h, announce_port, net_family, callback, NULL);
            searching = 0;
        }
        if(closing) {
            // TODO: Create a routine to save the cache nodes in the file sometimes and before closing.
            return 0; // end thread.
        }
    }
}

int bootstrap_kademlia(int sock, int family, char* peer_id, int timeout)
{
    int rc, i, len;
    unsigned char id[20];
    struct sockaddr_in sa;

    len = sizeof(bootstrap_list) / sizeof(bootstrap_list[0]); // array length

    if (len > MAX_BOOTSTRAP_NODES) {
        len = MAX_BOOTSTRAP_NODES; // limit array length
    }

    memset(&sa, 0, sizeof sa);
    for (i = 0 ; i < len ; i++) {
        if (family == AF_INET6 && inet_pton(AF_INET6, bootstrap_list[i].ip, &(sa.sin_addr.s_addr)) == 1) {
            sa.sin_family = AF_INET6;
        } else if (inet_pton(AF_INET, bootstrap_list[i].ip, &(sa.sin_addr.s_addr)) == 1) {
            sa.sin_family = AF_INET;
        } else {
            continue; // not an ipv6 or ipv4?
        }

        sa.sin_port = htons (bootstrap_list[i].port);

        memcpy(&bootstrap_nodes[num_bootstrap_nodes++], &sa, sizeof(sa));
    }

    dht_hash (id, sizeof(id), peer_id, strlen(peer_id), NULL, 0, NULL, 0);

    if (family == AF_INET6) {
        rc = dht_init(-1, sock, id, NULL);
    } else {
        rc = dht_init(sock, -1, id, NULL);
    }
    if (rc < 0) {
        return rc;
    }

    /* For bootstrapping, we need an initial list of nodes.  This could be
       hard-wired, but can also be obtained from the nodes key of a torrent
       file, or from the PORT bittorrent message.

       Dht_ping_node is the brutal way of bootstrapping -- it actually
       sends a message to the peer.  If you're going to bootstrap from
       a massive number of nodes (for example because you're restoring from
       a dump) and you already know their ids, it's better to use
       dht_insert_node.  If the ids are incorrect, the DHT will recover. */
    for(i = 0; i < num_bootstrap_nodes; i++) {
        dht_ping_node((struct sockaddr*)&bootstrap_nodes[i],
                      sizeof (bootstrap_nodes[i]));
        usleep(random() % 100000);
    }

    // TODO: Read cache nodes from file and load using dht_insert_node.

    ksock = sock;
    net_family = family;
    tosleep = timeout;

    return pthread_create(&pth, NULL, kademlia_thread, NULL);
}

void stop_kademlia (void)
{
    closing = 1;

    // Wait kademlia_thread finish.
    (void) pthread_join(pth, NULL);

    dht_uninit();

    close (ksock);
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
    unsigned char *in, out[32];

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
