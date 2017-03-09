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
#include <libp2p/routing/kademlia.h>
#include <dht.h>

#define MAX_BOOTSTRAP_NODES 20
static struct sockaddr_storage bootstrap_nodes[MAX_BOOTSTRAP_NODES];
static int num_bootstrap_nodes = 0;

struct bs_struct {
    char *ip;
    uint16_t port;
} bootstrap_list[] = {
    { "127.0.0.1", 1234 },
    { "127.0.0.1", 4321 }
};

pthread_t pth_kademlia, pth_announce;
time_t tosleep = 0;
int ksock = -1;
int net_family = 0;
volatile int8_t searching = 0; // search lock, -1 to busy, 0 to free, 1 to running.
volatile char hash[20];     // hash to be search or announce.
volatile uint16_t announce_port = 0;
volatile int8_t closing = 0;

#define ANNOUNCE_WAIT_TIME		(28 * 60) // Wait 28 minutes.
#define ANNOUNCE_WAIT_TOLERANCE		60
struct announce_struct {
    unsigned char hash[20];
    uint16_t port;
    unsigned int time;
    struct announce_struct *next;
} *announce_list = NULL;

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

int start_kademlia(int sock, int family, char* peer_id, int timeout)
{
    int rc, i, len;
    unsigned char id[sizeof hash];
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

    rc = pthread_create(&pth_kademlia, NULL, kademlia_thread, NULL);
    if (rc) {
        return rc; // error
    }

    return pthread_create(&pth_announce, NULL, announce_thread, NULL);
}

void stop_kademlia (void)
{
    if (ksock != -1) {
        closing = 1;

        pthread_cancel(pth_announce);

        // Wait kademlia_thread finish.
        pthread_join(pth_kademlia, NULL);

        dht_uninit();

        close (ksock);
        ksock = -1;
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

void *announce_thread (void *ptr)
{
    unsigned int wait;
    struct announce_struct *n, *p;

    for(;;) {
        if (announce_list) {
            unsigned int now, minus_time = ((unsigned int) -1);

            p = NULL;
            // find max wait value.
            for (n = announce_list ; n ; n = n->next) {
                if (n->time < minus_time) {
                    minus_time = n->time;
                    p = n;
                }
            }
            if (p) {
                now = time(NULL);
                if ((minus_time + ANNOUNCE_WAIT_TIME) > (now + ANNOUNCE_WAIT_TOLERANCE)) {
                    wait = ANNOUNCE_WAIT_TIME - (now - minus_time);
                    sleep (wait);
                } else {
                    if (p) {
                        announce_once_kademlia (p->hash, p->port, ANNOUNCE_WAIT_TOLERANCE);
                        p->time = time(NULL);
                    }
                }
                continue;
            }
        }
        // Empty list, just wait.
        sleep (ANNOUNCE_WAIT_TIME);
    }
}

// Announce kademlia id hash only once.
int announce_once_kademlia(unsigned char* id, uint16_t port, int timeout)
{
    int i, to = timeout * 1000000;

    if (ksock == -1) {
        return 0; // start thread first.
    }

    while (searching != 0) {
        i = random() % 100000;
        if (i > to) {
            return 0; // timeout waiting a chance
        }
        usleep(i);
        to -= i;
    }

    searching = -1; // lock.

    for (i = 0 ; i < sizeof hash ; i++) {
        hash[i] = id[i];
    }

    announce_port = port;

    searching = 1; // announce.

    return 1;
}

int announce_kademlia (char* peer_id, uint16_t port)
{
    unsigned char id[sizeof hash];
    struct announce_struct *n, *p;

    dht_hash (id, sizeof(id), peer_id, strlen(peer_id), NULL, 0, NULL, 0);

    for (n = announce_list ; n ; n = n->next) {
        if (memcmp(n->hash, id, sizeof id) == 0) {
            return 0; // Already on the list.
        }
        if (! (n->next)) {
            break; // Keep n->next at the insertion point.
        }
    }


    if ((p = malloc (sizeof(struct announce_struct))) == NULL) {
        return 0; // Fail to alloc.
    }

    announce_once_kademlia (id, port, ANNOUNCE_WAIT_TOLERANCE);

    memcpy(p->hash, id, sizeof id);
    p->port = port;
    p->next = NULL;
    p->time = time(NULL);

    if (!announce_list) {
        announce_list = p;
    } else {
        n->next = p;
    }

    return 1; // Announced and added to the list.
}

int search_kademlia(char* peer_id, int timeout)
{
    unsigned char id[sizeof hash];
    int i, to = timeout * 1000000;

    if (ksock == -1) {
        return 0; // start thread first.
    }

    dht_hash (id, sizeof(id), peer_id, strlen(peer_id), NULL, 0, NULL, 0);

    while (searching != 0) {
        i = random() % 100000;
        if (i > to) {
            return 0; // timeout waiting a chance
        }
        usleep(i);
        to -= i;
    }

    searching = -1; // lock.

    for (i = 0 ; i < sizeof hash ; i++) {
        hash[i] = id[i];
    }

    announce_port = 0;

    searching = 1; // search.

    return 1;
}

int ping_kademlia (char *ip, uint16_t port)
{
    struct sockaddr_in sa;

    if (inet_pton(AF_INET6, ip, &(sa.sin_addr.s_addr)) == 1) {
        sa.sin_family = AF_INET6;
    } if (inet_pton(AF_INET, ip, &(sa.sin_addr.s_addr)) == 1) {
        sa.sin_family = AF_INET;
    } else {
        return 0;
    }

    sa.sin_port = htons (port);

    dht_ping_node((struct sockaddr*)&sa, sizeof sa);
    //usleep(random() % 100000);

    return 1;
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
    int fd, rc = 0, save;
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
