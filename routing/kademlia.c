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
#include <libp2p/routing/dht.h>
#include <multiaddr/multiaddr.h>

extern FILE *dht_debug;

#define MAX_BOOTSTRAP_NODES 20
static struct sockaddr_storage bootstrap_nodes[MAX_BOOTSTRAP_NODES];
static int num_bootstrap_nodes = 0;

struct bs_struct {
    char *ip;
    uint16_t port;
} bootstrap_list[] = {
};

pthread_t pth_kademlia, pth_announce;
time_t tosleep = 0;
int kfd = -1;
int net_family = 0;
volatile int8_t searching = 0; // search lock, -1 to busy, 0 to free, 1 to running.
volatile char hash[20];     // hash to be search or announce.
volatile uint16_t announce_port = 0;
volatile int8_t closing = 0;

#define ANNOUNCE_WAIT_TIME		(28 * 60) // Wait 28 minutes.
#define ANNOUNCE_WAIT_TOLERANCE		60
struct announce_struct {
    unsigned char hash[sizeof hash];
    uint16_t port;
    unsigned int time;
    struct announce_struct *next;
} *announce_list = NULL;

#define DHT_MAX_IPV4	50
#define DHT_MAX_IPV6	10

struct ipv4_struct {
    uint32_t ip;
    uint16_t port;
};

struct ipv6_struct {
    uint8_t  ip[16];
    uint16_t port;
};

struct search_struct {
    unsigned char hash[sizeof hash];
    uint8_t ipv4_count;
    uint8_t ipv6_count;
    struct ipv4_struct ipv4[DHT_MAX_IPV4];
    struct ipv6_struct ipv6[DHT_MAX_IPV6];
    struct search_struct *next;
} *search_result = NULL;

/***
 * The call-back function is called by the DHT whenever something
 * interesting happens.  Right now, it only happens when we get a new value or
 * when a search completes, but this may be extended in future versions.
 * @param closure
 * @param event the event
 * @param info_hash the hash to work with
 * @param data the new value to be added
 * @param data_len the length of the data
 */
static void callback(void *closure, int event, const unsigned char *info_hash, const void *data, size_t data_len) {
    struct search_struct *sp, *rp = NULL; // struct pointer and result pointer

    switch (event) {
        case DHT_EVENT_VALUES:
        case DHT_EVENT_VALUES6:
            if (dht_debug) {
                fprintf(dht_debug, "Received %d values.\n", (int)(data_len / 6));
            }
            // Find the item in the list.
            for (rp = search_result ; rp ; rp = rp->next) {
                if (memcmp(rp->hash, info_hash, sizeof hash) == 0) { // Found.
                    int i;
                    if (event == DHT_EVENT_VALUES) { // IPv4
                        struct ipv4_struct ipv4;
                        if (rp->ipv4_count == DHT_MAX_IPV4) { // Full
                            return;
                        }
                        // Make sure the data is in struct format.
                        memcpy(&ipv4.ip, data, 4);
                        memcpy(&ipv4.port, data+4, 2);
                        ipv4.port = ntohs(ipv4.port);
                        for (i = 0 ; i < rp->ipv4_count ; i++) {
                            if (memcmp(&rp->ipv4[i], &ipv4, sizeof ipv4) == 0) {
                                return; // Alread in the list.
                            }
                        }
                        // Not in the list, then add.
                        memcpy(&rp->ipv4[rp->ipv4_count], &ipv4, sizeof ipv4);
                        rp->ipv4_count++;
                    } else { // IPv6
                        struct ipv6_struct ipv6;
                        if (rp->ipv6_count == DHT_MAX_IPV6) { // Full
                            return;
                        }
                        // Make sure the data is in struct format.
                        memcpy(&ipv6.ip, data, 16);
                        memcpy(&ipv6.port, data+16, 2);
                        for (i = 0 ; i < rp->ipv6_count ; i++) {
                            if (memcmp(&rp->ipv6[i], &ipv6, sizeof ipv6) == 0) {
                                return; // Alread in the list.
                            }
                        }
                        // Not in the list, then add.
                        memcpy(&rp->ipv6[rp->ipv6_count], &ipv6, sizeof ipv6);
                        rp->ipv6_count++;
                    }
                    return;
                }
            }
            break; // Not found, how can EVENT_VALUE may occur before SEARCH_DONE?
        case DHT_EVENT_SEARCH_DONE:
        case DHT_EVENT_SEARCH_DONE6:
            if (dht_debug) {
                fprintf(dht_debug, "Search done.\n");
            }
            if (search_result) {
                // Try to find the item in the list.
                for (sp = search_result ; sp->next ; sp = sp->next) {
                    if (memcmp(sp->hash, info_hash, sizeof hash) == 0) { // Found.
                        rp = sp;
                        break;
                    }
                }
                if (!rp) {
                    rp = malloc(sizeof(struct search_struct));
                    if (!rp) return; // Abort, out of memory.
                    memset(rp, 0, sizeof(struct search_struct));
                    memcpy(rp->hash, info_hash, sizeof hash);
                    sp->next = rp; // Insert in the list.
                }
            } else {
                rp = malloc(sizeof(struct search_struct));
                if (!rp) return; // Abort, out of memory.
                memset(rp, 0, sizeof(struct search_struct));
                memcpy(rp->hash, info_hash, sizeof hash);
                search_result = rp; // Insert first item in the list.
            }
            break;
        default:
            break;
    }
}

int start_kademlia_multiaddress(struct MultiAddress* address, char* peer_id, int timeout, struct Libp2pVector* bootstrap_addresses) {
	int port = multiaddress_get_ip_port(address);
	int family = multiaddress_get_ip_family(address);
	int fd = socket(family, SOCK_DGRAM, 0);
	if (fd < 0)
		return 0;
	struct sockaddr_in serv_addr;
	serv_addr.sin_family = family;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = port;
	if (bind(fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) != 0)
		return 0;
	return start_kademlia(fd, family, peer_id, timeout, bootstrap_addresses);
}

/***
 * Start the kademlia service
 * @param net_fd the file descriptor of the address/socket already bound
 * @param family ip4 or ip6
 * @param peer_id the first 20 chars of the public PeerID in a null terminated string
 * @param timeout seconds before a select() timeout
 */
int start_kademlia(int net_fd, int family, char* peer_id, int timeout, struct Libp2pVector* bootstrap_addresses)
{
    int rc, i, len;
    unsigned char id[sizeof hash];
    struct sockaddr_in sa;

    dht_debug = stderr;

    len = bootstrap_addresses->total;

    if (len > MAX_BOOTSTRAP_NODES) {
        len = MAX_BOOTSTRAP_NODES; // limit array length
    }

    memset(&sa, 0, sizeof sa);
    char* ip = NULL;
    for (i = 0 ; i < len ; i++) {
    	struct MultiAddress* addr = (struct MultiAddress*)libp2p_utils_vector_get(bootstrap_addresses, i);
    	if (ip != NULL)
    		free(ip);
    	if (multiaddress_is_ip(addr)) {
    		multiaddress_get_ip_address(addr, &ip);
    		if (family == AF_INET6 && multiaddress_is_ip6(addr)) {
    			if (inet_pton(AF_INET6, ip, &(sa.sin_addr.s_addr)) == 1)
    				sa.sin_family = AF_INET6;
    			else
    				continue;
    		} else {
    			if (inet_pton(AF_INET , ip, &(sa.sin_addr.s_addr)) == 1)
					sa.sin_family = AF_INET;
    			else
    				continue;
    		}
    	} else {
            continue; // not an ipv6 or ipv4?
        }

        sa.sin_port = htons (multiaddress_get_ip_port(addr));

        memcpy(&bootstrap_nodes[num_bootstrap_nodes++], &sa, sizeof(sa));
    }
    if (ip != NULL)
    	free(ip);

    dht_hash (id, sizeof(id), peer_id, strlen(peer_id), NULL, 0, NULL, 0);

    if (family == AF_INET6) {
        rc = dht_init(-1, net_fd, id, NULL);
    } else {
        rc = dht_init(net_fd, -1, id, NULL);
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
    	// for debugging
    	int retVal =
        dht_ping_node((struct sockaddr*)&bootstrap_nodes[i],
                      sizeof (bootstrap_nodes[i]));
    	fprintf(stderr, "ping returned %d\n", retVal);
        usleep(random() % 100000);
    }

    // TODO: Read cache nodes from file and load using dht_insert_node.

    kfd = net_fd;
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
    if (kfd != -1) {
        closing = 1;

        pthread_cancel(pth_announce);

        // Wait kademlia_thread finish.
        pthread_join(pth_kademlia, NULL);

        dht_uninit();

        close (kfd);
        kfd = -1;
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
        FD_SET(kfd, &readfds);
        rc = select(kfd + 1, &readfds, NULL, NULL, &tv);
        if(rc < 0) {
            if(errno != EINTR) {
                perror("select");
                sleep(1);
            }
        }

        if(rc > 0 && FD_ISSET(kfd, &readfds)) {
            fromlen = sizeof(from);
            rc = recvfrom(kfd, buf, sizeof(buf) - 1, 0,
                          (struct sockaddr*)&from, &fromlen);
            if (rc < 0) {
            	if (errno == EAGAIN || errno == EWOULDBLOCK) {
            		continue;
            	} else {
            		fprintf(stderr, "kademlia_thread:recvfrom failed with %d\n", errno);
            		continue;
            	}
            }
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
    return (void*)1;
}

/**
 * Search for a hash
 * @param id the hash to look for
 * @param port the port if it is available
 * @param to the time out
 * @returns the time left
 */
int search_kademlia_internal (unsigned char* id, int port, int to)
{
    int i;

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

    searching = 1; // search.

    return to;
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
                        search_kademlia_internal (p->hash, p->port, ANNOUNCE_WAIT_TOLERANCE * 1000000);
                        p->time = time(NULL);
                    }
                }
                continue;
            }
        }
        // Empty list, just wait.
        sleep (ANNOUNCE_WAIT_TIME);
    }
    return (void*)1;
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

    search_kademlia_internal (id, port, ANNOUNCE_WAIT_TOLERANCE * 1000000);

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

struct MultiAddress** search_kademlia(char* peer_id, int timeout)
{
    unsigned char id[sizeof hash];
    int i, to = timeout * 1000000;
    struct search_struct *rp; // result pointer
    struct MultiAddress **ret;

    if (kfd == -1) {
        return NULL; // start thread first.
    }

    dht_hash (id, sizeof(id), peer_id, strlen(peer_id), NULL, 0, NULL, 0);

    //TODO: Is this the right place to ask the net?
    dht_search(peer_id, 0, AF_INET, NULL, NULL);
    to = search_kademlia_internal (id, 0, to);
    if (to == 0) return NULL; // time out.

    // Wait for search completion.
    for(;;) {
        i = random() % 100000;
        if (i > to) {
            return NULL; // timeout.
        }
        usleep(i);
        for (rp = search_result ; rp ; rp = rp->next) {
            if (memcmp(rp->hash, id, sizeof hash) == 0) { // Found.
                char ipstr[INET6_ADDRSTRLEN + 1];
                char str[sizeof ipstr + 16];
                int c = 0;

                // Wait for result or time out.
                while (to > 0 &&
                       search_result->ipv4_count == 0 &&
                       search_result->ipv6_count == 0) {
                         to = search_kademlia_internal (id, 0, to); // Repeat search to collect result.
                         usleep(2000000); // Wait a few seconds for the result.
                         to -= 2000000;
                }

                if (search_result->ipv4_count == 0 ||
                    search_result->ipv6_count == 0) return NULL; // no result.

                ret = calloc(search_result->ipv4_count + search_result->ipv6_count + 1, // IPv4 + IPv6 itens and a NULL terminator.
                             sizeof (struct MultiAddress*)); // array of pointer.
                if (!ret) {
                    return NULL;
                }

                for (i = 0 ; i < search_result->ipv4_count ; i++) {
                    if (inet_ntop(AF_INET, &search_result->ipv4[i].ip, ipstr, sizeof ipstr)) {
                        snprintf (str, sizeof str, "/ip4/%s/tcp/%d", ipstr, search_result->ipv4[i].port);
                        if (dht_debug) {
                            fprintf(dht_debug, "SEARCH %s (%d) = %s\n", peer_id, c, str);
                        }
                        ret[c] = multiaddress_new_from_string (str);
                        if (ret[c] > 0) { // Sucess.
                            c++;
                        }
                    }
                }
                for (i = 0 ; i < search_result->ipv6_count ; i++) {
                    if (inet_ntop(AF_INET6, search_result->ipv6[i].ip, ipstr, sizeof ipstr)) {
                        snprintf (str, sizeof str, "/ip6/%s/tcp/%d", ipstr, search_result->ipv6[i].port);
                        if (dht_debug) {
                            fprintf(dht_debug, "SEARCH %s (%d) = %s\n", peer_id, c, str);
                        }
                        ret[c] = multiaddress_new_from_string (str);
                        if (ret[c] > 0) { // Sucess.
                            c++;
                        }
                    }
                }
                ret[c] = NULL; // NULL terminator.
                return ret;
            }
        }
        to -= i;
    }

    return NULL;
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
