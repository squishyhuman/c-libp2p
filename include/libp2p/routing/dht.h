/*
Copyright (c) 2009-2011 by Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The callback method that you can implement
 * to receive events
 */
typedef void dht_callback(void *closure, int event,
             const unsigned char *info_hash,
             const void *data, size_t data_len);

#define DHT_EVENT_NONE 0
#define DHT_EVENT_VALUES 1
#define DHT_EVENT_VALUES6 2
#define DHT_EVENT_SEARCH_DONE 3
#define DHT_EVENT_SEARCH_DONE6 4

extern FILE *dht_debug;

int dht_init(int s, int s6, const unsigned char *id, const unsigned char *v);
int dht_insert_node(const unsigned char *id, struct sockaddr *sa, int salen);
int dht_ping_node(const struct sockaddr *sa, int salen);
/***
 * Called when something is received from the network or
 * the network times out (things that should be done
 * periodically)
 * @param buf what came in from the network
 * @param buflen the size of buf
 * @param from where it came from
 * @param fromlen
 * @param tosleep
 * @param callback
 * @param closure
 * @returns ??
 */
int dht_periodic(const void *buf, size_t buflen,
                 const struct sockaddr *from, int fromlen,
                 time_t *tosleep, dht_callback *callback, void *closure);
/**
 * Start a search.  If port is non-zero, perform an announce when the
 * search is complete.
 * @param id the hash to search for
 * @param port where it is available
 * @param af IP family (AF_INET or AF_INET6)
 * @param callback the callback method
 * @param closure
 * @returns -1 on failure, 1 on success
 **/
int dht_search(const unsigned char *id, int port, int af,
               dht_callback *callback, void *closure);
int dht_nodes(int af,
              int *good_return, int *dubious_return, int *cached_return,
              int *incoming_return);
void dht_dump_tables(FILE *f);
int dht_get_nodes(struct sockaddr_in *sin, int *num,
                  struct sockaddr_in6 *sin6, int *num6);
int dht_uninit(void);

/* This must be provided by the user. */
int dht_blacklisted(const struct sockaddr *sa, int salen);
void dht_hash(void *hash_return, int hash_size,
              const void *v1, int len1,
              const void *v2, int len2,
              const void *v3, int len3);
int dht_random_bytes(void *buf, size_t size);

#ifdef __cplusplus
}
#endif
