#include <stdio.h>
#include <stdlib.h>

#include "libp2p/utils/vector.h"

struct Libp2pVector* libp2p_utils_vector_new(int initial_size)
{
	struct Libp2pVector* v = (struct Libp2pVector*)malloc(sizeof(struct Libp2pVector));
    v->capacity = initial_size;
    v->total = 0;
    v->items = malloc(sizeof(void *) * v->capacity);
    return v;
}

int libp2p_utils_vector_total(struct Libp2pVector *v)
{
    return v->total;
}

static void libp2p_utils_vector_resize(struct Libp2pVector *v, int capacity)
{
    #ifdef DEBUG_ON
    printf("vector_resize: %d to %d\n", v->capacity, capacity);
    #endif

    void **items = realloc(v->items, sizeof(void *) * capacity);
    if (items) {
        v->items = items;
        v->capacity = capacity;
    }
}

/****
 * Add an item to the vector. NOTE: This does not copy the item
 * @param v the vector to add to
 * @param item the item to add
 */
void libp2p_utils_vector_add(struct Libp2pVector *v, void *item)
{
    if (v->capacity == v->total)
        libp2p_utils_vector_resize(v, v->capacity * 2);
    v->items[v->total++] = item;
}

void libp2p_utils_vector_set(struct Libp2pVector *v, int index, void *item)
{
    if (index >= 0 && index < v->total)
        v->items[index] = item;
}

void *libp2p_utils_vector_get(struct Libp2pVector *v, int index)
{
    if (index >= 0 && index < v->total)
        return v->items[index];
    return NULL;
}

void libp2p_utils_vector_delete(struct Libp2pVector *v, int index)
{
    if (index < 0 || index >= v->total)
        return;

    v->items[index] = NULL;

    for (int i = 0; i < v->total - 1; i++) {
        v->items[i] = v->items[i + 1];
        v->items[i + 1] = NULL;
    }

    v->total--;

    if (v->total > 0 && v->total == v->capacity / 4)
        libp2p_utils_vector_resize(v, v->capacity / 2);
}

void libp2p_utils_vector_free(struct Libp2pVector *v)
{
    free(v->items);
    free(v);
}
