#pragma once

#define VECTOR_INIT_CAPACITY 4

//#define VECTOR_INIT(vec) vector vec; vector_init(&vec)
//#define VECTOR_ADD(vec, item) vector_add(&vec, (void *) item)
//#define VECTOR_SET(vec, id, item) vector_set(&vec, id, (void *) item)
//#define VECTOR_GET(vec, type, id) (type) vector_get(&vec, id)
//#define VECTOR_DELETE(vec, id) vector_delete(&vec, id)
//#define VECTOR_TOTAL(vec) vector_total(&vec)
//#define VECTOR_FREE(vec) vector_free(&vec)

/**
 * This is an implementation of a simple vector.
 *
 * NOTE: that items are stored as pointers. So if you free the item
 * after insertion, you will be unable to retrieve it.
 */

struct Libp2pVector {
    void const** items;
    int capacity;
    int total;
};

struct Libp2pVector* libp2p_utils_vector_new(int initial_size);
int libp2p_utils_vector_total(struct Libp2pVector* in);
//static void libp2p_utils_vector_resize(struct Libp2pVector *vector, int new_size);
/**
 * Add a value to the vector
 * @param vector the vector to add the item to.
 * @param value the value to be added NOTE: this only saves the pointer, it does not copy.
 * @returns the index of the item in the vector
 */
int libp2p_utils_vector_add(struct Libp2pVector *vector, const void * value);
void libp2p_utils_vector_set(struct Libp2pVector *vector, int pos, void *value);
const void *libp2p_utils_vector_get(struct Libp2pVector *vector, int);
void libp2p_utils_vector_delete(struct Libp2pVector *vector, int pos);
void libp2p_utils_vector_free(struct Libp2pVector *vector);
