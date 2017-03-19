#pragma once

#define VECTOR_INIT_CAPACITY 4

//#define VECTOR_INIT(vec) vector vec; vector_init(&vec)
//#define VECTOR_ADD(vec, item) vector_add(&vec, (void *) item)
//#define VECTOR_SET(vec, id, item) vector_set(&vec, id, (void *) item)
//#define VECTOR_GET(vec, type, id) (type) vector_get(&vec, id)
//#define VECTOR_DELETE(vec, id) vector_delete(&vec, id)
//#define VECTOR_TOTAL(vec) vector_total(&vec)
//#define VECTOR_FREE(vec) vector_free(&vec)

struct Libp2pVector {
    void **items;
    int capacity;
    int total;
};

struct Libp2pVector* libp2p_utils_vector_new(int initial_size);
int libp2p_utils_vector_total(struct Libp2pVector* in);
//static void libp2p_utils_vector_resize(struct Libp2pVector *vector, int new_size);
void libp2p_utils_vector_add(struct Libp2pVector *vector, void * value);
void libp2p_utils_vector_set(struct Libp2pVector *vector, int pos, void *value);
void *libp2p_utils_vector_get(struct Libp2pVector *vector, int);
void libp2p_utils_vector_delete(struct Libp2pVector *vector, int pos);
void libp2p_utils_vector_free(struct Libp2pVector *vector);
