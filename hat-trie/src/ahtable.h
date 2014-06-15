/*
 * This file is part of hat-trie.
 *
 * Copyright (c) 2011 by Daniel C. Jones <dcjones@cs.washington.edu>
 *
 *
 * This is an implementation of the 'cache-conscious' hash tables described in,
 *
 *    Askitis, N., & Zobel, J. (2005). Cache-conscious collision resolution in
 *    string hash tables. String Processing and Information Retrieval (pp.
 *    91–102). Springer.
 *
 * Briefly, the idea is, as opposed to separate chaining with linked lists, to
 * store keys contiguously in one big array, thereby improving the caching
 * behavior, and reducing space requirments.
 *
 */

#ifndef HATTRIE_AHTABLE_H
#define HATTRIE_AHTABLE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdbool.h>
#include "pstdint.h"
#include "common.h"

typedef unsigned char* slot_t;

typedef struct ahtable_t_
{
    /* these fields are reserved for hattrie to fiddle with */
    uint8_t flag; 
    unsigned char c0;
    unsigned char c1;

    size_t n;        // number of slots
    size_t m;        // numbur of key/value pairs stored
    size_t max_m;    // number of stored keys before we resize

    size_t*  slot_sizes;
    slot_t*  slots;
} ahtable_t;

extern const double ahtable_max_load_factor;
extern const size_t ahtable_initial_size;

ahtable_t* ahtable_create   (void);         // Create an empty hash table.
ahtable_t* ahtable_create_n (size_t n);     // Create an empty hash table, with
                                            //  n slots reserved.

void       ahtable_free   (ahtable_t*);       // Free all memory used by a table.
void       ahtable_clear  (ahtable_t*);       // Remove all entries.
size_t     ahtable_size   (const ahtable_t*); // Number of stored keys.


/** Find the given key in the table, inserting it if it does not exist, and
 * returning a pointer to it's key.
 *
 * This pointer is not guaranteed to be valid after additional calls to
 * ahtable_get, ahtable_del, ahtable_clear, or other functions that modifies the
 * table.
 */
value_t* ahtable_get (ahtable_t*, const char* key, size_t len);


/** Find a given key in the table, returning a NULL pointer if it does not
 * exist. */
value_t* ahtable_tryget (ahtable_t*, const char* key, size_t len);


int ahtable_del(ahtable_t*, const char* key, size_t len);


typedef struct ahtable_iter_t_ ahtable_iter_t;

ahtable_iter_t* ahtable_iter_begin     (const ahtable_t*, bool sorted);
void            ahtable_iter_next      (ahtable_iter_t*);
bool            ahtable_iter_finished  (ahtable_iter_t*);
void            ahtable_iter_free      (ahtable_iter_t*);
const char*     ahtable_iter_key       (ahtable_iter_t*, size_t* len);
value_t*        ahtable_iter_val       (ahtable_iter_t*);


#ifdef __cplusplus
}
#endif

#endif

