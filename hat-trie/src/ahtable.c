/*
 * This file is part of hat-trie.
 *
 * Copyright (c) 2011 by Daniel C. Jones <dcjones@cs.washington.edu>
 *
 */

#include "ahtable.h"
#include "misc.h"
#include "murmurhash3.h"
#include <assert.h>
#include <string.h>



const double ahtable_max_load_factor = 100000.0; /* arbitrary large number => don't resize */
const const size_t ahtable_initial_size = 4096;
static const uint16_t LONG_KEYLEN_MASK = 0x7fff;

static size_t keylen(slot_t s) {
    if (0x1 & *s) {
        return (size_t) (*((uint16_t*) s) >> 1);
    }
    else {
        return (size_t) (*s >> 1);
    }
}


ahtable_t* ahtable_create()
{
    return ahtable_create_n(ahtable_initial_size);
}


ahtable_t* ahtable_create_n(size_t n)
{
    ahtable_t* T = malloc_or_die(sizeof(ahtable_t));
    T->flag = 0;
    T->c0 = T->c1 = '\0';

    T->n = n;
    T->m = 0;
    T->max_m = (size_t) (ahtable_max_load_factor * (double) T->n);
    T->slots = malloc_or_die(n * sizeof(slot_t));
    memset(T->slots, 0, n * sizeof(slot_t));

    T->slot_sizes = malloc_or_die(n * sizeof(size_t));
    memset(T->slot_sizes, 0, n * sizeof(size_t));

    return T;
}


void ahtable_free(ahtable_t* T)
{
    if (T == NULL) return;
    size_t i;
    for (i = 0; i < T->n; ++i) free(T->slots[i]);
    free(T->slots);
    free(T->slot_sizes);
    free(T);
}


size_t ahtable_size(const ahtable_t* T)
{
    return T->m;
}


void ahtable_clear(ahtable_t* T)
{
    size_t i;
    for (i = 0; i < T->n; ++i) free(T->slots[i]);
    T->n = ahtable_initial_size;
    T->slots = realloc_or_die(T->slots, T->n * sizeof(slot_t));
    memset(T->slots, 0, T->n * sizeof(slot_t));

    T->slot_sizes = realloc_or_die(T->slot_sizes, T->n * sizeof(size_t));
    memset(T->slot_sizes, 0, T->n * sizeof(size_t));
}


static slot_t ins_key(slot_t s, const char* key, size_t len, value_t** val)
{
    // key length
    if (len < 128) {
        s[0] = (unsigned char) (len << 1);
        s += 1;
    }
    else {
        /* The most significant bit is set to indicate that two bytes are
         * being used to store the key length. */
        *((uint16_t*) s) = ((uint16_t) len << 1) | 0x1;
        s += 2;
    }

    // key
    memcpy(s, key, len * sizeof(unsigned char));
    s += len;

    // value
    *val = (value_t*) s;
    **val = 0;
    s += sizeof(value_t);

    return s;
}


static void ahtable_expand(ahtable_t* T)
{
    /* Resizing a table is essentially building a brand new one.
     * One little shortcut we can take on the memory allocation front is to
     * figure out how much memory each slot needs in advance.
     */
    assert(T->n > 0);
    size_t new_n = 2 * T->n;
    size_t* slot_sizes = malloc_or_die(new_n * sizeof(size_t));
    memset(slot_sizes, 0, new_n * sizeof(size_t));

    const char* key;
    size_t len = 0;
    size_t m = 0;
    ahtable_iter_t* i = ahtable_iter_begin(T, false);
    while (!ahtable_iter_finished(i)) {
        key = ahtable_iter_key(i, &len);
        slot_sizes[hash(key, len) % new_n] +=
            len + sizeof(value_t) + (len >= 128 ? 2 : 1);

        ++m;
        ahtable_iter_next(i);
    }
    assert(m == T->m);
    ahtable_iter_free(i);


    /* allocate slots */
    slot_t* slots = malloc_or_die(new_n * sizeof(slot_t));
    size_t j;
    for (j = 0; j < new_n; ++j) {
        if (slot_sizes[j] > 0) {
            slots[j] = malloc_or_die(slot_sizes[j]);
        }
        else slots[j] = NULL;
    }

    /* rehash values. A few shortcuts can be taken here as well, as we know
     * there will be no collisions. Instead of the regular insertion routine,
     * we keep track of the ends of every slot and simply insert keys.
     * */
    slot_t* slots_next = malloc_or_die(new_n * sizeof(slot_t));
    memcpy(slots_next, slots, new_n * sizeof(slot_t));
    size_t h;
    m = 0;
    value_t* u;
    value_t* v;
    i = ahtable_iter_begin(T, false);
    while (!ahtable_iter_finished(i)) {

        key = ahtable_iter_key(i, &len);
        h = hash(key, len) % new_n;

        slots_next[h] = ins_key(slots_next[h], key, len, &u);
        v = ahtable_iter_val(i);
        *u = *v;

        ++m;
        ahtable_iter_next(i);
    }
    assert(m == T->m);
    ahtable_iter_free(i);


    free(slots_next);
    for (j = 0; j < T->n; ++j) free(T->slots[j]);

    free(T->slots);
    T->slots = slots;

    free(T->slot_sizes);
    T->slot_sizes = slot_sizes;

    T->n = new_n;
    T->max_m = (size_t) (ahtable_max_load_factor * (double) T->n);
}


static value_t* get_key(ahtable_t* T, const char* key, size_t len, bool insert_missing)
{
    /* if we are at capacity, preemptively resize */
    if (insert_missing && T->m >= T->max_m) {
        ahtable_expand(T);
    }


    uint32_t i = hash(key, len) % T->n;
    size_t k;
    slot_t s;
    value_t* val;

    /* search the array for our key */
    s = T->slots[i];
    while ((size_t) (s - T->slots[i]) < T->slot_sizes[i]) {
        /* get the key length */
        k = keylen(s);
        s += k < 128 ? 1 : 2;

        /* skip keys that are longer than ours */
        if (k != len) {
            s += k + sizeof(value_t);
            continue;
        }

        /* key found. */
        if (memcmp(s, key, len) == 0) {
            return (value_t*) (s + len);
        }
        /* key not found. */
        else {
            s += k + sizeof(value_t);
            continue;
        }
    }


    if (insert_missing) {
        /* the key was not found, so we must insert it. */
        size_t new_size = T->slot_sizes[i];
        new_size += 1 + (len >= 128 ? 1 : 0);    // key length
        new_size += len * sizeof(unsigned char); // key
        new_size += sizeof(value_t);             // value

        T->slots[i] = realloc_or_die(T->slots[i], new_size);

        ++T->m;
        ins_key(T->slots[i] + T->slot_sizes[i], key, len, &val);
        T->slot_sizes[i] = new_size;

        return val;
    }
    else return NULL;
}


value_t* ahtable_get(ahtable_t* T, const char* key, size_t len)
{
    return get_key(T, key, len, true);
}


value_t* ahtable_tryget(ahtable_t* T, const char* key, size_t len )
{
    return get_key(T, key, len, false);
}


int ahtable_del(ahtable_t* T, const char* key, size_t len)
{
    uint32_t i = hash(key, len) % T->n;
    size_t k;
    slot_t s;

    /* search the array for our key */
    s = T->slots[i];
    while ((size_t) (s - T->slots[i]) < T->slot_sizes[i]) {
        /* get the key length */
        k = keylen(s);
        s += k < 128 ? 1 : 2;

        /* skip keys that are longer than ours */
        if (k != len) {
            s += k + sizeof(value_t);
            continue;
        }

        /* key found. */
        if (memcmp(s, key, len) == 0) {
            /* move everything over, resize the array */
            unsigned char* t = s + len + sizeof(value_t);
            s -= k < 128 ? 1 : 2;
            memmove(s, t, T->slot_sizes[i] - (size_t) (t - T->slots[i]));
            T->slot_sizes[i] -= (size_t) (t - s);
            --T->m;
            return 0;
        }
        /* key not found. */
        else {
            s += k + sizeof(value_t);
            continue;
        }
    }

    // Key was not found. Do nothing.
    return -1;
}



static int cmpkey(const void* a_, const void* b_)
{
    slot_t a = *(slot_t*) a_;
    slot_t b = *(slot_t*) b_;

    size_t ka = keylen(a), kb = keylen(b);

    a += ka < 128 ? 1 : 2;
    b += kb < 128 ? 1 : 2;

    int c = memcmp(a, b, ka < kb ? ka : kb);
    return c == 0 ? (int) ka - (int) kb : c;
}


/* Sorted/unsorted iterators are kept private and exposed by passing the
sorted flag to ahtable_iter_begin. */

typedef struct ahtable_sorted_iter_t_
{
    const ahtable_t* T; // parent
    slot_t* xs; // pointers to keys
    size_t i; // current key
} ahtable_sorted_iter_t;


static ahtable_sorted_iter_t* ahtable_sorted_iter_begin(const ahtable_t* T)
{
    ahtable_sorted_iter_t* i = malloc_or_die(sizeof(ahtable_sorted_iter_t));
    i->T = T;
    i->xs = malloc_or_die(T->m * sizeof(slot_t));
    i->i = 0;

    slot_t s;
    size_t j, k, u;
    for (j = 0, u = 0; j < T->n; ++j) {
        s = T->slots[j];
        while (s < T->slots[j] + T->slot_sizes[j]) {
            i->xs[u++] = s;
            k = keylen(s);
            s += k < 128 ? 1 : 2;
            s += k + sizeof(value_t);
        }
    }

    qsort(i->xs, T->m, sizeof(slot_t), cmpkey);

    return i;
}


static bool ahtable_sorted_iter_finished(ahtable_sorted_iter_t* i)
{
    return i->i >= i->T->m;
}


static void ahtable_sorted_iter_next(ahtable_sorted_iter_t* i)
{
    if (ahtable_sorted_iter_finished(i)) return;
    ++i->i;
}


static void ahtable_sorted_iter_free(ahtable_sorted_iter_t* i)
{
    if (i == NULL) return;
    free(i->xs);
    free(i);
}


static const char* ahtable_sorted_iter_key(ahtable_sorted_iter_t* i, size_t* len)
{
    if (ahtable_sorted_iter_finished(i)) return NULL;

    slot_t s = i->xs[i->i];
    *len = keylen(s);

    return (const char*) (s + (*len < 128 ? 1 : 2));
}


static value_t*  ahtable_sorted_iter_val(ahtable_sorted_iter_t* i)
{
    if (ahtable_sorted_iter_finished(i)) return NULL;

    slot_t s = i->xs[i->i];
    size_t k = keylen(s);

    s += k < 128 ? 1 : 2;
    s += k;

    return (value_t*) s;
}


typedef struct ahtable_unsorted_iter_t_
{
    const ahtable_t* T; // parent
    size_t i;           // slot index
    slot_t s;           // slot position
} ahtable_unsorted_iter_t;


static ahtable_unsorted_iter_t* ahtable_unsorted_iter_begin(const ahtable_t* T)
{
    ahtable_unsorted_iter_t* i = malloc_or_die(sizeof(ahtable_unsorted_iter_t));
    i->T = T;

    for (i->i = 0; i->i < i->T->n; ++i->i) {
        i->s = T->slots[i->i];
        if ((size_t) (i->s - T->slots[i->i]) >= T->slot_sizes[i->i]) continue;
        break;
    }

    return i;
}


static bool ahtable_unsorted_iter_finished(ahtable_unsorted_iter_t* i)
{
    return i->i >= i->T->n;
}


static void ahtable_unsorted_iter_next(ahtable_unsorted_iter_t* i)
{
    if (ahtable_unsorted_iter_finished(i)) return;

    /* get the key length */
    size_t k = keylen(i->s);
    i->s += k < 128 ? 1 : 2;

    /* skip to the next key */
    i->s += k + sizeof(value_t);

    if ((size_t) (i->s - i->T->slots[i->i]) >= i->T->slot_sizes[i->i]) {
        do {
            ++i->i;
        } while(i->i < i->T->n &&
                i->T->slot_sizes[i->i] == 0);

        if (i->i < i->T->n) i->s = i->T->slots[i->i];
        else i->s = NULL;
    }
}


static void ahtable_unsorted_iter_free(ahtable_unsorted_iter_t* i)
{
    free(i);
}


static const char* ahtable_unsorted_iter_key(ahtable_unsorted_iter_t* i, size_t* len)
{
    if (ahtable_unsorted_iter_finished(i)) return NULL;

    slot_t s = i->s;
    size_t k;
    if (0x1 & *s) {
        k = (size_t) (*((uint16_t*) s)) >> 1;
        s += 2;
    }
    else {
        k = (size_t) (*s >> 1);
        s += 1;
    }

    *len = k;
    return (const char*) s;
}


static value_t* ahtable_unsorted_iter_val(ahtable_unsorted_iter_t* i)
{
    if (ahtable_unsorted_iter_finished(i)) return NULL;

    slot_t s = i->s;

    size_t k;
    if (0x1 & *s) {
        k = (size_t) (*((uint16_t*) s)) >> 1;
        s += 2;
    }
    else {
        k = (size_t) (*s >> 1);
        s += 1;
    }

    s += k;
    return (value_t*) s;
}


struct ahtable_iter_t_
{
    bool sorted;
    union {
        ahtable_unsorted_iter_t* unsorted;
        ahtable_sorted_iter_t* sorted;
    } i;
};


ahtable_iter_t* ahtable_iter_begin(const ahtable_t* T, bool sorted) {
    ahtable_iter_t* i = malloc_or_die(sizeof(ahtable_iter_t));
    i->sorted = sorted;
    if (sorted) i->i.sorted   = ahtable_sorted_iter_begin(T);
    else        i->i.unsorted = ahtable_unsorted_iter_begin(T);
    return i;
}


void ahtable_iter_next(ahtable_iter_t* i)
{
    if (i->sorted) ahtable_sorted_iter_next(i->i.sorted);
    else           ahtable_unsorted_iter_next(i->i.unsorted);
}


bool ahtable_iter_finished(ahtable_iter_t* i)
{
    if (i->sorted) return ahtable_sorted_iter_finished(i->i.sorted);
    else           return ahtable_unsorted_iter_finished(i->i.unsorted);
}


void ahtable_iter_free(ahtable_iter_t* i)
{
    if (i == NULL) return;
    if (i->sorted) ahtable_sorted_iter_free(i->i.sorted);
    else           ahtable_unsorted_iter_free(i->i.unsorted);
    free(i);
}


const char* ahtable_iter_key(ahtable_iter_t* i, size_t* len)
{
    if (i->sorted) return ahtable_sorted_iter_key(i->i.sorted, len);
    else           return ahtable_unsorted_iter_key(i->i.unsorted, len);
}


value_t* ahtable_iter_val(ahtable_iter_t* i)
{
    if (i->sorted) return ahtable_sorted_iter_val(i->i.sorted);
    else           return ahtable_unsorted_iter_val(i->i.unsorted);
}

