package safebrowsing

/*
#cgo LDFLAGS: -lhat-trie

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hat-trie/hat-trie.h>

hattrie_t* start() {
	hattrie_t* trie;

	trie = hattrie_create();

	return trie;
}

void set(hattrie_t* h, char* key) {
	value_t* val;
	val = hattrie_get(h, key, strlen(key));
	*val = 1;
}

int get(hattrie_t* h, char* key) {
	value_t* val;
	val = hattrie_tryget(h, key, strlen(key));
	if (val != 0) {
		return *val;
	}
	return 0;
}

void delete(hattrie_t* h, char* key) {
	value_t* val;
	val = hattrie_tryget(h, key, strlen(key));
	if (val != 0) {
		*val = 0;
	}
}

char* hattrie_iter_key_string(hattrie_iter_t* i) {
	size_t len;
	const char* in_key;
	char* out_key;
	in_key = hattrie_iter_key(i, &len);
	out_key = malloc((len + 1) * sizeof(char));
	memcpy(out_key, in_key, len);
	out_key[len] = 0;
	return out_key;
}

*/
import "C"

import (
	"runtime"
	"unsafe"
)

type HatTrie struct {
	trie *C.hattrie_t
}

func finalizeHatTrie(c *HatTrie) {
	C.hattrie_free(c.trie)
}

func NewTrie() *HatTrie {
	trie := C.start()
	out := &HatTrie{
		trie: trie,
	}
	runtime.SetFinalizer(out, finalizeHatTrie)
	return out
}

func (h *HatTrie) Delete(key string) {
	ckey := C.CString(key)
	defer C.free(unsafe.Pointer(ckey))
	C.delete(h.trie, ckey)
}

func (h *HatTrie) Set(key string) {
	ckey := C.CString(key)
	defer C.free(unsafe.Pointer(ckey))
	C.set(h.trie, ckey)
}

func (h *HatTrie) Get(key string) bool {
	ckey := C.CString(key)
	defer C.free(unsafe.Pointer(ckey))
	val := C.get(h.trie, ckey)
	return val == 1
}

type HatTrieIterator struct {
	iterator *C.hattrie_iter_t
}

func finalizeHatTrieIterator(i *HatTrieIterator) {
	C.hattrie_iter_free(i.iterator)
}

func (h *HatTrie) Iterator() *HatTrieIterator {
	out := C.hattrie_iter_begin(h.trie, true)
	hi := &HatTrieIterator{
		iterator: out,
	}
	runtime.SetFinalizer(hi, finalizeHatTrieIterator)
	return hi
}

func (i *HatTrieIterator) Next() string {
	if C.hattrie_iter_finished(i.iterator) {
		return ""
	}
	ckey := C.hattrie_iter_key_string(i.iterator)
	defer C.free(unsafe.Pointer(ckey))
	key := C.GoString(ckey)
	C.hattrie_iter_next(i.iterator)
	return key
}
