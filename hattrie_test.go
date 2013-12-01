package safebrowsing

import (
	"testing"
)

func TestNewTrie(t *testing.T) {
	trie := NewTrie()
	val := trie.Get("asdf")
	if val != false {
		t.Fatal("Unset value returned as true")
	}
	trie.Set("asdf")
	val = trie.Get("asdf")
	if val != true {
		t.Fatal("Set value returned as false")
	}
	trie.Delete("asdf")
	val = trie.Get("asdf")
	if val != false {
		t.Fatal("Deleted value returned as true")
	}
}

func TestDeleteFromTrie(t *testing.T) {
	trie := NewTrie()
	trie.Delete("asdf")
	val := trie.Get("asdf")
	if val != false {
		t.Fatal("Unset value returned as true")
	}
}
