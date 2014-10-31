/*
Copyright (c) 2013, Richard Johnson
Copyright (c) 2014, Kilian Gilonne
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package safebrowsing

import "code.google.com/p/goprotobuf/proto"

import (
	"io/ioutil"
	"os"
	"testing"
)

func getTempFilename() (string, error) {
	f, err := ioutil.TempFile("", "test")
	if err != nil {
		return "", err
	}
	filename := f.Name()
	f.Close()
	return filename, nil
}

func TestLoad(t *testing.T) {
	testFilename, err := getTempFilename()
	if err != nil {
		t.Error(err)
		return
	}
	ssl := newSafeBrowsingList("test", testFilename)

	chunk := &ChunkData{
		ChunkNumber: proto.Int32(1),
		ChunkType:   CHUNK_TYPE_ADD.Enum(),
		PrefixType:  PREFIX_4B.Enum(),
		Hashes:      []byte("test1234"),
	}
	ssl.load([]*ChunkData{chunk})
	if !ssl.Lookup.Get("test") {
		t.Errorf("Hashes were not added to LookupMap")
		return
	}
	if !ssl.Lookup.Get("1234") {
		t.Errorf("Hashes were not added to LookupMap")
		return
	}

	chunk = &ChunkData{
		ChunkNumber: proto.Int32(1),
		ChunkType:   CHUNK_TYPE_SUB.Enum(),
		PrefixType:  PREFIX_4B.Enum(),
		Hashes:      []byte("test"),
	}
	ssl.load([]*ChunkData{chunk})
	if ssl.Lookup.Get("test") {
		t.Errorf("Hashes were not deleted from LookupMap")
		return
	}

	chunks := []*ChunkData{
		&ChunkData{
			ChunkNumber: proto.Int32(2),
			ChunkType:   CHUNK_TYPE_SUB.Enum(),
			PrefixType:  PREFIX_32B.Enum(),
			Hashes:      []byte("test123412341234123412341234123412341234123412341234123412341234"),
		},
		&ChunkData{
			ChunkNumber: proto.Int32(2),
			ChunkType:   CHUNK_TYPE_ADD.Enum(),
			PrefixType:  PREFIX_4B.Enum(),
			Hashes:      []byte("test1234"),
		},
	}
	ssl.load(chunks)

	// should now be empty
	i := ssl.FullHashes.Iterator()
	for key := i.Next(); key != ""; key = i.Next() {
		if ssl.FullHashes.Get(key) {
			t.Errorf("Failed to delete full length hash with prefix")
			return
		}
	}

	// remove some of the chunks
	ssl.DeleteChunks = map[ChunkData_ChunkType]map[ChunkNum]bool{
		CHUNK_TYPE_ADD: map[ChunkNum]bool{1: true},
		CHUNK_TYPE_SUB: map[ChunkNum]bool{1: true, 2: true},
	}

	ssl.load(nil)

	// should have 2 of the entries in there again, test and 1234
	i = ssl.Lookup.Iterator()
	if ssl.Lookup.Get(i.Next()) != true || ssl.Lookup.Get(i.Next()) != true {
		t.Errorf("Hashes were deleted from LookupMap")
		return
	}

	os.Remove(testFilename)
}
