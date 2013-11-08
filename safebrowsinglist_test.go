/*
Copyright (c) 2013, Richard Johnson
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

	chunk := &Chunk{
		ChunkNum:  1,
		ChunkType: CHUNK_TYPE_ADD,
		HashLen:   4,
		Hashes: map[HostHash][]LookupHash{
			HostHash("test"): []LookupHash{
				LookupHash("test"),
				LookupHash("1234"),
			},
		},
	}
	ssl.load([]*Chunk{chunk})
	if len(ssl.LookupMap) != 1 ||
		len(ssl.LookupMap[HostHash("test")]) != 2 {
		t.Errorf("Hashes were not added to LookupMap")
		return
	}

	chunk = &Chunk{
		ChunkNum:  1,
		ChunkType: CHUNK_TYPE_SUB,
		HashLen:   4,
		Hashes: map[HostHash][]LookupHash{
			HostHash("test"): []LookupHash{
				LookupHash("test"),
			},
		},
	}
	ssl.load([]*Chunk{chunk})
	if len(ssl.LookupMap) != 1 ||
		len(ssl.LookupMap[HostHash("test")]) != 1 {
		t.Errorf("Hashes were not deleted from LookupMap")
		return
	}

	chunks := []*Chunk{
		&Chunk{
			ChunkNum:  2,
			ChunkType: CHUNK_TYPE_ADD,
			HashLen:   32,
			Hashes: map[HostHash][]LookupHash{
				HostHash("test"): []LookupHash{
					LookupHash("test1234123412341234123412341234"),
					LookupHash("12341234123412341234123412341234"),
				},
			},
		},
		&Chunk{
			ChunkNum:  2,
			ChunkType: CHUNK_TYPE_SUB,
			HashLen:   4,
			Hashes: map[HostHash][]LookupHash{
				HostHash("test"): []LookupHash{
					LookupHash("test"),
					LookupHash("1234"),
				},
			},
		},
	}
	ssl.load(chunks)

	// should now be empty
	if len(ssl.LookupMap) != 0 {
		t.Errorf("Failed to delete full length hash with prefix")
		return
	}

	// remove some of the chunks
	ssl.DeleteChunks = map[ChunkType]map[ChunkNum]bool{
		CHUNK_TYPE_ADD: map[ChunkNum]bool{1: true},
		CHUNK_TYPE_SUB: map[ChunkNum]bool{1: true, 2: true},
	}

	ssl.load(nil)

	// should have 2 of the entries in there again.
	if len(ssl.LookupMap) != 1 ||
		len(ssl.LookupMap[HostHash("test")]) != 2 {
		t.Errorf("Hashes were not deleted from LookupMap")
		return
	}

	os.Remove(testFilename)
}
