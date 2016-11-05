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

import (
	//"fmt"
	"os"
	"testing"
	"time"
	//"bytes"
	"bytes"
	//"encoding/hex"
	"crypto/sha256"
	"io/ioutil"
	"net/http"
	"sync"
	//"strings"
)

type MockReadCloser struct {
	buf *bytes.Buffer
}

func NewMockReadCloser(contents string) (mrc *MockReadCloser) {
	return &MockReadCloser{
		buf: bytes.NewBuffer([]byte(contents)),
	}
}
func (mrc *MockReadCloser) Read(p []byte) (n int, err error) {
	n, err = mrc.buf.Read(p)
	return n, err
}
func (mrc *MockReadCloser) Close() (err error) {
	return nil
}

func NewMockRequest(data string) func(string, string, bool) (*http.Response, error) {
	request := func(string, string, bool) (*http.Response, error) {
		response := &http.Response{
			StatusCode: 200,
			Body:       NewMockReadCloser(data),
		}
		return response, nil
	}
	return request
}

func TestSafeBrowsingLists(t *testing.T) {
	data := "googpub-phish-shavar\ngoog-malware-shavar"
	ss := &SafeBrowsing{
		request: NewMockRequest(data),
		Lists:   make(map[string]*SafeBrowsingList),
		Logger:  new(DefaultLogger),
	}
	err := ss.requestSafeBrowsingLists()
	if err != nil {
		t.Fatal(err)
	}
	if len(ss.Lists) != 2 {
		t.Error("List not processed correctly")
	}
}

func TestRedirectList(t *testing.T) {
	data := `n:1200
i:googpub-phish-shavar
u:cache.google.com/first_redirect_example
u:cache.google.com/first_redirect_example_1
sd:1,2
i:acme-white-shavar
u:cache.google.com/second_redirect_example
u:cache.google.com/second_redirect_example_2
ad:1-2,4-5,7
sd:2-6`
	ss := &SafeBrowsing{
		request: NewMockRequest(data),
		Lists: map[string]*SafeBrowsingList{
			"googpub-phish-shavar": newSafeBrowsingList("googpub-phish-shavar", ""),
			"acme-white-shavar":    newSafeBrowsingList("acme-white-shavar", ""),
		},
		Logger: new(DefaultLogger),
	}
	err, _ := ss.requestRedirectList()
	if err != nil {
		t.Error(err)
	}
	if len(ss.Lists["googpub-phish-shavar"].DataRedirects) != 2 {
		t.Error("Unable to parse redirect list")
	}
	if ss.Lists["googpub-phish-shavar"].DataRedirects[0] != "https://cache.google.com/first_redirect_example" {
		t.Error("Unable to parse redirect list")
	}
	if ss.Lists["acme-white-shavar"].DataRedirects[0] != "https://cache.google.com/second_redirect_example" {
		t.Error("Unable to parse redirect list")
	}
	if len(ss.Lists["googpub-phish-shavar"].DeleteChunks[CHUNK_TYPE_SUB]) != 2 {
		t.Error("Delete chunks not processed")
	}
	if len(ss.Lists["acme-white-shavar"].DeleteChunks[CHUNK_TYPE_ADD]) != 5 {
		t.Error("Delete chunks not processed")
	}
	if len(ss.Lists["acme-white-shavar"].DeleteChunks[CHUNK_TYPE_SUB]) != 5 {
		t.Error("Delete chunks not processed")
	}
	if ss.UpdateDelay != 1200 {
		t.Error("Update delay not parsed")
	}
}

func TestUrlListed(t *testing.T) {

	url := "http://test.com/"
	url = Canonicalize(url)
	urls := GenerateTestCandidates(url)
	url = urls[0]
	hasher := sha256.New()
	hasher.Write([]byte(url))
	hash := hasher.Sum(nil)
	chunkData := []byte("600\n" + "googpub-phish-shavar:32:1\n" + string(hash))
	tmpDirName, err := ioutil.TempDir("", "safebrowsing")
	if err != nil {
		t.Error(err)
		return
	}

	ss := &SafeBrowsing{
		LastUpdated: time.Now(),
		DataDir:     tmpDirName,
		Lists: map[string]*SafeBrowsingList{
			"googpub-phish-shavar": &SafeBrowsingList{
				Name:              "googpub-phish-shavar",
				FileName:          tmpDirName + "/googpub-phish-shavar.dat",
				Lookup:            NewTrie(),
				FullHashRequested: NewTrie(),
				FullHashes:        NewTrie(),
				Cache:             make(map[FullHash]*FullHashCache),
				DeleteChunks: map[ChunkData_ChunkType]map[ChunkNum]bool{
					CHUNK_TYPE_ADD: make(map[ChunkNum]bool),
					CHUNK_TYPE_SUB: make(map[ChunkNum]bool),
				},
				Logger: new(DefaultLogger),
				fsLock: new(sync.Mutex),
			},
		},
		Logger:  new(DefaultLogger),
		request: NewMockRequest(string(chunkData)),
	}
	ss.Lists["googpub-phish-shavar"].Lookup.Set(string(hash[:PREFIX_4B_SZ]))

	result, _, err := ss.MightBeListed(url)
	if err != nil {
		t.Error(err)
		return
	}
	if result == "" {
		t.Error("Hash was not found :/")
		return
	}

	result, err = ss.IsListed(url)
	if err != nil {
		t.Error(err)
		return
	}
	if result == "" {
		t.Error("Full hash was not found :/")
		return
	}
	os.RemoveAll(tmpDirName)
}
