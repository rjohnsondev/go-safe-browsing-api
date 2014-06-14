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
	"bufio"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"
)

// This calculated assuming a size of 500,000 entries
// and a false-positive probability of 1.0E-20
// thanks to http://hur.st/bloomfilter?n=500000&p=1.0E-20
const BLOOM_FILTER_BITS = 50000000
const BLOOM_FILTER_HASHES = 66

type SafeBrowsingList struct {
	Name          string
	FileName      string
	DataRedirects []string
	DeleteChunks  map[ChunkType]map[ChunkNum]bool

	ChunkRanges map[ChunkType]string

	HashPrefixLen int
	// We have the lookup map keyed by host hash, this may mean we have
	// to do duplicated full has requests for the same hash prefix on
	// different hosts, but that should be a pretty rare occurance.
	Lookup            *HatTrie
	FullHashRequested *HatTrie
	FullHashes        *HatTrie
	EntryCount        int
	Logger            logger
	updateLock        *sync.RWMutex
}

func newSafeBrowsingList(name string, filename string) (ssl *SafeBrowsingList) {
	ssl = &SafeBrowsingList{
		Name:              name,
		FileName:          filename,
		DataRedirects:     make([]string, 0),
		Lookup:            NewTrie(),
		FullHashRequested: NewTrie(),
		FullHashes:        NewTrie(),
		DeleteChunks:      make(map[ChunkType]map[ChunkNum]bool),
		Logger:            &DefaultLogger{},
		updateLock:        new(sync.RWMutex),
	}
	ssl.DeleteChunks[CHUNK_TYPE_ADD] = make(map[ChunkNum]bool)
	ssl.DeleteChunks[CHUNK_TYPE_SUB] = make(map[ChunkNum]bool)
	return ssl
}

func (ssl *SafeBrowsingList) load(newChunks []*Chunk) (err error) {
	ssl.Logger.Info("Reloading %s", ssl.Name)
	ssl.updateLock.Lock()

	//  get the input stream
	f, err := os.Open(ssl.FileName)
	if err != nil {
		ssl.Logger.Warn("Error opening data file for reading, assuming empty: %s", err)
	}
	var dec *gob.Decoder = nil
	if f != nil {
		dec = gob.NewDecoder(f)
	}

	// open the file again for output
	fOut, err := os.Create(ssl.FileName + ".tmp")
	if err != nil {
		ssl.updateLock.Unlock()
		return fmt.Errorf("Error opening file: %s", err)
	}
	enc := gob.NewEncoder(fOut)

	// the chunks we loaded for the next request to the server
	addChunkIndexes := make(map[ChunkNum]bool)
	subChunkIndexes := make(map[ChunkNum]bool)

	// reset the lookup map
	newEntryCount := 0
	subEntryCount := 0

	deletedChunkCount := 0

	// load 'em up boys
	if dec != nil {
		for {
			chunk := &Chunk{}
			err = dec.Decode(&chunk)
			if err != nil {
				break
			}
			if _, exists := ssl.DeleteChunks[chunk.ChunkType][chunk.ChunkNum]; exists {
				// skip this chunk, we've been instructed to delete it
				deletedChunkCount++
				continue
			}
			if enc != nil {
				err = enc.Encode(chunk)
				if err != nil {
					ssl.updateLock.Unlock()
					return err
				}
			}
			switch chunk.ChunkType {
			case CHUNK_TYPE_ADD:
				addChunkIndexes[chunk.ChunkNum] = true
				newEntryCount += len(chunk.Hashes)
			case CHUNK_TYPE_SUB:
				subChunkIndexes[chunk.ChunkNum] = true
				subEntryCount += len(chunk.Hashes)
			}
			// apply this chunk.
			ssl.updateLookupMap(chunk)
		}
		if err != io.EOF {
			ssl.updateLock.Unlock()
			return err
		}
	}

	// add on any new chunks
	if newChunks != nil {
		for _, chunk := range newChunks {
			if _, exists := ssl.DeleteChunks[chunk.ChunkType][chunk.ChunkNum]; exists {
				// skip this chunk, we've been instructed to delete it
				continue
			}
			if enc != nil {
				err = enc.Encode(chunk)
				if err != nil {
					ssl.updateLock.Unlock()
					return err
				}
			}
			switch chunk.ChunkType {
			case CHUNK_TYPE_ADD:
				addChunkIndexes[chunk.ChunkNum] = true
				newEntryCount += len(chunk.Hashes)
			case CHUNK_TYPE_SUB:
				subChunkIndexes[chunk.ChunkNum] = true
				subEntryCount += len(chunk.Hashes)
			}
			ssl.updateLookupMap(chunk)
		}
	}

	// now close off our files, discard the old and keep the new
	if f != nil {
		f.Close()
		fOut.Close()
		err = os.Remove(ssl.FileName)
		if err != nil {
			ssl.updateLock.Unlock()
			return err
		}
	}
	err = os.Rename(ssl.FileName+".tmp", ssl.FileName)
	if err != nil {
		ssl.updateLock.Unlock()
		return err
	}

	ssl.ChunkRanges = map[ChunkType]string{
		CHUNK_TYPE_ADD: buildChunkRanges(addChunkIndexes),
		CHUNK_TYPE_SUB: buildChunkRanges(subChunkIndexes),
	}
	ssl.DeleteChunks = make(map[ChunkType]map[ChunkNum]bool)
	ssl.Logger.Info("Loaded %d existing add chunks and %d sub chunks "+
		"(~ %d hashes added, ~ %d hashes removed), deleted %d chunks, added %d new chunks.",
		len(addChunkIndexes),
		len(subChunkIndexes),
		newEntryCount,
		subEntryCount,
		deletedChunkCount,
		len(newChunks),
	)
	ssl.updateLock.Unlock()
	return nil
}

func (ssl *SafeBrowsingList) loadDataFromRedirectLists() error {
	if len(ssl.DataRedirects) < 1 {
		ssl.Logger.Info("No pending updates available")
		return nil
	}

	newChunks := make([]*Chunk, 0)

	for _, url := range ssl.DataRedirects {
		response, err := request(url, "", false)
		if err != nil {
			return err
		}
		if response.StatusCode != 200 {
			return fmt.Errorf("Unexpected server response code: %d",
				response.StatusCode)
		}

		buf := bufio.NewReader(response.Body)
		for {
			chunk, err := ReadChunk(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
				return err
			}
			newChunks = append(newChunks, chunk)
		}
	}
	return ssl.load(newChunks)
}

func (ssl *SafeBrowsingList) updateLookupMap(chunk *Chunk) {
	for hostHashString, hashes := range chunk.Hashes {
		hostHash := HostHash(hostHashString)
		for _, hash := range hashes {
			if len(hash) == 32 {
				// we are a full-length hash
				lookupHash := string(hostHash) + string(hash)
				switch chunk.ChunkType {
				case CHUNK_TYPE_ADD:
					ssl.Logger.Debug("Adding full length hash: %s",
						hex.EncodeToString([]byte(lookupHash)))
					ssl.FullHashes.Set(lookupHash)
				case CHUNK_TYPE_SUB:
					ssl.FullHashes.Delete(lookupHash)
				}

			} else {
				// update the hash prefix
				if ssl.HashPrefixLen == 0 {
					ssl.HashPrefixLen = chunk.HashLen
				} else if ssl.HashPrefixLen != chunk.HashLen {
					// ERR, more than one length hash in this list :/
					panic(fmt.Errorf(
						"Found more than 1 length hash in a single list, " +
							"this is currently unsupported"))
				}

				// we are a hash-prefix
				lookup := string(hostHash) + string(hash)
				switch chunk.ChunkType {
				case CHUNK_TYPE_ADD:
					ssl.Lookup.Set(lookup)
				case CHUNK_TYPE_SUB:
					ssl.Lookup.Delete(lookup)
					i := ssl.FullHashes.Iterator()
					for key := i.Next(); key != ""; key = i.Next() {
						keyPrefix := key[0:len(lookup)]
						if keyPrefix == lookup {
							ssl.FullHashes.Delete(key)
						}
					}
				}
			}
		}
	}
}
