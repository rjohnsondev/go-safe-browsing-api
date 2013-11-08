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
	"fmt"
	"io"
	"os"
)

type SafeBrowsingList struct {
	Name          string
	FileName      string
	DataRedirects []string
	DeleteChunks  map[ChunkType]map[ChunkNum]bool

	ChunkRanges map[ChunkType]string

	HashSizesBytes map[int]bool
	// We have the lookup map keyed by host hash, this may mean we have
	// to do duplicated full has requests for the same hash prefix on
	// different hosts, but that should be a pretty rare occurance.
	LookupMap         map[HostHash]map[LookupHash]ChunkNum
	FullHashRequested map[HostHash]map[LookupHash]bool
	EntryCount        int
	Logger            logger
}

func newSafeBrowsingList(name string, filename string) (ssl *SafeBrowsingList) {
	ssl = &SafeBrowsingList{
		Name:              name,
		FileName:          filename,
		DataRedirects:     make([]string, 0),
		HashSizesBytes:    make(map[int]bool),
		LookupMap:         make(map[HostHash]map[LookupHash]ChunkNum),
		FullHashRequested: make(map[HostHash]map[LookupHash]bool),
		DeleteChunks:      make(map[ChunkType]map[ChunkNum]bool),
		Logger:            &DefaultLogger{},
	}
	ssl.DeleteChunks[CHUNK_TYPE_ADD] = make(map[ChunkNum]bool)
	ssl.DeleteChunks[CHUNK_TYPE_SUB] = make(map[ChunkNum]bool)
	return ssl
}

func (ssl *SafeBrowsingList) load(newChunks []*Chunk) (err error) {

	ssl.Logger.Info("Reloading %s", ssl.Name)

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
		return fmt.Errorf("Error opening file: %s", err)
	}
	enc := gob.NewEncoder(fOut)

	// the chunks we loaded for the next request to the server
	addChunkIndexes := make(map[ChunkNum]bool)
	subChunkIndexes := make(map[ChunkNum]bool)

	// reset the lookup map
	newLookup := make(map[HostHash]map[LookupHash]ChunkNum)
	newEntryCount := 0

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
					return err
				}
			}
			switch chunk.ChunkType {
			case CHUNK_TYPE_ADD:
				addChunkIndexes[chunk.ChunkNum] = true
				newEntryCount += len(chunk.Hashes)
			case CHUNK_TYPE_SUB:
				subChunkIndexes[chunk.ChunkNum] = true
			}
			// apply this chunk.
			newLookup = updateLookupMap(newLookup, chunk)
		}
		if err != io.EOF {
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
					return err
				}
			}
			switch chunk.ChunkType {
			case CHUNK_TYPE_ADD:
				addChunkIndexes[chunk.ChunkNum] = true
				newEntryCount += len(chunk.Hashes)
			case CHUNK_TYPE_SUB:
				subChunkIndexes[chunk.ChunkNum] = true
			}
			// apply this chunk.
			ssl.HashSizesBytes[chunk.HashLen] = true
			newLookup = updateLookupMap(newLookup, chunk)
		}
	}

	// now close off our files, discard the old and keep the new
	if f != nil {
		f.Close()
		fOut.Close()
		err = os.Remove(ssl.FileName)
		if err != nil {
			return err
		}
	}
	err = os.Rename(ssl.FileName+".tmp", ssl.FileName)
	if err != nil {
		return err
	}

	ssl.ChunkRanges = map[ChunkType]string{
		CHUNK_TYPE_ADD: buildChunkRanges(addChunkIndexes),
		CHUNK_TYPE_SUB: buildChunkRanges(subChunkIndexes),
	}
	ssl.LookupMap = newLookup
	ssl.DeleteChunks = make(map[ChunkType]map[ChunkNum]bool)
	ssl.Logger.Info("Loaded %d existing add chunks and %d sub chunks " +
					"(~ %d hashes, over %d hosts), deleted %d, added %d.",
		len(addChunkIndexes),
		len(subChunkIndexes),
		newEntryCount,
		len(newLookup),
		deletedChunkCount,
		len(newChunks),
	)
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

func updateLookupMap(lookupMap map[HostHash]map[LookupHash]ChunkNum, chunk *Chunk) map[HostHash]map[LookupHash]ChunkNum {
	for hostHashString, hashes := range chunk.Hashes {
		hostHash := HostHash(hostHashString)
		for _, hash := range hashes {
			switch chunk.ChunkType {
			case CHUNK_TYPE_ADD:
				if _, exists := lookupMap[hostHash]; !exists {
					lookupMap[hostHash] = make(map[LookupHash]ChunkNum)
				}
				lookupMap[hostHash][hash] = chunk.ChunkNum
			case CHUNK_TYPE_SUB:
				if _, exists := lookupMap[hostHash]; !exists {
					continue
				}
				// TODO(rjohnsondev): this is kinda slow and rubbish...
				for fullTestHash, _ := range lookupMap[hostHash] {
					testHash := fullTestHash
					if len(testHash) > len(hash) {
						testHash = testHash[0:len(hash)]
					}
					if testHash == hash {
						delete(lookupMap[hostHash], fullTestHash)
					}
				}
				if len(lookupMap[hostHash]) == 0 {
					delete(lookupMap, hostHash)
				}
			}
		}
	}
	return lookupMap
}
