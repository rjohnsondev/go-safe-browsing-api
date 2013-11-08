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
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type ChunkNum uint32
type ChunkType string

const CHUNK_TYPE_ADD = "a"
const CHUNK_TYPE_SUB = "s"

type Chunk struct {
	ChunkNum  ChunkNum
	ChunkType ChunkType
	HashLen   int
	ChunkLen  int
	Hashes    map[HostHash][]LookupHash
	// Note: AddChunkNums this is not used in this implementation. I was
	// unable to see in the docs any mention of sub chunks needing to match
	// both the hash and the add chunk number prior to a hash being removed
	// from the lookup.  I assume this is included in the protocol for
	// convience more than anything else.
	AddChunkNums map[HostHash][]uint32
}

func (c *Chunk) String() string {
	return fmt.Sprintf(`Chunk %d,
type: %s,
hash length (bytes): %d,
chunk length: %d,
Num hashes:  %d
`, c.ChunkNum,
		c.ChunkType,
		c.HashLen,
		c.ChunkLen,
		len(c.Hashes))
}

func parseChunkHeader(header string) (*Chunk, error) {
	header = strings.TrimSpace(header)
	headerParts := strings.Split(header, ":")
	if len(headerParts) != 4 {
		return nil, fmt.Errorf("Unexpected header: %s", header)
	}
	chunkNum, err := strconv.ParseUint(headerParts[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("Bad chunk num.")
	}
	hashLen, err := strconv.Atoi(headerParts[2])
	if err != nil {
		return nil, fmt.Errorf("Bad hash len.")
	}
	chunkLen, err := strconv.Atoi(headerParts[3])
	if err != nil {
		return nil, fmt.Errorf("Bad chunklen: %s", header)
	}
	chunk := &Chunk{
		ChunkNum:  ChunkNum(chunkNum),
		ChunkType: ChunkType(headerParts[0]),
		HashLen:   hashLen,
		ChunkLen:  chunkLen,
	}
	return chunk, nil
}

func readSlice(buf *bufio.Reader, numBytes int) (out []byte, err error) {
	err = nil
	out = make([]byte, 0, numBytes)
	for len(out) < numBytes && err == nil {
		more := make([]byte, numBytes-len(out))
		var noRead int
		noRead, err = buf.Read(more)
		out = append(out, more[:noRead]...)
	}
	return out, err
}

// Read a chunk from the provided buffer.
// The buffer cursor is left at the exact end of the read chunk,
// allowing for repeated calls to this function.
// Will return an io.EOF when the end of the stream is encountered.
func ReadChunk(buf *bufio.Reader) (chunk *Chunk, err error) {
	header, err := buf.ReadString('\n')
	if err != nil {
		return nil, err
	}
	chunk, err = parseChunkHeader(header[:len(header)-1])
	if err != nil {
		return nil, err
	}
	chunk.Hashes = make(map[HostHash][]LookupHash)
	chunk.AddChunkNums = make(map[HostHash][]uint32)
	chunkBytes, err := readSlice(buf, chunk.ChunkLen)
	if err != nil {
		return nil, fmt.Errorf("Unexpected end of chunk: %s", err)
	}
	for x := 0; x < chunk.ChunkLen; {
		if x+4 > len(chunkBytes) {
			return nil, fmt.Errorf("Unexpected end of chunk")
		}
		hostKey := HostHash(chunkBytes[x : x+4])
		x += 4
		if _, exists := chunk.Hashes[hostKey]; !exists {
			chunk.Hashes[hostKey] = make([]LookupHash, 0)
			if chunk.ChunkType == CHUNK_TYPE_SUB {
				chunk.AddChunkNums[hostKey] = make([]uint32, 0)
			}
		}
		if x > len(chunkBytes) {
			return nil, fmt.Errorf("Unexpected end of chunk")
		}
		count := uint(chunkBytes[x])
		x++
		if count == 0 {
			chunk.Hashes[hostKey] = append(
				chunk.Hashes[hostKey], LookupHash(hostKey))
			if chunk.ChunkType == CHUNK_TYPE_SUB {
				if x+4 > len(chunkBytes) {
					return nil, fmt.Errorf("Unexpected end of chunk")
				}
				addChunkNum, err := readChunkNumber(chunkBytes, x)
				x += 4
				if err != nil {
					return nil, err
				}
				chunk.AddChunkNums[hostKey] = append(
					chunk.AddChunkNums[hostKey], addChunkNum)
			}
			continue
		}
		for y := uint(0); y < count; y++ {
			if chunk.ChunkType == CHUNK_TYPE_SUB {
				if x+4 > len(chunkBytes) {
					return nil, fmt.Errorf("Unexpected end of chunk")
				}
				addChunkNum, err := readChunkNumber(chunkBytes, x)
				x += 4
				if err != nil {
					return nil, err
				}
				chunk.AddChunkNums[hostKey] = append(
					chunk.AddChunkNums[hostKey], addChunkNum)
			}
			if x+chunk.HashLen > len(chunkBytes) {
				return nil, fmt.Errorf("Unexpected end of chunk")
			}
			prefix := LookupHash(chunkBytes[x : x+chunk.HashLen])
			x += chunk.HashLen
			chunk.Hashes[hostKey] = append(chunk.Hashes[hostKey], prefix)
		}
	}
	return chunk, nil
}

func readChunkNumber(chunkBytes []byte, x int) (uint32, error) {
	addChunkNumBytes := chunkBytes[x : x+4]
	addChunkNum := uint32(0)
	err := binary.Read(
		bytes.NewBuffer(addChunkNumBytes),
		binary.BigEndian, &addChunkNum)
	if err != nil {
		return 0, err
	}
	return addChunkNum, nil
}

// Read a full-hash chunk from the provided buffer.
// The buffer cursor is left at the exact end of the read chunk,
// allowing for repeated calls to this function.
// Will return an io.EOF when the end of the stream is encountered.
// Full Hash chunks are slightly different in format to standard Add chunks,
// as we assume a 32 byte entry length.  HostHashes are not provided either,
// so we simply associate with the host hash we are currently checking.
func ReadFullHashChunk(buf *bufio.Reader, host HostHash) (chunk *Chunk, err error) {
	// got me some data!
	header, err := buf.ReadString('\n')
	if len(header) == 0 {
		return nil, io.EOF
	}
	bits := strings.Split(strings.TrimSpace(header), ":")
	chunkNum64, err := strconv.ParseUint(bits[1], 10, 32)
	if err != nil {
		return nil, err
	}
	chunkNum := ChunkNum(chunkNum64)
	chunkLen, err := strconv.Atoi(bits[2])
	if err != nil {
		return nil, err
	}
	chunk = &Chunk{
		ChunkNum:  chunkNum,
		ChunkType: CHUNK_TYPE_ADD,
		HashLen:   32,
		ChunkLen:  chunkLen,
		Hashes:    make(map[HostHash][]LookupHash),
	}
	chunk.Hashes[host] = make([]LookupHash, 0, chunkLen/chunk.HashLen)
	respBytes, err := readSlice(buf, chunk.ChunkLen)
	if err != nil {
		return nil, err
	}
	for x := 0; x < chunkLen/chunk.HashLen; x++ {
		startByte := x * chunk.HashLen
		if startByte+chunk.HashLen > len(respBytes) {
			return nil, fmt.Errorf("Unexpected end of chunk")
		}
		hashResp := LookupHash(respBytes[startByte : startByte+chunk.HashLen])
		chunk.Hashes[host] = append(chunk.Hashes[host], hashResp)
	}
	return chunk, nil
}
