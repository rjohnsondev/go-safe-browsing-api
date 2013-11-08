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
	"bytes"
	//"encoding/hex"
	"testing"
	//"fmt"
	"bufio"
)

func TestParseChunkHeader(t *testing.T) {
	header := "a:9:32:320\n" // newline should generally be ommitted
	chunk, err := parseChunkHeader(header)
	if err != nil {
		t.Error(err)
		return
	}
	if chunk.ChunkType != CHUNK_TYPE_ADD {
		t.Errorf("Bad chunk type")
	}
	if chunk.ChunkNum != 9 {
		t.Errorf("Bad chunk num")
	}
	if chunk.HashLen != 32 {
		t.Errorf("Bad hash length")
	}
	if chunk.ChunkLen != 320 {
		t.Errorf("Bad chunk length")
	}
	header = "a:9:32320"
	_, err = parseChunkHeader(header)
	if err == nil {
		t.Errorf("Parsed bad header")
	}
}

func TestChunkParsingA(t *testing.T) {
	// 32 byte hash
	chunkData := []byte{
		'a', ':', '9', ':', '3', '2', ':', '3', '7', '\n',
		0x01, 0x01, 0x01, 0x01, // Host Hash
		0x01, // hash count
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, // Hash Prefix (in this case full)
	}
	buf := bufio.NewReader(bytes.NewBuffer(chunkData))
	chunk, err := ReadChunk(buf)
	if err != nil {
		t.Error(err)
		return
	}
	if len(chunk.Hashes[HostHash([]byte{0x01, 0x01, 0x01, 0x01})]) != 1 {
		t.Error("Wrong number of hashes extracted")
		return
	}
	// 4 byte hash
	chunkData = []byte{
		'a', ':', '9', ':', '4', ':', '1', '7', '\n',
		0x01, 0x01, 0x01, 0x01, // Host Hash
		0x03, // hash count
		0x02, 0x02, 0x02, 0x01,
		0x02, 0x02, 0x02, 0x02,
		0x02, 0x02, 0x02, 0x03, // Hash Prefix (in this case full)
	}
	buf = bufio.NewReader(bytes.NewBuffer(chunkData))
	chunk, err = ReadChunk(buf)
	if err != nil {
		t.Error(err)
		return
	}
	if len(chunk.Hashes[HostHash([]byte{0x01, 0x01, 0x01, 0x01})]) != 3 {
		t.Error("Wrong number of hashes extracted")
		return
	}
	// host only chunk
	chunkData = []byte{
		'a', ':', '9', ':', '4', ':', '5', '\n',
		0x01, 0x01, 0x01, 0x01, // Host Hash
		0x00, // hash count
		// missing prefixes
	}
	buf = bufio.NewReader(bytes.NewBuffer(chunkData))
	chunk, err = ReadChunk(buf)
	if err != nil {
		t.Error(err)
		return
	}
	if len(chunk.Hashes[HostHash([]byte{0x01, 0x01, 0x01, 0x01})]) != 1 {
		t.Error("Didn't add self as hash")
		return
	}
}

func TestChunkParsingABad(t *testing.T) {
	// 32 byte hash
	chunkData := []byte{
		'a', ':', '9', ':', '3', '2', ':', '3', '6', '\n', // 36 is incorrect
		0x01, 0x01, 0x01, 0x01, // Host Hash
		0x01, // hash count
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, // Hash Prefix (in this case full)
	}
	buf := bufio.NewReader(bytes.NewBuffer(chunkData))
	_, err := ReadChunk(buf)
	if err == nil {
		t.Error("Parsed bad hash")
		return
	}
	chunkData = []byte{
		'a', ':', '9', ':', '3', '2', ':', '3', '7', '\n',
		0x01, 0x01, 0x01, 0x01, // Host Hash
		0x02, // hash count, 2 is incorrect
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, // Hash Prefix (in this case full)
	}
	buf = bufio.NewReader(bytes.NewBuffer(chunkData))
	_, err = ReadChunk(buf)
	if err == nil {
		t.Error("Parsed bad hash")
		return
	}
}

func TestChunkParsingS(t *testing.T) {
	// 32 byte hash
	chunkData := []byte{
		's', ':', '9', ':', '3', '2', ':', '4', '1', '\n',
		0x01, 0x01, 0x01, 0x01, // Host Hash
		0x01,                   // hash count
		0x00, 0x00, 0x00, 0x01, // Add hash number (big endian)
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, // Hash Prefix (in this case full)
	}
	buf := bufio.NewReader(bytes.NewBuffer(chunkData))
	chunk, err := ReadChunk(buf)
	if err != nil {
		t.Error(err)
		return
	}
	if len(chunk.Hashes[HostHash([]byte{0x01, 0x01, 0x01, 0x01})]) != 1 {
		t.Error("Wrong number of hashes extracted")
		return
	}
	if chunk.AddChunkNums[HostHash([]byte{0x01, 0x01, 0x01, 0x01})][0] != 1 {
		t.Error("Wrong add chunk number identified")
		return
	}
}

func TestFullHashChunkParsing(t *testing.T) {
	// 32 byte hash
	chunkData := append(
		[]byte("googpub-phish-shavar:9:32\n"),
		[]byte{
			0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
			0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
			0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
		}...,
	)
	buf := bufio.NewReader(bytes.NewBuffer(chunkData))
	hostHash := HostHash([]byte{0x01, 0x01, 0x01, 0x01})
	chunk, err := ReadFullHashChunk(buf, hostHash)
	if err != nil {
		t.Error(err)
		return
	}
	if len(chunk.Hashes[HostHash([]byte{0x01, 0x01, 0x01, 0x01})]) != 1 {
		t.Error("Wrong number of hashes extracted")
		return
	}

	// Deal with 2 full length hashes in a response...
	chunkData = append(
		chunkData,
		[]byte("googpub-phish-shavar:9:32\n")...,
	)
	chunkData = append(
		chunkData,
		[]byte{
			'.', '.', '.', '.', '.', '.', '.', '.',
			'.', '.', '.', '.', '.', '.', '.', '.',
			'.', '.', '.', '.', '.', '.', '.', '.',
			'.', '.', '.', '.', '.', '.', '.', '.',
		}...,
	)
	buf = bufio.NewReader(bytes.NewBuffer(chunkData))
	chunk, err = ReadFullHashChunk(buf, hostHash)
	if err != nil {
		t.Error(err)
		return
	}
	if len(chunk.Hashes[HostHash([]byte{0x01, 0x01, 0x01, 0x01})]) != 1 {
		t.Error("Wrong number of hashes extracted")
		return
	}
	chunk, err = ReadFullHashChunk(buf, hostHash)
	if err != nil {
		t.Error(err)
		return
	}
	if len(chunk.Hashes[HostHash([]byte{0x01, 0x01, 0x01, 0x01})]) != 1 {
		t.Error("Wrong number of hashes extracted")
		return
	}
}
