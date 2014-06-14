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
	"fmt"
	"testing"
)

func TestParseChunkList(t *testing.T) {
	compareListAndString := func(list []int, str string) error {
		listOutput, err := parseChunkRange(str)
		if err != nil {
			return fmt.Errorf("Error parsing range: %s", err)
		}
		for _, value := range list {
			if _, exists := listOutput[ChunkNum(value)]; !exists {
				return fmt.Errorf("Missed value: %d", value)
			}
		}
		return nil
	}
	if err := compareListAndString([]int{1}, "1"); err != nil {
		t.Error(err)
	}
	if err := compareListAndString([]int{1, 2}, "1-2"); err != nil {
		t.Error(err)
	}
	if err := compareListAndString([]int{1, 3}, "1,3"); err != nil {
		t.Error(err)
	}
	if err := compareListAndString([]int{1, 2, 3}, "1-3"); err != nil {
		t.Error(err)
	}
	if err := compareListAndString([]int{1, 2, 3, 5, 6}, "1-3,5-6"); err != nil {
		t.Error(err)
	}
	if err := compareListAndString([]int{1, 3, 5}, "1,3,5"); err != nil {
		t.Error(err)
	}
	if err := compareListAndString([]int{1, 2, 3, 4, 5, 6}, "1-6"); err != nil {
		t.Error(err)
	}
	if err := compareListAndString([]int{1, 3, 4, 5, 6}, "1,3-6"); err != nil {
		t.Error(err)
	}
	if err := compareListAndString([]int{1, 5, 6, 7, 10}, "1,5-7,10"); err != nil {
		t.Error(err)
	}
	if err := compareListAndString([]int{2, 3, 4, 5, 10}, "2-5,10"); err != nil {
		t.Error(err)
	}
}

func TestBuildChunkList(t *testing.T) {
	list := map[ChunkNum]bool{
		1: true,
	}
	listOutput := buildChunkRanges(list)
	if listOutput != "1" {
		t.Errorf("Failed to generate for list 1: " + listOutput)
	}
	list = map[ChunkNum]bool{
		1: true,
		2: true,
	}
	listOutput = buildChunkRanges(list)
	if listOutput != "1-2" {
		t.Errorf("Failed to generate for list 2: " + listOutput)
	}
	list = map[ChunkNum]bool{
		1: true,
		3: true,
	}
	listOutput = buildChunkRanges(list)
	if listOutput != "1,3" {
		t.Errorf("Failed to generate for list 3: " + listOutput)
	}
	list = map[ChunkNum]bool{
		1: true,
		2: true,
		3: true,
	}
	listOutput = buildChunkRanges(list)
	if listOutput != "1-3" {
		t.Errorf("Failed to generate for list 4: " + listOutput)
	}
	list = map[ChunkNum]bool{
		1: true,
		2: true,
		3: true,
		5: true,
		6: true,
	}
	listOutput = buildChunkRanges(list)
	if listOutput != "1-3,5-6" {
		t.Errorf("Failed to generate for list 5: " + listOutput)
	}
	list = map[ChunkNum]bool{
		1: true,
		3: true,
		5: true,
	}
	listOutput = buildChunkRanges(list)
	if listOutput != "1,3,5" {
		t.Errorf("Failed to generate for list 6: " + listOutput)
	}
	list = map[ChunkNum]bool{
		1: true,
		2: true,
		3: true,
		4: true,
		5: true,
		6: true,
	}
	listOutput = buildChunkRanges(list)
	if listOutput != "1-6" {
		t.Errorf("Failed to generate for list 7: " + listOutput)
	}
	list = map[ChunkNum]bool{
		1: true,
		3: true,
		4: true,
		5: true,
		6: true,
	}
	listOutput = buildChunkRanges(list)
	if listOutput != "1,3-6" {
		t.Errorf("Failed to generate for list 8: " + listOutput)
	}
	list = map[ChunkNum]bool{
		1:  true,
		5:  true,
		6:  true,
		7:  true,
		10: true,
	}
	listOutput = buildChunkRanges(list)
	if listOutput != "1,5-7,10" {
		t.Errorf("Failed to generate for list 9: " + listOutput)
	}
	list = map[ChunkNum]bool{
		2:  true,
		3:  true,
		4:  true,
		5:  true,
		10: true,
	}
	listOutput = buildChunkRanges(list)
	if listOutput != "2-5,10" {
		t.Errorf("Failed to generate for list 10: " + listOutput)
	}
}
