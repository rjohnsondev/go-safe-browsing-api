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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"runtime/debug"
)

var SupportedLists map[string]bool = map[string]bool{
	"goog-malware-shavar":  true,
	"googpub-phish-shavar": true,
}

type HostHash string
type LookupHash string

type SafeBrowsing struct {
	Key         string
	Client      string
	AppVersion  string
	UpdateDelay int
	LastUpdated time.Time
	Lists       map[string]*SafeBrowsingList
	DataDir     string
	request     func(string, string, bool) (*http.Response, error)
	Logger		logger
}

var Logger logger = new(DefaultLogger)
var Client string = "api"
var AppVersion string = "1.0"
var OfflineMode bool = false

func NewSafeBrowsing(apiKey string, dataDirectory string) (ss *SafeBrowsing, err error) {
	ss = &SafeBrowsing{
		Key:        apiKey,
		Client:     Client,
		AppVersion: AppVersion,
		DataDir:    dataDirectory,
		Lists:      make(map[string]*SafeBrowsingList),
		request:    request,
		Logger:     Logger,
	}

	// if we are in offline mode we want to just load up the lists we
	// currently have and work with that
	if OfflineMode {
		for listName, _ := range SupportedLists {
			fileName := ss.DataDir + "/" + listName + ".dat"
			tmpList := newSafeBrowsingList(listName, fileName)
			tmpList.Logger = ss.Logger
			err := tmpList.load(nil)
			if err != nil {
				ss.Logger.Warn("Error loading list: %s", listName, err)
				continue
			}
			ss.Lists[listName] = tmpList
		}
		debug.FreeOSMemory()
		return ss, nil
	}

	// normal mode, contact the server for updates, etc.
	err = ss.update()
	if err != nil {
		return nil, err
	}
	go ss.reloadLoop()
	return ss, nil
}

func (ss *SafeBrowsing) reloadLoop() {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomFloat := r.Float64()
	for {
		// wait the update delay
		duration := time.Duration(ss.UpdateDelay) * time.Second
		ss.Logger.Info("Next update in %d seconds", ss.UpdateDelay)
		time.Sleep(duration)
		err := ss.update()
		for x := 0; err != nil; x++ {
			// first we wait 1 min, than some time between 30-60 mins
			// doubling until we stop at 480 mins or succeed
			mins := (30 * (randomFloat + 1) * float64(x)) + 1
			if mins > 480 {
				mins = 480
			}
			ss.Logger.Warn(
				"Update failed, in back-off mode (waiting %d mins): %s",
				mins,
				err,
			)
			time.Sleep(time.Duration(mins) * time.Minute)
			err = ss.update()
		}
		debug.FreeOSMemory()
	}
}

func (ss *SafeBrowsing) update() error {
	ss.Logger.Info("Requesting list of lists from server...")
	err := ss.requestSafeBrowsingLists()
	if err != nil {
		return err
	}

	ss.Logger.Info("Loading existing data....")
	for _, ssl := range ss.Lists {
		err := ssl.load(nil)
		if err != nil {
			return fmt.Errorf("Error loading list: %s", ss.DataDir, err)
		}
		debug.FreeOSMemory()
	}

	ss.Logger.Info("Requesting updates...")
	if err := ss.requestRedirectList(); err != nil {
		return fmt.Errorf("Unable to retrieve updates: %s", err.Error())
	}
	for listName, list := range ss.Lists {
		if err := list.loadDataFromRedirectLists(); err != nil {
			return fmt.Errorf("Unable to process updates for %s: %s", listName, err.Error())
		}
	}

	// update the last updated time
	ss.LastUpdated = time.Now()
	return nil
}

func (ss *SafeBrowsing) requestSafeBrowsingLists() (err error) {
	url := fmt.Sprintf(
		"http://safebrowsing.clients.google.com/safebrowsing/list?"+
			"client=%s&apikey=%s&appver=%s&pver=2.2",
		ss.Client, ss.Key, ss.AppVersion)
	listresp, err := ss.request(url, "", true)
	if err != nil {
		return err
	}
	if listresp.StatusCode != 200 {
		return fmt.Errorf("Unexpected server response code: %d", listresp.StatusCode)
	}
	return ss.processSafeBrowsingLists(listresp.Body)
}

func (ss *SafeBrowsing) processSafeBrowsingLists(body io.Reader) (err error) {
	buf := bytes.Buffer{}
	if _, err = buf.ReadFrom(body); err != nil {
		return fmt.Errorf("Unable to read list data: %s", err)
	}
	for _, listName := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if _, exists := SupportedLists[listName]; !exists {
			continue
		}
		fileName := ss.DataDir + "/" + listName + ".dat"
		tmpList := newSafeBrowsingList(listName, fileName)
		tmpList.Logger = ss.Logger
		ss.Lists[listName] = tmpList
	}
	return nil
}

func (ss *SafeBrowsing) requestRedirectList() error {
	url := fmt.Sprintf(
		"http://safebrowsing.clients.google.com/safebrowsing/downloads?"+
			"client=%s&apikey=%s&appver=%s&pver=2.2",
		ss.Client, ss.Key, ss.AppVersion)

	listsStr := ""
	for list, ssl := range ss.Lists {
		listsStr += string(list) + ";"
		addChunkRange := ssl.ChunkRanges[CHUNK_TYPE_ADD]
		if addChunkRange != "" {
			listsStr += "a:" + addChunkRange + ":"
		}
		subChunkRange := ssl.ChunkRanges[CHUNK_TYPE_SUB]
		if subChunkRange != "" {
			listsStr += "s:" + subChunkRange
		}
		listsStr += "\n"
	}
	redirects, err := ss.request(url, listsStr, true)
	if redirects.StatusCode != 200 {
		tmp := &bytes.Buffer{}
		tmp.ReadFrom(redirects.Body)
		return fmt.Errorf("Unexpected server response code: %d\n%s", redirects.StatusCode, tmp)
	}
	if err != nil {
		return err
	}
	if err = ss.processRedirectList(redirects.Body); err != nil {
		return err
	}
	return nil
}

func (ss *SafeBrowsing) reset() {
	for _, ssl := range ss.Lists {
		// recreate the lookup map
		ssl.LookupMap = make(map[HostHash]map[LookupHash]ChunkNum)
		// kill off the chunks
		ssl.ChunkRanges = map[ChunkType]string{
			CHUNK_TYPE_ADD: "",
			CHUNK_TYPE_SUB: "",
		}
		// delete any files we have loaded for this map
		if ssl.FileName != "" {
			os.Remove(ssl.FileName)
		}
	}
}

func (ss *SafeBrowsing) processRedirectList(buf io.Reader) error {
	scanner := bufio.NewScanner(buf)
	var currentList []string = nil
	currentDeletes := make(map[ChunkType]map[ChunkNum]bool)
	currentDeletes[CHUNK_TYPE_ADD] = make(map[ChunkNum]bool)
	currentDeletes[CHUNK_TYPE_SUB] = make(map[ChunkNum]bool)
	var currentListName string
	for scanner.Scan() {
		line := scanner.Text()
		bits := strings.SplitN(line, ":", 2)
		switch bits[0] {
		case "r":
			// we need to reset full!
			ss.reset()
			// the docs say to request again, so we do that...
			return ss.requestRedirectList()
		case "i":
			if currentList != nil {
				// save to DataRedirects
				ss.Lists[currentListName].DataRedirects = currentList
				ss.Lists[currentListName].DeleteChunks = currentDeletes
			}
			currentList = make([]string, 0)
			currentListName = bits[1]
			currentDeletes := make(map[ChunkType][]ChunkNum)
			currentDeletes[CHUNK_TYPE_ADD] = make([]ChunkNum, 0)
			currentDeletes[CHUNK_TYPE_SUB] = make([]ChunkNum, 0)
		case "u":
			currentList = append(currentList, "http://"+bits[1])
		case "n":
			updateDelayStr := bits[1]
			updateDelay, err := strconv.Atoi(updateDelayStr)
			if err != nil {
				return fmt.Errorf("Unable to parse timeout: %s", err)
			}
			ss.UpdateDelay = updateDelay
		case "e":
			svrError := bits[1]
			return fmt.Errorf("Error recieved from server: %s", svrError)
		case "ad":
			addDeletes, err := parseChunkRange(bits[1])
			if err != nil {
				return fmt.Errorf("Error parsing delete add chunks range: %s", err)
			}
			ss.Lists[currentListName].DeleteChunks[CHUNK_TYPE_ADD] = addDeletes
		case "sd":
			subDeletes, err := parseChunkRange(bits[1])
			if err != nil {
				return fmt.Errorf("Error parsing delete sub chunks range: %s", err)
			}
			ss.Lists[currentListName].DeleteChunks[CHUNK_TYPE_SUB] = subDeletes
		}
	}
	// add the final list
	ss.Lists[currentListName].DataRedirects = currentList
	ss.Lists[currentListName].DeleteChunks = currentDeletes
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("Unable to parse list response: %s", err)
	}
	return nil
}

func getHash(input string) (hash LookupHash) {
	hasher := sha256.New()
	hasher.Write([]byte(input))
	return LookupHash(hasher.Sum(nil))
}

func insertionSortHashLength(a []LookupHash) {
	for i := 1; i < len(a); i++ {
		value := a[i]
		j := i - 1
		for j >= 0 && len(a[j]) < len(value) {
			a[j+1] = a[j]
			j = j - 1
		}
		a[j+1] = value
	}
}

// Check to see if a URL is marked as unsafe by Google.
// Returns what list the URL is on, or an empty string if the URL is unlisted.
// Note that this query may perform a blocking HTTP request; if speed is important
// it may be preferable to use MightBeListed which will return quickly.  If showing
// a warning to the user however, this call must be used.
func (ss *SafeBrowsing) IsListed(url string) (list string, err error) {
	list, _, err = ss.queryUrl(url, true)
	return list, err
}

// Check to see if a URL is likely marked as unsafe by Google.
// Returns what list the URL may be listed on, or an empty string if the URL is not listed.
// Note that this query does not perform a "request for full hashes" and MUST NOT be
// used to show a warning to the user.
func (ss *SafeBrowsing) MightBeListed(url string) (list string, fullHashMatch bool, err error) {
	return ss.queryUrl(url, false)
}

// Checks to ensure we have had a successful update in the last 45 mins
func (ss *SafeBrowsing) IsUpToDate() bool {
	return !OfflineMode && time.Since(ss.LastUpdated) < (time.Duration(45)*time.Minute)
}

// Here is where we actually look up the hashes against our map.
func (ss *SafeBrowsing) queryUrl(url string, matchFullHash bool) (list string, fullHashMatch bool, err error) {

	if matchFullHash && !ss.IsUpToDate() {
		// we haven't had a sucessful update in the last 45 mins!  abort!
		return "", false, fmt.Errorf(
			"Unable to check listing, list hasn't been updated for 45 mins")
	}

	// first Canonicalize
	url, err = Canonicalize(url)
	if err != nil {
		return "", false, nil
	}

	// now see if there is a host hit
	hostKey := ExtractHostKey(url)
	hostKeyHash := HostHash(getHash(hostKey)[:4])
	ss.Logger.Debug("Host hash: %s", hex.EncodeToString([]byte(hostKeyHash)))
	for list, ssl := range ss.Lists {
		hashes, exists := ssl.LookupMap[hostKeyHash]
		if !exists {
			ss.Logger.Debug("Host hash not found: %s", hex.EncodeToString([]byte(hostKeyHash)))
			return "", false, nil
		}
		ss.Logger.Debug("Host hash found: " + hex.EncodeToString([]byte(hostKeyHash)))

		urls, err := GenerateTestCandidates(url)
		if err != nil {
			return "", false, nil
		}
		ss.Logger.Debug("Checking %d iterations of url", len(urls))
		for _, url := range urls {
			// hash it up
			ss.Logger.Debug("Hashing %s", url)
			urlHash := getHash(url)
			// build a list of hashes from long to short
			prefixes := make([]LookupHash, 0, len(ssl.HashSizesBytes))
			prefixes = append(prefixes, urlHash)
			for size, _ := range ssl.HashSizesBytes {
				prefix := urlHash[0:size]
				ss.Logger.Debug("Generated Hash %s", hex.EncodeToString([]byte(prefix)))
				prefixes = append(prefixes, prefix)
			}
			insertionSortHashLength(prefixes)
			fullHashRequestList := make([]LookupHash, 0)
			// now query them!
			for _, hash := range prefixes {
				//log.Debug("testing hash: %s", hex.EncodeToString([]byte(hash)))
				if _, exists := hashes[hash]; exists {
					// we got a hit! if it's already a full hash there's our answer
					if len(hash) == 32 {
						ss.Logger.Debug("Full length hash hit")
						return list, true, nil
					}
					if !matchFullHash {
						ss.Logger.Debug("Partial hash hit")
						return list, false, nil
					}
					// have we have already asked for full hashes for this prefix?
					if _, exists := ssl.FullHashRequested[hostKeyHash][hash]; exists {
						ss.Logger.Debug("Full length hash miss")
						return "", false, nil
					}
					// we matched a prefix and need to request a full hash
					fullHashRequestList = append(fullHashRequestList, hash)
				}
			}
			if len(fullHashRequestList) > 0 && !OfflineMode {
				// request any required full hashes
				err := ss.requestFullHashes(list, hostKeyHash, fullHashRequestList)
				if err != nil {
					return "", false, nil
				}
				// re-check for full hash hits.
				for _, hash := range prefixes {
					ss.Logger.Debug("Need to request full length hashes for %s",
						hex.EncodeToString([]byte(hash)))
					if len(hash) == 32 {
						if _, exists := ssl.LookupMap[hostKeyHash][hash]; exists {
							return list, true, nil
						}
					}
				}
			}
		}
	}

	return "", false, nil
}

func (ss *SafeBrowsing) requestFullHashes(list string, host HostHash, prefixes []LookupHash) error {
	if len(prefixes) == 0 {
		return nil
	}
	query := "%d:%d\n%s"
	buf := bytes.Buffer{}
	firstPrefixLen := len(prefixes[0])
	for _, prefix := range prefixes {
		_, err := buf.Write([]byte(prefix))
		if err != nil {
			return err
		}
		if firstPrefixLen != len(prefixes[0]) {
			return fmt.Errorf("Attempted to used variable length hashes in lookup!")
		}
	}
	body := fmt.Sprintf(query,
		firstPrefixLen,
		len(buf.String()),
		buf.String())
	url := fmt.Sprintf(
		"http://safebrowsing.clients.google.com/safebrowsing/gethash?"+
			"client=%s&apikey=%s&appver=%s&pver=2.2",
		ss.Client, ss.Key, ss.AppVersion)
	response, err := ss.request(url, body, true)
	if err != nil {
		return err
	}
	if response.StatusCode >= 400 {
		return fmt.Errorf("Unable to lookup hash, server returned %d",
			response.StatusCode)
	}
	// mark these prefxes as having been requested
	for _, prefix := range prefixes {
		if _, exists := ss.Lists[list].FullHashRequested[host]; !exists {
			ss.Lists[list].FullHashRequested[host] = make(map[LookupHash]bool)
		}
		ss.Lists[list].FullHashRequested[host][prefix] = true
	}
	return ss.processFullHashes(list, response.Body, host)
}

func (ss *SafeBrowsing) processFullHashes(list string, f io.Reader, host HostHash) error {
	responseBuf := bufio.NewReader(f)
	chunks := make([]*Chunk, 0)
	var err error = nil
	var chunk *Chunk = nil
	for err == nil {
		chunk, err = ReadFullHashChunk(responseBuf, host)
		if err == nil {
			chunks = append(chunks, chunk)
		}
	}
	if err != io.EOF {
		return err
	}
	err = ss.Lists[list].load(chunks)
	if err != nil {
		return err
	}
	debug.FreeOSMemory()
	return nil
}
