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
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	//	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

//import "encoding/hex"

type FullHashCache struct {
	CreationDate  time.Time
	CacheLifeTime int
}

func newFullHashCache(creationDate time.Time, cacheLifeTime int) (fch *FullHashCache) {
	fch = &FullHashCache{
		CreationDate:  creationDate,
		CacheLifeTime: cacheLifeTime,
	}
	return fch

}

// Check to see if a URL is marked as unsafe by Google.
// Returns what list the URL is on, or an empty string if the URL is unlisted.
// Note that this query may perform a blocking HTTP request; if speed is important
// it may be preferable to use MightBeListed which will return quickly.  If showing
// a warning to the user however, this call must be used.
func (sb *SafeBrowsing) IsListed(url string) (list string, err error) {
	list, _, err = sb.queryUrl(url, true)
	return list, err
}

// Check to see if a URL is likely marked as unsafe by Google.
// Returns what list the URL may be listed on, or an empty string if the URL is not listed.
// Note that this query does not perform a "request for full hashes" and MUST NOT be
// used to show a warning to the user.
func (sb *SafeBrowsing) MightBeListed(url string) (list string, fullHashMatch bool, err error) {
	return sb.queryUrl(url, false)
}

var ErrOutOfDateHashes = errors.New("Unable to check listing, list hasn't been updated for 45 mins")

// Here is where we actually look up the hashes against our map.
func (sb *SafeBrowsing) queryUrl(url string, matchFullHash bool) (list string, fullHashMatch bool, err error) {
	//	defer debug.FreeOSMemory()

	if matchFullHash && !sb.IsUpToDate() {
		// we haven't had a sucessful update in the last 45 mins!  abort!
		return "", false, ErrOutOfDateHashes
	}

	// first Canonicalize
	url = Canonicalize(url)

	urls := GenerateTestCandidates(url)
	//      sb.Logger.Debug("Checking %d iterations of url", len(urls))
	for list, sbl := range sb.Lists {

		// create the map for all prefixes we need to do the full hash lookup
		keysToLookupMap := make(map[LookupHash]bool)

		for _, url := range urls {

			urlHash := getHash(url)

			prefix := urlHash[:PREFIX_4B_SZ]
			lookupHash := string(prefix)
			fullLookupHash := string(urlHash)

			fhc, ok := sbl.Cache[FullHash(fullLookupHash)]
			if ok && !fhc.checkValidity() {
				delete(sbl.Cache, FullHash(fullLookupHash))
				//sbl.Logger.Debug("Delete full length hash: %s",fullLookupHash)
				sbl.FullHashRequested.Delete(lookupHash)
				sbl.FullHashes.Delete(fullLookupHash)
			}

			// look up full hash matches
			if sbl.FullHashes.Get(fullLookupHash) {
				return list, true, nil
			}

			// now see if there is a match in our prefix trie
			if sbl.Lookup.Get(lookupHash) {
				if !matchFullHash || OfflineMode {
					//					sb.Logger.Debug("Partial hash hit")
					return list, false, nil
				}
				// have we have already asked for full hashes for this prefix?
				if sbl.FullHashRequested.Get(string(lookupHash)) {
					//                                        sb.Logger.Debug("Full length hash miss")
					continue
				}

				// we matched a prefix and need to request a full hash
				keysToLookupMap[prefix] = true
			}
		}

		// Check if we need to do a fullHashLookup
		if len(keysToLookupMap) > 0 {
			err := sb.requestFullHashes(list, keysToLookupMap)
			if err != nil {
				return "", false, err
			}

			// re-check for full hash hit.
			for _, url := range urls {
				urlHash := getHash(url)
				fullLookupHash := string(urlHash)

				if sbl.FullHashes.Get(string(fullLookupHash)) {
					return list, true, nil
				}
			}
		}
		//			debug.FreeOSMemory()
	}
	return "", false, nil
}

// Checks to ensure we have had a successful update in the last 45 mins
func (sb *SafeBrowsing) IsUpToDate() bool {
	return !OfflineMode && time.Since(sb.LastUpdated) < (time.Duration(45)*time.Minute)
}

func getHash(input string) (hash LookupHash) {
	hasher := sha256.New()
	hasher.Write([]byte(input))
	return LookupHash(hasher.Sum(nil))
}

// Full hashes request have a temporary response validity
func (fhc *FullHashCache) checkValidity() bool {
	return (time.Since(fhc.CreationDate) < (time.Duration(fhc.CacheLifeTime) * time.Second))
}

// request full hases for a set of lookup prefixes.
func (sb *SafeBrowsing) requestFullHashes(list string, prefixes map[LookupHash]bool) error {

	if len(prefixes) == 0 {
		return nil
	}
	query := "%d:%d\n%s"
	buf := bytes.Buffer{}
	firstPrefixLen := 0
	for prefix, _ := range prefixes {
		_, err := buf.Write([]byte(prefix))
		if err != nil {
			return err
		}
		if firstPrefixLen == 0 {
			firstPrefixLen = len(prefix)
		}
		if firstPrefixLen != len(prefix) {
			return fmt.Errorf("Attempted to used variable length hashes in lookup!")
		}
	}
	body := fmt.Sprintf(query,
		firstPrefixLen,
		len(buf.String()),
		buf.String())
	url := fmt.Sprintf(
		"https://safebrowsing.google.com/safebrowsing/gethash?"+
			"client=%s&key=%s&appver=%s&pver=%s",
		sb.Client, sb.Key, sb.AppVersion, sb.ProtocolVersion)
	response, err := sb.request(url, body, true)
	if err != nil {
		return err // non-server error with HTTP
	}
	defer response.Body.Close()

	// mark these prefxes as having been requested
	for prefix, _ := range prefixes {
		sb.Lists[list].FullHashRequested.Set(string(prefix))
	}

	if response.StatusCode != 200 {
		if response.StatusCode == 503 {
			// Retry in background with a new thread
			go sb.doFullHashBackOffRequest(url, body)
			return fmt.Errorf("Service temporarily Unavailable")
		}
		return fmt.Errorf("Unable to lookup full hash, server returned %d",
			response.StatusCode)
	}
	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}
	return sb.processFullHashes(string(data))
}

// Process the retrieved full hashes, saving them to disk
func (sb *SafeBrowsing) processFullHashes(data string) error {
	//	defer debug.FreeOSMemory()

	pos := strings.IndexByte(data, '\n')
	if -1 == pos {
		return nil
	}
	cacheLifeTime, err := strconv.Atoi(data[0:pos])
	if err != nil {
		return err
	}
	data = data[pos+1:]

	for pos, rec_len := 0, 0; pos < len(data); pos += rec_len {
		nl_pos := strings.IndexByte(data[pos:], '\n')
		if -1 == nl_pos {
			return fmt.Errorf("Malformated response: unable to find end of header")
		}
		header := data[pos : pos+nl_pos]
		// Increment by the header+newline
		rec_len = pos + nl_pos + 1

		headerArray := strings.Split(header, ":")
		headerRecCount := len(headerArray)
		if 3 != headerRecCount && 4 != headerRecCount {
			return fmt.Errorf("Malformated response: %s", header)
		}
		// How many 32 byte hashes do we have
		num_resp, err := strconv.Atoi(headerArray[2])
		if err != nil {
			return err
		} else if 0 >= num_resp {
			return fmt.Errorf("Malformated response: %s", header)
		} else if (pos + (num_resp * 32)) > len(data) {
			return fmt.Errorf("Malformated response: %s", header)
		}

		hashes := data[nl_pos+1 : nl_pos+1+(num_resp*32)]
		// Increment by the number of 32 byte hashes
		rec_len = rec_len + num_resp*32

		if 4 == headerRecCount {
			// We have metadata, check for a valid marker
			if "m" != headerArray[3] {
				return fmt.Errorf("Malformated response: %s", header)
			}
			for resp := 0; resp < num_resp; resp++ {
				nl_pos = strings.IndexByte(data[pos+rec_len:], '\n')
				if -1 == nl_pos {
					return fmt.Errorf("Malformated response: unable to parse metadata length")
				}
				// How many bytes is the metadata record
				len_meta, err := strconv.Atoi(data[pos+rec_len : pos+rec_len+nl_pos])
				if err != nil {
					return err
				} else if pos+rec_len+nl_pos+len_meta > len(data) {
					return fmt.Errorf("Malformated response: %s", header)
				}
				// Increment by the length field and the meta data
				rec_len += nl_pos + 1 + len_meta
			}
		}
		err = sb.readFullHashChunk(hashes, headerArray[0], cacheLifeTime)
	}
	return err
}

func (sb *SafeBrowsing) readFullHashChunk(hashes string, list string, cacheLifeTime int) (err error) {
	if hashes == "" || list == "" {
		return fmt.Errorf("Imcomplete data to readFullHashChunck()")
	}

	hashlen := 32
	hasheslen := len(hashes)
	for i := 0; (i + hashlen) <= hasheslen; i += hashlen {
		hash := hashes[i:(i + hashlen)]
		//sb.Lists[list].Logger.Debug("Adding full length hash: %s",
		//hex.EncodeToString([]byte(hash)))
		if sb.Lists == nil {
			return fmt.Errorf("Google safe browsing lists have not been initialized")
		} else if sb.Lists[list] == nil {
			return fmt.Errorf("Google safe browsing list (%s) have not been initialized", list)
		}
		sb.Lists[list].FullHashes.Set(hash)
		sb.Lists[list].Cache[FullHash(hash)] = newFullHashCache(time.Now(), cacheLifeTime)
	}
	return nil
}

// Continue the attempt to request for full hashes in the background, observing the required backoff behaviour.
func (sb *SafeBrowsing) doFullHashBackOffRequest(url string, body string) {

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomFloat := r.Float64()
	var response *http.Response
	response.StatusCode = 503
	var err error

	for x := 0; response.StatusCode == 503; x++ {
		// first we wait 1 min, than some time between 30-60 mins
		// doubling until we stop at 480 mins or succeed
		mins := (30 * (randomFloat + 1) * float64(x)) + 1
		if mins > 480 {
			sb.Logger.Warn(
				"Back-off for full hash %s exceeded 8 hours, it ain't going to happen, giving up: %s",
				body,
				response,
			)
			return
		}
		sb.Logger.Warn(
			"Update failed, in full hash back-off mode (waiting %d mins)",
			mins,
		)
		time.Sleep(time.Duration(mins) * time.Minute)
		response, err = sb.request(url, body, true)
		if err != nil {
			sb.Logger.Error(
				"Unable to request full hashes from response in back-off mode: %s",
				err,
			)
			continue
		}
	}
	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		sb.Logger.Error(
			"Unable to request full hashes from response in back-off mode: %s",
			err,
		)
	}
	err = sb.processFullHashes(string(data))
	if err != nil {
		sb.Logger.Error(
			"Unable process full hashes from response in back-off mode: %s; trying again.",
			err,
		)
		sb.doFullHashBackOffRequest(url, body)
	}
}
