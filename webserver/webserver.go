/*
Copyright (c) 2014, Richard Johnson
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

package main

import (
	safebrowsing "github.com/rjohnsondev/go-safe-browsing-api"
	"net/http"
	"fmt"
)

var ss *safebrowsing.SafeBrowsing

func main() {

	key := ""
	dataDir := "./data"
	var err error
	ss, err = safebrowsing.NewSafeBrowsing(key, dataDir)
	if err != nil {
		panic(err)
	}

    http.HandleFunc("/", handler)
    http.ListenAndServe(":8080", nil)
}


func handler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		fmt.Fprintf(w, "Error parsing form: %s", err.Error())
		return
	}
	if urls, exists := r.Form["url"]; exists && len(urls) > 0 {
		list, err := ss.IsListed(urls[0])
		if err != nil {
			fmt.Fprintf(w, "Error looking up url: %s", err.Error())
			return
		}
		if list != "" {
			fmt.Fprintf(w, "URL is listed in: %s", list)
			return
		}
		fmt.Fprintf(w, "URL is not listed.")
		return
	}
    fmt.Fprintf(w, "Missing url to query")
}

