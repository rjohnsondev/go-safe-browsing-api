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
	"flag"
	"fmt"
	toml "github.com/BurntSushi/toml"
	safebrowsing "github.com/rjohnsondev/go-safe-browsing-api"
	"net/http"
	"os"
	"encoding/json"
)

type Config struct {
	Address      string
	GoogleApiKey string
	DataDir      string
}

var ss *safebrowsing.SafeBrowsing

func main() {

	flag.Parse()
	if len(flag.Args()) < 1 {
		fmt.Printf("Usage: webserver config-file.toml")
		os.Exit(1)
	}

	var conf Config
	if _, err := toml.DecodeFile(flag.Arg(0), &conf); err != nil {
		fmt.Printf(
			"Error reading config file %s: %s",
			flag.Arg(0),
			err,
		)
		os.Exit(1)
	}

	var err error
	ss, err = safebrowsing.NewSafeBrowsing(
		conf.GoogleApiKey,
		conf.DataDir,
	)
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/form", handleHtml)
	http.HandleFunc("/", handler)
	http.ListenAndServe(conf.Address, nil)
}

type UrlResponse struct {
	IsListed bool `json:"isListed"`
	List string `json:"list,omitempty"`
	Error string `json:"error,omitempty"`
	WarningTitle string `json:"warningTitle,omitempty"`
	WarningText string `json:"warningText,omitempty"`
	FullHashesRequested bool `json:"fullHashesRequested,omitempty"`
}

var warnings map[string]map[string]string = map[string]map[string]string{
	"goog-malware-shavar": map[string]string{
		"title": "Warning - Visiting this web site may harm your computer.",
		"text": "This page may be a forgery or imitation of another website, " +
				"designed to trick users into sharing personal or financial " +
				"information. Entering any personal information on this page " +
				"may result in identity theft or other abuse. You can find " +
				"out more about phishing from http://www.antiphishing.org/",
	},
	"googpub-phish-shavar": map[string]string{
		"title": "Warning - Suspected phishing page.",
		"text": "This page appears to contain malicious code that could be " +
				"downloaded to your computer without your consent. You can " +
				"learn more about harmful web content including viruses and " +
				"other malicious code and how to protect your computer at " +
				"http://StopBadware.org/",
	},
}

func handleHtml(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
	<html>
	<body>
	<textarea id="txtJson" cols="60" rows="10">[
	"http://www.google.com/",
	"http://www.ianfette.org/",
	"http://www.evil.com/"
]
	</textarea><br />
	<pre id="output"></pre><br/>
	<input type="button" value="Submit" onclick="fireRequest();" />
	<script>
		fireRequest = function() {
			$.post("/", {"urls": $("#txtJson").text()}, function(data, textStatus, jqXHR) {
				console.log(data);
				$("#output").text(data);
			});
		}
	</script>
	<script src="//ajax.googleapis.com/ajax/libs/jquery/1.11.1/jquery.min.js"></script>
	</body>
	</html>
	`
	fmt.Fprintf(w, html)
}


func queryUrl(url string) (response *UrlResponse) {
	response = new(UrlResponse)
	list, err := ss.IsListed(url)
	if err != nil {
		fmt.Sprintf(response.Error, "Error looking up url: %s", err.Error())
	}
	println(list)
	if list != "" {
		response.IsListed = true
		response.List = list
		response.WarningTitle = warnings[list]["title"]
		response.WarningText = warnings[list]["text"]
	}
	return response
}

func handler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		fmt.Fprintf(w, "Error loading form: %s", err.Error())
		return
	}

	println(r.FormValue("urls"))
	urls := make([]string, 0)
	err = json.Unmarshal([]byte(r.FormValue("urls")), &urls)
	if err != nil {
		fmt.Fprintf(w, "Error loading form: %s", err.Error())
		return
	}

	output := make(map[string]*UrlResponse, 0)
	for _, url := range urls {
		output[url] = queryUrl(url)
	}
	txtOutput, err := json.Marshal(output)
	if err != nil {
		fmt.Fprintf(w, "Error marshalling response: %s", err.Error())
		return
	}
	fmt.Fprint(w, string(txtOutput))
}

