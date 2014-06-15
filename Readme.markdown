Google Safe Browsing API
========================

[![Build Status](https://travis-ci.org/rjohnsondev/go-safe-browsing-api.png?branch=master)](https://travis-ci.org/rjohnsondev/go-safe-browsing-api)
[![Coverage Status](https://coveralls.io/repos/rjohnsondev/go-safe-browsing-api/badge.png?branch=HEAD)](https://coveralls.io/r/rjohnsondev/go-safe-browsing-api?branch=HEAD)

This library provides client functionality for version 2 of the Google safe
browsing API as per:
https://developers.google.com/safe-browsing/developers_guide_v2

Installation
------------

This should do the trick:

    go get github.com/rjohnsondev/go-safe-browsing-api

Usage
-----

The library requires at least your Safe Browsing API key and a writable
directory to store the list data.

It it recommended you also set the <code>Client</code> and
<code>AppVersion</code> globals to something appropriate:

```go
safebrowsing.Client := "api"
safebrowsing.AppVersion := "1.0"
```

Calling <code>NewSafeBrowsing</code> immediately attempts to contact the google
servers and perform an update/inital download.  If this succeeds, it returns a
SafeBrowsing instance after spawning a new goroutine which will update itself
at the interval requested by google.

```go
package main

import (
	safebrowsing "github.com/rjohnsondev/go-safe-browsing-api"
    log          "github.com/rjohnsondev/log4go-raven"
    "os"
)

func main() {
    key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA_BBBBBBBBB"
    dataDir := "/var/lib/safebrowsing/"
	sb, err = safebrowsing.NewSafeBrowsing(key, dataDir)
	if err != nil {
		log.Error(err)
        os.Exit(1)
	}
}
```

### Looking up a URL

There are two methods for looking up URLs, <code>IsListed</code> and
<code>MightBeListed</code>.  Both of these return either an empty string in the
case of an unlisted URL, or the name of the list on which the URL is listed.
If there was an error requesting confirmation from Google for a listed URL, or
if the last update request was over 45 mins ago, it will be returned along with
an empty string.

<code>IsListed(string)</code> is the recommended method to use if displaying a
message to a user.  It may however make a blocking request to Google's servers
for pages that have partial hash matches to perform a full hash match (if it
has not already done so for that URL) which can be slow.

```go
response, err := sb.IsListed(url)
if err != nil {
    fmt.Printf("Error quering URL: %s", err)
}
if response == "" {
    fmt.Printf("not listed")
} else {
    fmt.Printf("URL listed on: %s", response)
}
```

If a quick return time is required, it may be worth using the
MightBeListed(string) method.  This will not contact Google for confirmation,
so it can only be used to display a message to the user if the fullHashMatch
return value is True AND the last successful update from Google was in the last
45 mins:

```go
response, fullHashMatch, err := sb.MightBeListed(url)
if err != nil {
    fmt.Printf("Error quering URL: %s", err)
}
if response == "" {
    fmt.Printf("not listed")
} else {
    if fullHashMatch && sb.IsUpToDate() {
        fmt.Printf("URL listed on: %s", response)
    } else {
        fmt.Printf("URL may be listed on: %s", response)
    }
}
```

It is recommended you combine the two calls when a non-blocking response is
required, so a full hash can be requested and used for future queries about the
same url:

```go
response, fullHashMatch, err := sb.MightBeListed(url)
if err != nil {
    fmt.Printf("Error quering URL: %s", err)
}
if response != "" {
    if fullHashMatch && sb.IsUpToDate() {
        fmt.Printf("URL listed on: %s", response)
    } else {
        fmt.Printf("URL may be listed on: %s", response)
        // Requesting full hash in background...
        go sb.IsListed(url)
    }
}
```

### Logging Injection

The library includes a safebrowsing.logger interface which can be used to
attach logging facilities to the library.  The interface matches the log4go
Logger, so you can drop that in pretty easily:

```go
package main

import (
	safebrowsing "github.com/rjohnsondev/go-safe-browsing-api"
    log          "github.com/rjohnsondev/log4go-raven"
)

func main() {
    safebrowsing.Logger = log.NewDefaultLogger(log.DEBUG)
}
```

### Offline Mode

The library can work in "offline" mode, where it will not attempt to contact
Google's servers and work purely from local files.  This can be activated by
setting the <code>OfflineMode</code> global variable:

```go
package main

import (
	safebrowsing "github.com/rjohnsondev/go-safe-browsing-api"
)

func main() {
    key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA_BBBBBBBBB"
    dataDir := "/var/lib/safebrowsing/"

    // only work from local files.
	safebrowsing.OfflineMode = true

	sb, err = safebrowsing.NewSafeBrowsing(key, dataDir)
	...
}
```

In this mode <code>IsListed</code> will always return an error complaining that
the list has not been updated within the last 45 mins and no warnings may be
shown to users.


Example Webserver
-----------------

The package also includes a small JSON endpoint for the bulk querying of URLs.
It has an additional config dependency, so it can be installed with something
like:

    go get github.com/rjohnsondev/go-safe-browsing-api
    go get github.com/BurntSushi/toml
	go install github.com/rjohnsondev/go-safe-browsing-api/webserver

The server takes a config file as a parameter, an example one is provided with
the source, but here's the contents for convenience:

	# example config file for safe browsing server
	address = "0.0.0.0:8080"
	googleApiKey = ""
	dataDir = "/tmp/safe-browsing-data"
	# enable example usage page at /form
	enableFormPage = true

The config requires at a minimum your Google API key to be added (otherwise
you'll get a nice non-friendly go panic).  Once up and running it provides a
helpful example page at http://localhost:8080/form


Other Notes
-----------

### Memory Usage

The current implementation stores hashes in a reasonably effecient hat-trie
data structure (bundled from https://github.com/dcjones/hat-trie).  This
results in a memory footprint of approximately 35MB.

### File Format

The files stored by the library are gob streams of Chunks.  They should be
portable between identical versions of the library.
