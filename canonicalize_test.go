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
	"testing"
)

func TestCandidates(t *testing.T) {
	url := "http://a.b.c/1/2.html?param=1"
	values := GenerateTestCandidates(url)
	lookup := make(map[string]bool)
	for _, val := range values {
		lookup[val] = true
	}
	comp := []string{
		"a.b.c/1/2.html?param=1",
		"a.b.c/1/2.html",
		"a.b.c/",
		"a.b.c/1/",
		"b.c/1/2.html?param=1",
		"b.c/1/2.html",
		"b.c/",
		"b.c/1/",
	}
	for _, val := range comp {
		if _, exists := lookup[val]; !exists {
			t.Error("Didn't create required hostname: " + val)
			return
		}
	}

	url = "http://a.b.c.d.e.f.g/1.html"
	values = GenerateTestCandidates(url)
	lookup = make(map[string]bool)
	for _, val := range values {
		lookup[val] = true
	}
	comp = []string{
		"a.b.c.d.e.f.g/1.html",
		"a.b.c.d.e.f.g/",
		"c.d.e.f.g/1.html",
		"c.d.e.f.g/",
		"d.e.f.g/1.html",
		"d.e.f.g/",
		"e.f.g/1.html",
		"e.f.g/",
		"f.g/1.html",
		"f.g/",
	}
	for _, val := range comp {
		if _, exists := lookup[val]; !exists {
			t.Error("Didn't create required hostname: " + val)
			return
		}
	}

	url = "http://1.2.3.4/1/"
	values = GenerateTestCandidates(url)
	lookup = make(map[string]bool)
	for _, val := range values {
		lookup[val] = true
	}
	comp = []string{
		"1.2.3.4/1/",
		"1.2.3.4/",
	}
	for _, val := range comp {
		if _, exists := lookup[val]; !exists {
			t.Error("Didn't create required hostname: " + val)
			return
		}
	}

	url = "http://1.2.3.4/"
	values = GenerateTestCandidates(url)
	lookup = make(map[string]bool)
	for _, val := range values {
		lookup[val] = true
	}
	comp = []string{
		"1.2.3.4/",
	}
	for _, val := range comp {
		if _, exists := lookup[val]; !exists {
			t.Error("Didn't create required hostname: " + val)
			return
		}
	}
}

func TestHostname(t *testing.T) {
	url := "http://a.b.c.d.e.f.g/1.html"
	values := iterateHostnames(url)
	lookup := make(map[string]bool)
	for _, val := range values {
		lookup[val] = true
	}
	comp := []string{
		"http://a.b.c.d.e.f.g/1.html",
		"http://f.g/1.html",
		"http://e.f.g/1.html",
		"http://d.e.f.g/1.html",
		"http://c.d.e.f.g/1.html",
	}
	for _, val := range comp {
		if _, exists := lookup[val]; !exists {
			t.Error("Didn't create required hostname: " + val)
			return
		}
	}

	url = "http://a.b.c.d.e.f.g/"
	values = iterateHostnames(url)
	lookup = make(map[string]bool)
	for _, val := range values {
		lookup[val] = true
	}
	comp = []string{
		"http://a.b.c.d.e.f.g/",
		"http://f.g/",
		"http://e.f.g/",
		"http://d.e.f.g/",
		"http://c.d.e.f.g/",
	}
	for _, val := range comp {
		if _, exists := lookup[val]; !exists {
			t.Error("Didn't create required hostname: " + val)
			return
		}
	}
}

func TestCanonicalize(t *testing.T) {

	src := []string{
		"http://host/%25%32%35",
		"http://host/%25%32%35%25%32%35",
		"http://host/%2525252525252525",
		"http://host/asdf%25%32%35asd",
		"http://host/%%%25%32%35asd%%",
		"http://www.google.com/",
		"http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/",
		"http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/",
		"http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%255E00%252611%252A22%252833%252944_55%252B",
		"http://3279880203/blah",
		"http://www.google.com/blah/..",
		"www.google.com/",
		"www.google.com",
		"http://www.evil.com/blah#frag",
		"http://www.GOOgle.com/",
		"http://www.google.com.../",
		"http://www.google.com/foo\tbar\rbaz\n2",
		"http://www.google.com/q?",
		"http://www.google.com/q?r?",
		"http://www.google.com/q?r?s",
		"http://evil.com/foo#bar#baz",
		"http://evil.com/foo;",
		"http://evil.com/foo?bar;",
		"http://\x01\x80.com/",
		"http://notrailingslash.com",
		"http://www.gotaport.com:1234/",
		"  http://www.google.com/  ",
		"http:// leadingspace.com/",
		"http://%20leadingspace.com/",
		"%20leadingspace.com/",
		"https://www.securesite.com/",
		"http://host.com/ab%23cd",
		"http://host.com//twoslashes?more//slashes",
		"http://host.com/another//twoslashes?more//slashes",
	}
	comp := []string{
		"http://host/%25",
		"http://host/%25%25",
		"http://host/%25",
		"http://host/asdf%25asd",
		"http://host/%25%25%25asd%25%25",
		"http://www.google.com/",
		"http://168.188.99.26/.secure/www.ebay.com/",
		"http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/",
		"http://host%23.com/~a!b@c%23d$e%25f^00&11*22(33)44_55+",
		"http://195.127.0.11/blah",
		"http://www.google.com/",
		"http://www.google.com/",
		"http://www.google.com/",
		"http://www.evil.com/blah",
		"http://www.google.com/",
		"http://www.google.com/",
		"http://www.google.com/foobarbaz2",
		"http://www.google.com/q?",
		"http://www.google.com/q?r?",
		"http://www.google.com/q?r?s",
		"http://evil.com/foo",
		"http://evil.com/foo;",
		"http://evil.com/foo?bar;",
		"http://%01%80.com/",
		"http://notrailingslash.com/",
		"http://www.gotaport.com:1234/",
		"http://www.google.com/",
		"http://%20leadingspace.com/",
		"http://%20leadingspace.com/",
		"http://%20leadingspace.com/",
		"https://www.securesite.com/",
		"http://host.com/ab%23cd",
		"http://host.com/twoslashes?more//slashes",
		"http://host.com/another/twoslashes?more//slashes",
	}

	for x := 0; x < len(src); x++ {
		out := Canonicalize(src[x])
		if out != comp[x] {
			t.Errorf("failed %d: src - '%s', comp - '%s', out - '%s'",
				x, src[x], comp[x], out)
		}
	}

}
