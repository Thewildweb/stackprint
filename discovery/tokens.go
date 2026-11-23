// Package discovery mines candidate rule signals from a corpus of scanned
// pages.
//
// Pages are labelled with the technologies the current rules detect
// confidently. Every page is also broken into normalised tokens: path
// stems, file names, class and id names, data-* attribute names, meta and
// header names, cookie names, comment openings, inline global
// assignments, DNS host suffixes. For each label, tokens that occur on
// (almost) only labelled pages and on many of them are candidates for new
// signals; frequent tokens no label explains are leads for technologies the
// rules do not know yet.
//
// The miner only proposes. A candidate becomes a rule after review, with the
// mined statistics recorded as its provenance.
package discovery

import (
	_ "embed"
	"net/url"
	"regexp"
	"strings"

	"github.com/Thewildweb/stackprint/page"
)

// Token types.
const (
	TPath    = "path"    // first-party directory prefix
	TFile    = "file"    // file name (normalised)
	THost    = "host"    // third-party host
	THostDir = "hostdir" // third-party host + first directory
	TClass   = "class"
	TID      = "id"
	TData    = "data"
	TMeta    = "meta"
	THeader  = "header"
	TCookie  = "cookie"
	TComment = "comment"
	TGlobal  = "global"
	TDNS     = "dns"
	TStorage = "storage" // Web Storage key
	TResHdr  = "reshdr"  // sub-resource response header name (or server=value)
)

var (
	digitsRe   = regexp.MustCompile(`[0-9]+`)
	hexRunRe   = regexp.MustCompile(`[0-9a-f]{8,}`)
	globalRe   = regexp.MustCompile(`(?:\bwindow\.|\bvar\s+|\blet\s+|\bconst\s+)([A-Za-z_$][A-Za-z0-9_$]{3,40})\s*=`)
	wordsRe    = regexp.MustCompile(`[a-z][a-z0-9_.-]*`)
	includeRe  = regexp.MustCompile(`include:([a-z0-9._-]+)`)
	verifyRe   = regexp.MustCompile(`^([a-z0-9-]+(?:-verification|-site-verification|-domain-verification)?)=`)
	versionish = regexp.MustCompile(`[/ -]v?[0-9][0-9.]*`)
)

// commonHeader lists generic HTTP headers that identify nothing.
var commonHeader = map[string]bool{}

//go:embed browser_globals.txt
var browserGlobalsTxt string

// browserGlobal holds window properties of the browser itself.
var browserGlobal = map[string]bool{}

func init() {
	for _, l := range strings.Split(browserGlobalsTxt, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			browserGlobal[l] = true
		}
	}
	for _, h := range strings.Fields(`date content-length content-type set-cookie cache-control expires
		last-modified etag connection vary accept-ranges location keep-alive age pragma content-encoding
		transfer-encoding strict-transport-security x-content-type-options x-frame-options x-xss-protection
		referrer-policy content-security-policy permissions-policy access-control-allow-origin
		access-control-allow-methods access-control-allow-headers access-control-expose-headers
		access-control-max-age access-control-allow-credentials timing-allow-origin alt-svc
		cross-origin-resource-policy cross-origin-opener-policy cross-origin-embedder-policy
		content-disposition link nel report-to server-timing x-cache status`) {
		commonHeader[h] = true
	}
}

// norm lowercases, collapses hex runs and digit runs.
func norm(s string) string {
	s = strings.ToLower(s)
	s = hexRunRe.ReplaceAllString(s, "*")
	return digitsRe.ReplaceAllString(s, "#")
}

// Token is one mined observation, "type\x00value".
type Token string

func tok(typ, v string) Token { return Token(typ + "\x00" + v) }

// Split returns the type and value of a token.
func (t Token) Split() (string, string) {
	typ, v, _ := strings.Cut(string(t), "\x00")
	return typ, v
}

// PageTokens returns the distinct normalised tokens of one page.
func PageTokens(doc *page.Document, toks *page.Tokens) []Token {
	set := map[Token]bool{}
	add := func(typ, v string) {
		if len(v) >= 3 && len(v) <= 120 {
			set[tok(typ, v)] = true
		}
	}
	pageHost := hostname(doc.BaseURL())

	for _, it := range toks.Items[page.SigResourceURL] {
		urlTokens(it.Value, pageHost, toks.Site, add)
	}
	for _, it := range toks.Items[page.SigClass] {
		add(TClass, norm(it.Value))
	}
	for _, it := range toks.Items[page.SigID] {
		add(TID, norm(it.Value))
	}
	for _, it := range toks.Items[page.SigDataAttr] {
		add(TData, norm(it.Key))
	}
	for _, it := range toks.Items[page.SigMeta] {
		switch it.Key {
		case "generator", "application-name":
			v := strings.TrimSpace(versionish.ReplaceAllString(strings.ToLower(it.Value), " "))
			add(TMeta, it.Key+"="+norm(firstWords(v, 3)))
		default:
			add(TMeta, norm(it.Key))
		}
	}
	for _, it := range toks.Items[page.SigHeader] {
		switch it.Key {
		case "server", "x-powered-by", "x-generator", "via":
			v := strings.TrimSpace(versionish.ReplaceAllString(strings.ToLower(it.Value), " "))
			add(THeader, it.Key+"="+norm(firstWords(v, 2)))
		default:
			if !commonHeader[it.Key] {
				add(THeader, norm(it.Key))
			}
		}
	}
	for _, it := range toks.Items[page.SigStorage] {
		add(TStorage, norm(it.Key))
	}
	for _, it := range toks.Items[page.SigResourceHeader] {
		switch it.Key {
		case "server", "x-powered-by", "via":
			v := strings.TrimSpace(versionish.ReplaceAllString(strings.ToLower(it.Value), " "))
			add(TResHdr, it.Key+"="+norm(firstWords(v, 2)))
		default:
			if !commonHeader[it.Key] {
				add(TResHdr, norm(it.Key))
			}
		}
	}
	for _, it := range toks.Items[page.SigCookie] {
		add(TCookie, norm(it.Key))
	}
	for _, it := range toks.Items[page.SigComment] {
		commentTokens(it.Value, add)
	}
	for _, it := range toks.Items[page.SigInlineScript] {
		for _, m := range globalRe.FindAllStringSubmatch(it.Value, 50) {
			add(TGlobal, m[1])
		}
	}
	for _, it := range toks.Items[page.SigJSGlobal] {
		if !browserGlobal[it.Key] {
			add(TGlobal, it.Key)
		}
	}
	for _, it := range toks.Items[page.SigDNS] {
		dnsTokens(it.Key, it.Value, false, add)
	}

	out := make([]Token, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	return out
}

// urlTokens adds the tokens of one referenced URL: host and hostdir for a
// third-party host, path prefixes for a first-party one, and the file name.
func urlTokens(raw, pageHost, site string, add func(typ, v string)) {
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	host := strings.ToLower(u.Hostname())
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segs) == 0 || segs[0] == "" {
		return
	}
	file := segs[len(segs)-1]
	dirs := segs[:len(segs)-1]
	if host != "" && host != pageHost && page.RegistrableDomain(host) != site {
		add(THost, host)
		if len(dirs) > 0 {
			add(THostDir, host+"/"+norm(dirs[0])+"/")
		}
	} else {
		p := ""
		for i := 0; i < len(dirs) && i < 4; i++ {
			p += "/" + norm(dirs[i])
			if i >= 1 || len(dirs) == 1 {
				add(TPath, p+"/")
			}
		}
	}
	if strings.Contains(file, ".") {
		add(TFile, norm(file))
	}
}

// commentTokens adds the token of one HTML comment (its first words).
func commentTokens(c string, add func(typ, v string)) {
	if c = strings.ToLower(c); len(c) >= 10 {
		add(TComment, norm(firstWords(c, 5)))
	}
}

// dnsTokens adds the tokens of one DNS record. With singleInclude, an SPF
// record contributes its include only when it has exactly one: evidence names
// the record, not which include matched, so a multi-include record explains
// none of them.
func dnsTokens(key, v string, singleInclude bool, add func(typ, v string)) {
	switch key {
	case "MX":
		if i := strings.LastIndexByte(v, ' '); i >= 0 {
			v = v[i+1:]
		}
		add(TDNS, "mx:"+lastLabels(v, 3))
	case "NS":
		add(TDNS, "ns:"+lastLabels(v, 2))
	case "CNAME":
		add(TDNS, "cname:"+lastLabels(v, 3))
	case "TXT":
		inc := includeRe.FindAllStringSubmatch(v, 10)
		if !singleInclude || len(inc) == 1 {
			for _, m := range inc {
				add(TDNS, "spf-include:"+m[1])
			}
		}
		if m := verifyRe.FindStringSubmatch(v); m != nil && !strings.HasPrefix(v, "v=") {
			add(TDNS, "txt:"+m[1])
		}
	}
}

func firstWords(s string, n int) string {
	w := wordsRe.FindAllString(s, n)
	return strings.Join(w, " ")
}

func hostname(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func lastLabels(h string, n int) string {
	parts := strings.Split(strings.Trim(h, "."), ".")
	if len(parts) <= n {
		return strings.Join(parts, ".")
	}
	return strings.Join(parts[len(parts)-n:], ".")
}

// EvidenceTokens returns the tokens (as PageTokens would produce them) behind
// one piece of detection evidence, so the miner can tell which tokens current
// rules already explain. A URL also explains every token of its host's
// registrable domain on the page (see ExplainedSet).
func EvidenceTokens(pageSite, signal, key, value string) []Token {
	var out []Token
	add := func(typ, v string) { out = append(out, tok(typ, v)) }
	switch signal {
	case "dns":
		dnsTokens(key, value, true, add)
	case "comment":
		commentTokens(value, add)
	case "url", "script_url", "stylesheet_url", "resource_url", "asset_hash":
		if f := strings.Fields(value); len(f) > 0 && !strings.HasPrefix(f[0], "data:") {
			urlTokens(f[0], "", pageSite, func(typ, v string) {
				if typ == TPath || typ == TFile { // hosts: see the registrable-domain pass in ExplainedSet
					add(typ, v)
				}
			})
		}
	case "js_global":
		out = append(out, tok(TGlobal, key))
	case "cookie":
		out = append(out, tok(TCookie, norm(key)))
	case "storage":
		out = append(out, tok(TStorage, norm(key)))
	case "header":
		out = append(out, tok(THeader, norm(key)))
	case "resource_header":
		out = append(out, tok(TResHdr, norm(key)))
	case "data_attr":
		out = append(out, tok(TData, norm(key)))
	case "class":
		out = append(out, tok(TClass, norm(value)))
	case "id":
		out = append(out, tok(TID, norm(value)))
	}
	return out
}

// ExplainedSet builds a page's explained tokens from its detections'
// evidence: tokens named by EvidenceTokens, plus every host/hostdir token on
// a registrable domain that a matched URL belongs to.
func ExplainedSet(pageSite string, pageTokens []Token, evidence [][4]string) Explained {
	exp := Explained{}
	sites := map[string]bool{}
	for _, e := range evidence {
		for _, t := range EvidenceTokens(pageSite, e[0], e[1], e[2]) {
			exp[t] = true
		}
		if strings.Contains(e[2], "://") || strings.HasPrefix(e[2], "//") {
			if h := hostname(strings.Fields(e[2])[0]); h != "" {
				sites[page.RegistrableDomain(h)] = true
			}
		}
		if e[0] == "meta" && e[1] == "generator" {
			for _, t := range pageTokens {
				if typ, _ := t.Split(); typ == TMeta {
					exp[t] = true
				}
			}
		}
	}
	for _, t := range pageTokens {
		typ, v := t.Split()
		if typ != THost && typ != THostDir {
			continue
		}
		host, _, _ := strings.Cut(v, "/")
		if sites[page.RegistrableDomain(host)] {
			exp[t] = true
		}
	}
	return exp
}
