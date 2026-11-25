package page

import (
	"net/url"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"
)

// SignalType names a kind of observation rules can match against.
type SignalType int

// Signal types. Keyed types carry a name (Item.Key) and a value.
const (
	SigURL            SignalType = iota // the page URL
	SigHeader                           // keyed: lowercased header name
	SigCookie                           // keyed: cookie name
	SigMeta                             // keyed: lowercased meta name/property/http-equiv
	SigHTML                             // the raw HTML
	SigScriptURL                        // <script src>, script preloads
	SigStylesheetURL                    // <link rel=stylesheet href>
	SigResourceURL                      // every referenced URL (scripts, styles, links, images, resources, URLs inside inline code)
	SigInlineScript                     // inline <script> bodies
	SigInlineStyle                      // inline <style> bodies
	SigClass                            // class names
	SigID                               // element ids
	SigDataAttr                         // keyed: data-* attribute name
	SigComment                          // HTML comments
	SigJSGlobal                         // keyed: global path
	SigDNS                              // keyed: record type
	SigTLSIssuer                        // certificate issuer
	SigAssetBody                        // body of a fetched JS/CSS asset (asset scans only)
	SigStorage                          // keyed: Web Storage key
	SigResourceHeader                   // keyed: lowercased response header name of a sub-resource
	SigCertHost                         // certificate host name below its registrable domain (Item.Key: the full host)
	NumSignalTypes
)

var signalNames = [NumSignalTypes]string{
	"url", "header", "cookie", "meta", "html", "script_url", "stylesheet_url",
	"resource_url", "inline_script", "inline_style", "class", "id", "data_attr",
	"comment", "js_global", "dns", "tls_issuer", "asset_body", "storage",
	"resource_header", "cert_host",
}

func (t SignalType) String() string {
	if t >= 0 && t < NumSignalTypes {
		return signalNames[t]
	}
	return "unknown"
}

// Keyed reports whether items of this type carry a name in Item.Key.
func (t SignalType) Keyed() bool {
	switch t {
	case SigHeader, SigCookie, SigMeta, SigDataAttr, SigJSGlobal, SigDNS, SigStorage, SigResourceHeader:
		return true
	}
	return false
}

// IsURL reports whether items of this type are URLs.
func (t SignalType) IsURL() bool {
	return t == SigURL || t == SigScriptURL || t == SigStylesheetURL || t == SigResourceURL
}

// ParseSignalType maps a rule-file type name to a SignalType.
func ParseSignalType(s string) (SignalType, bool) {
	for i, n := range signalNames {
		if n == s {
			return SignalType(i), true
		}
	}
	return 0, false
}

// Item is one observed token.
type Item struct {
	Key   string
	Value string
}

// Tokens is a Document broken into per-type token lists. It is built once per
// page (one HTML parse) and read by every rule.
type Tokens struct {
	Items    [NumSignalTypes][]Item
	Observed []string
	// Site is the registrable domain (eTLD+1) of the page URL.
	Site string
}

// Limits keep adversarial pages from blowing up token lists.
const (
	maxClasses      = 5000
	maxIDs          = 2000
	maxDataAttrs    = 2000
	maxComments     = 500
	maxCommentLen   = 1000
	maxDataValueLen = 200
	maxResourceURLs = 3000
	maxInlineRefs   = 1000
	maxResHeaders   = 5000
	maxStorage      = 1000
	maxStorageValue = 200
	maxCertHosts    = 5000
)

// Tokenize parses a Document into Tokens.
func Tokenize(d *Document) *Tokens {
	t := &Tokens{Observed: d.EffectiveObserved()}
	base, _ := url.Parse(d.BaseURL())
	if base != nil {
		t.Site = RegistrableDomain(base.Hostname())
	}

	if u := d.BaseURL(); u != "" {
		t.add(SigURL, "", u)
	}

	for _, h := range d.Headers {
		t.add(SigHeader, strings.ToLower(strings.TrimSpace(h[0])), strings.TrimSpace(h[1]))
	}

	if len(d.Cookies) > 0 {
		for _, c := range d.Cookies {
			t.add(SigCookie, c.Name, c.Value)
		}
	} else {
		for _, h := range d.Headers {
			if !strings.EqualFold(h[0], "set-cookie") {
				continue
			}
			nv, _, _ := strings.Cut(h[1], ";")
			name, value, _ := strings.Cut(nv, "=")
			if name = strings.TrimSpace(name); name != "" {
				t.add(SigCookie, name, strings.TrimSpace(value))
			}
		}
	}

	resources := newURLSet(base, maxResourceURLs)
	resHeaders := map[Item]bool{}
	for _, r := range d.Resources {
		for _, h := range r.Headers {
			it := Item{Key: strings.ToLower(strings.TrimSpace(h[0])), Value: strings.TrimSpace(h[1])}
			if len(it.Value) > maxDataValueLen {
				it.Value = it.Value[:maxDataValueLen]
			}
			if len(resHeaders) < maxResHeaders && !resHeaders[it] {
				resHeaders[it] = true
				t.add(SigResourceHeader, it.Key, it.Value)
			}
		}
		u := resources.add(r.URL)
		if u == "" {
			continue
		}
		switch r.Kind {
		case "script":
			t.add(SigScriptURL, "", u)
		case "stylesheet":
			t.add(SigStylesheetURL, "", u)
		}
	}

	if d.HTML != "" {
		t.add(SigHTML, "", d.HTML)
		t.parseHTML(d.HTML, resources)
	}
	for _, u := range resources.list {
		t.add(SigResourceURL, "", u)
	}

	if len(d.JSGlobals) > 0 {
		keys := make([]string, 0, len(d.JSGlobals))
		for k := range d.JSGlobals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			t.add(SigJSGlobal, k, d.JSGlobals[k])
		}
	}

	if len(d.DNS) > 0 {
		types := make([]string, 0, len(d.DNS))
		for k := range d.DNS {
			types = append(types, k)
		}
		sort.Strings(types)
		for _, typ := range types {
			for _, v := range d.DNS[typ] {
				v = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), ".")
				if v != "" {
					t.add(SigDNS, strings.ToUpper(typ), v)
				}
			}
		}
	}

	seenStorage := map[string]bool{}
	for _, st := range d.Storage {
		if st.Key == "" || seenStorage[st.Key] || len(seenStorage) >= maxStorage {
			continue
		}
		seenStorage[st.Key] = true
		v := st.Value
		if len(v) > maxStorageValue {
			v = v[:maxStorageValue]
		}
		t.add(SigStorage, st.Key, v)
	}

	if d.TLS != nil && d.TLS.Issuer != "" {
		t.add(SigTLSIssuer, "", d.TLS.Issuer)
	}

	// Certificate host names: the value is the part below the registrable
	// domain ("fiori" for fiori.example.nl, "sap.intra" for
	// *.sap.intra.example.com), so rules match labels without the domain
	// itself (shop.fiori.nl has no fiori label). The registrable domain alone
	// says nothing and is skipped.
	seenHost := map[string]bool{}
	for _, h := range d.CertHosts {
		h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
		h = strings.TrimPrefix(h, "*.")
		if h == "" || seenHost[h] || len(seenHost) >= maxCertHosts {
			continue
		}
		seenHost[h] = true
		reg := RegistrableDomain(h)
		if reg == "" || reg == h || !strings.HasSuffix(h, "."+reg) {
			continue
		}
		t.add(SigCertHost, h, strings.TrimSuffix(h, "."+reg))
	}
	return t
}

// TokenizeAsset turns an asset body into Tokens for asset-level rules.
func TokenizeAsset(a *Asset) *Tokens {
	t := &Tokens{Observed: []string{ObservedAssets}}
	if a.URL != "" {
		t.add(SigResourceURL, "", a.URL)
	}
	t.add(SigAssetBody, "", a.Body)
	return t
}

func (t *Tokens) add(typ SignalType, key, value string) {
	t.Items[typ] = append(t.Items[typ], Item{Key: key, Value: value})
}

// Has reports whether a signal group was observed.
func (t *Tokens) Has(group string) bool {
	for _, g := range t.Observed {
		if g == group {
			return true
		}
	}
	return false
}

func (t *Tokens) parseHTML(doc string, resources *urlSet) {
	z := html.NewTokenizer(strings.NewReader(doc))
	classes := map[string]bool{}
	ids := map[string]bool{}
	dataAttrs := map[Item]bool{}
	nComments := 0
	var rawTag string // "script" or "style" while inside one
	inlineRefs := 0

	scanInline := func(body string) {
		if inlineRefs >= maxInlineRefs {
			return
		}
		for _, m := range inlineRefRe.FindAllStringSubmatch(body, maxInlineRefs-inlineRefs) {
			ref := strings.ReplaceAll(m[1], `\/`, "/")
			if !strings.Contains(ref, ".") {
				continue
			}
			if resources.add(ref) != "" {
				inlineRefs++
			}
		}
	}

	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return
		case html.TextToken:
			if rawTag == "" {
				continue
			}
			text := string(z.Text())
			if strings.TrimSpace(text) == "" {
				continue
			}
			if rawTag == "script" {
				t.add(SigInlineScript, "", text)
			} else {
				t.add(SigInlineStyle, "", text)
			}
			scanInline(text)
		case html.EndTagToken:
			rawTag = ""
		case html.CommentToken:
			if nComments >= maxComments {
				continue
			}
			c := strings.TrimSpace(string(z.Text()))
			if c == "" {
				continue
			}
			if len(c) > maxCommentLen {
				c = c[:maxCommentLen]
			}
			t.add(SigComment, "", c)
			nComments++
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			tag := string(name)
			attrs := map[string]string{}
			for hasAttr {
				var k, v []byte
				k, v, hasAttr = z.TagAttr()
				key := string(k)
				val := string(v)
				switch {
				case key == "class":
					for _, c := range strings.Fields(val) {
						if len(classes) < maxClasses && !classes[c] {
							classes[c] = true
							t.add(SigClass, "", c)
						}
					}
				case key == "id":
					if val != "" && len(ids) < maxIDs && !ids[val] {
						ids[val] = true
						t.add(SigID, "", val)
					}
				case strings.HasPrefix(key, "data-"):
					if len(val) > maxDataValueLen {
						val = val[:maxDataValueLen]
					}
					it := Item{Key: key, Value: val}
					if len(dataAttrs) < maxDataAttrs && !dataAttrs[it] {
						dataAttrs[it] = true
						t.add(SigDataAttr, key, val)
					}
				}
				attrs[key] = val
			}
			t.tag(tag, attrs, resources)
			if tt == html.StartTagToken && (tag == "script" || tag == "style") {
				if tag == "script" && attrs["src"] != "" {
					rawTag = "" // external script: its body is not inline code
				} else {
					rawTag = tag
				}
			}
		}
	}
}

func (t *Tokens) tag(tag string, attrs map[string]string, resources *urlSet) {
	switch tag {
	case "script":
		if u := resources.add(attrs["src"]); u != "" {
			t.add(SigScriptURL, "", u)
		}
	case "link":
		u := resources.add(attrs["href"])
		if u == "" {
			return
		}
		rel := strings.ToLower(attrs["rel"])
		as := strings.ToLower(attrs["as"])
		switch {
		case strings.Contains(rel, "stylesheet") || as == "style":
			t.add(SigStylesheetURL, "", u)
		case rel == "modulepreload" || as == "script":
			t.add(SigScriptURL, "", u)
		}
	case "meta":
		key := attrs["name"]
		if key == "" {
			key = attrs["property"]
		}
		if key == "" {
			key = attrs["http-equiv"]
		}
		if key != "" {
			t.add(SigMeta, strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(attrs["content"]))
		}
	case "img", "iframe", "source", "embed", "video", "audio":
		resources.add(attrs["src"])
		if ss := attrs["srcset"]; ss != "" {
			first, _, _ := strings.Cut(strings.TrimSpace(ss), " ")
			resources.add(strings.TrimSuffix(first, ","))
		}
		// Lazy-load libraries park the real URL in a data attribute.
		resources.add(attrs["data-src"])
		resources.add(attrs["data-lazy-src"])
	case "form":
		resources.add(attrs["action"])
	}
}

// RegistrableDomain returns the eTLD+1 of host ("www.example.co.uk" ->
// "example.co.uk"), or the lowercased host when it has none (IPs, localhost).
func RegistrableDomain(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return ""
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

// URLSite returns the registrable domain of a URL, or "".
func URLSite(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return RegistrableDomain(u.Hostname())
}

// inlineRefRe finds quoted or url()-wrapped references inside inline code:
// absolute, protocol-relative or root-relative, with JSON-escaped slashes.
var inlineRefRe = regexp.MustCompile(`["'(]((?:https?:)?(?:\\?/){1,2}[^"'()\s<>\\]*(?:\\/[^"'()\s<>\\]*)*)["')]`)

// urlSet resolves and de-duplicates referenced URLs, keeping first-seen order.
type urlSet struct {
	base *url.URL
	seen map[string]bool
	list []string
	max  int
}

func newURLSet(base *url.URL, max int) *urlSet {
	return &urlSet{base: base, seen: map[string]bool{}, max: max}
}

// add resolves ref and records it, returning the resolved URL ("" when ref
// is empty, not a fetchable URL, or the set is full). A URL already in the
// set is returned again so callers can still classify it.
func (s *urlSet) add(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || len(ref) > 2048 {
		return ""
	}
	low := strings.ToLower(ref)
	for _, p := range []string{"data:", "javascript:", "mailto:", "tel:", "#", "about:", "blob:"} {
		if strings.HasPrefix(low, p) {
			return ""
		}
	}
	resolved := ref
	if s.base != nil {
		if u, err := s.base.Parse(ref); err == nil {
			resolved = u.String()
		}
	}
	if s.seen[resolved] {
		return resolved
	}
	if len(s.list) >= s.max {
		return ""
	}
	s.seen[resolved] = true
	s.list = append(s.list, resolved)
	return resolved
}
