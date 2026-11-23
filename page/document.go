// Package page defines stackprint's input contract and turns a document into
// the token sets the engine matches against.
//
// A Document describes one fetched page, independent of who fetched it: a
// plain HTTP client, a headless browser or a crawl archive (WARC) reader. A
// fetcher fills in what it observed and lists those signal groups in Observed,
// so that "absent" can be told apart from "observed, and there was none".
package page

import (
	"strings"
	"time"
)

// SchemaVersion is the Document schema version this package reads and writes.
const SchemaVersion = 1

// Signal groups a fetcher can declare in Document.Observed.
const (
	ObservedHeaders   = "headers"
	ObservedCookies   = "cookies"
	ObservedHTML      = "html"
	ObservedResources = "resources"
	ObservedJSGlobals = "js_globals"
	ObservedDNS       = "dns"
	ObservedTLS       = "tls"
	ObservedAssets    = "assets"
	ObservedStorage   = "storage"
)

// Document is one fetched page.
type Document struct {
	SchemaVersion int `json:"schema_version,omitempty" yaml:"schema_version,omitempty"`

	// Site is the registrable domain the page belongs to as the fetcher
	// knows it (the crawl unit). Optional; copied into results.
	Site string `json:"site,omitempty" yaml:"site,omitempty"`

	// URL is the requested URL; FinalURL the URL after redirects. Relative
	// references in the HTML are resolved against FinalURL (or URL).
	URL      string `json:"url" yaml:"url"`
	FinalURL string `json:"final_url,omitempty" yaml:"final_url,omitempty"`

	// FetchedAt is when the page was fetched. It is used to rule out
	// releases published after the fetch (old crawl archives).
	FetchedAt *time.Time `json:"fetched_at,omitempty" yaml:"fetched_at,omitempty"`

	Fetcher Fetcher `json:"fetcher,omitempty" yaml:"fetcher,omitempty"`
	Status  int     `json:"status,omitempty" yaml:"status,omitempty"`

	// Headers are the response headers of the final hop, in order, as
	// [name, value] pairs. Repeated headers (Set-Cookie) appear repeatedly.
	Headers [][2]string `json:"headers,omitempty" yaml:"headers,omitempty"`

	// Cookies set by the page. When empty, cookies are derived from
	// Set-Cookie headers.
	Cookies []Cookie `json:"cookies,omitempty" yaml:"cookies,omitempty"`

	HTML          string `json:"html,omitempty" yaml:"html,omitempty"`
	HTMLTruncated bool   `json:"html_truncated,omitempty" yaml:"html_truncated,omitempty"`

	// Resources are requests made while loading the page (browser fetchers)
	// or known otherwise. Script and stylesheet references in the HTML are
	// extracted by the tokeniser and need not be repeated here.
	Resources []Resource `json:"resources,omitempty" yaml:"resources,omitempty"`

	// JSGlobals maps a dotted global path (e.g. "jQuery.fn.jquery") to its
	// string value, as evaluated by a browser. A fetcher that only lists
	// window property names sets the values to "" (presence rules still
	// match; version rules need values).
	JSGlobals map[string]string `json:"js_globals,omitempty" yaml:"js_globals,omitempty"`

	// DNS maps a record type (MX, NS, TXT, CNAME, A, AAAA, SOA) to its values
	// for the page's host or registrable domain.
	DNS map[string][]string `json:"dns,omitempty" yaml:"dns,omitempty"`

	TLS *TLS `json:"tls,omitempty" yaml:"tls,omitempty"`

	// Storage lists Web Storage entries the page set (browser fetchers).
	Storage []StorageItem `json:"storage,omitempty" yaml:"storage,omitempty"`

	// Observed lists the signal groups the fetcher collected. When empty it
	// is inferred from which fields are set (see EffectiveObserved).
	Observed []string `json:"observed,omitempty" yaml:"observed,omitempty"`
}

// Fetcher identifies what produced a Document.
type Fetcher struct {
	Name    string `json:"name,omitempty" yaml:"name,omitempty"`
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
	Kind    string `json:"kind,omitempty" yaml:"kind,omitempty"` // http | browser | warc
}

// Cookie is one cookie set by the page.
type Cookie struct {
	Name   string `json:"name" yaml:"name"`
	Value  string `json:"value,omitempty" yaml:"value,omitempty"`
	Domain string `json:"domain,omitempty" yaml:"domain,omitempty"`
	// Phase is "pre_consent" or "post_consent" when the fetcher accepted a
	// cookie banner; informational.
	Phase string `json:"phase,omitempty" yaml:"phase,omitempty"`
}

// StorageItem is one localStorage/sessionStorage entry.
type StorageItem struct {
	Kind  string `json:"kind,omitempty" yaml:"kind,omitempty"` // local | session
	Key   string `json:"key" yaml:"key"`
	Value string `json:"value,omitempty" yaml:"value,omitempty"`
	Phase string `json:"phase,omitempty" yaml:"phase,omitempty"`
}

// Resource is one sub-resource request.
type Resource struct {
	URL    string `json:"url" yaml:"url"`
	Kind   string `json:"kind,omitempty" yaml:"kind,omitempty"` // script | stylesheet | font | image | xhr | other
	SHA256 string `json:"sha256,omitempty" yaml:"sha256,omitempty"`
	// SHA1 is accepted next to (or instead of) SHA256 for crawlers that hash
	// with SHA-1; both are of the decoded body.
	SHA1   string `json:"sha1,omitempty" yaml:"sha1,omitempty"`
	Size   int64  `json:"size,omitempty" yaml:"size,omitempty"`
	Status int    `json:"status,omitempty" yaml:"status,omitempty"`
	MIME   string `json:"mime,omitempty" yaml:"mime,omitempty"`
	// Headers are the resource's response headers ([name, value] pairs).
	Headers [][2]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Phase   string      `json:"phase,omitempty" yaml:"phase,omitempty"`
}

// TLS holds certificate facts of the page's host.
type TLS struct {
	Issuer  string `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	Subject string `json:"subject,omitempty" yaml:"subject,omitempty"`
}

// Asset is a fetched sub-resource body (JS or CSS), scanned separately from
// the pages that load it and keyed by content hash.
type Asset struct {
	SHA256      string `json:"sha256" yaml:"sha256"`
	URL         string `json:"url,omitempty" yaml:"url,omitempty"`
	ContentType string `json:"content_type,omitempty" yaml:"content_type,omitempty"`
	Body        string `json:"body" yaml:"body"`
}

// EffectiveObserved returns Observed, or the groups inferred from the set
// fields when Observed is empty.
func (d *Document) EffectiveObserved() []string {
	if len(d.Observed) > 0 {
		return d.Observed
	}
	var out []string
	if len(d.Headers) > 0 {
		out = append(out, ObservedHeaders)
	}
	if len(d.Cookies) > 0 || d.hasSetCookie() {
		out = append(out, ObservedCookies)
	}
	if d.HTML != "" {
		out = append(out, ObservedHTML)
	}
	if len(d.Resources) > 0 {
		out = append(out, ObservedResources)
	}
	if len(d.JSGlobals) > 0 {
		out = append(out, ObservedJSGlobals)
	}
	if len(d.DNS) > 0 {
		out = append(out, ObservedDNS)
	}
	if d.TLS != nil {
		out = append(out, ObservedTLS)
	}
	if len(d.Storage) > 0 {
		out = append(out, ObservedStorage)
	}
	return out
}

func (d *Document) hasSetCookie() bool {
	for _, h := range d.Headers {
		if strings.EqualFold(h[0], "set-cookie") {
			return true
		}
	}
	return false
}

// BaseURL is the URL relative references resolve against.
func (d *Document) BaseURL() string {
	if d.FinalURL != "" {
		return d.FinalURL
	}
	return d.URL
}
