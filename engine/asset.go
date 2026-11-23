package engine

import (
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/Thewildweb/stackprint/page"
)

// AssetResult is what one asset body revealed. It depends only on the body
// and the rule set, so it can be cached by (sha256, ruleset version) and
// reused for every page that loads the same file.
type AssetResult struct {
	SHA256         string         `json:"sha256"`
	URL            string         `json:"url,omitempty"`
	RulesetVersion string         `json:"ruleset_version"`
	Findings       []AssetFinding `json:"findings"`
}

// AssetFinding is one technology found inside an asset.
type AssetFinding struct {
	TechID            string `json:"tech_id"`
	Version           string `json:"version,omitempty"`
	VersionConfidence string `json:"version_confidence,omitempty"`
	RuleID            string `json:"rule_id"`
	Excerpt           string `json:"excerpt,omitempty"`
}

// ScanAsset scans one asset body with the asset_body signals.
func (s *Scanner) ScanAsset(a *page.Asset) *AssetResult {
	res := &AssetResult{SHA256: strings.ToLower(a.SHA256), URL: a.URL, RulesetVersion: s.set.Version, Findings: []AssetFinding{}}
	toks := page.TokenizeAsset(a)
	// Only the body is asset evidence; the URL is the page's business.
	hits := s.matchList(page.SigAssetBody, toks.Items[page.SigAssetBody], "", nil)
	best := map[string]AssetFinding{}
	for _, h := range hits {
		sg := &s.signals[h.sig]
		f := AssetFinding{TechID: h.techID, Version: h.version, RuleID: sg.id, Excerpt: h.excerpt}
		if h.version != "" {
			f.VersionConfidence = sg.vconf.String()
		}
		cur, ok := best[h.techID]
		if !ok || (cur.Version == "" && f.Version != "") || parseVConf(f.VersionConfidence) > parseVConf(cur.VersionConfidence) {
			best[h.techID] = f
		}
	}
	for _, id := range sortedKeys(best) {
		res.Findings = append(res.Findings, best[id])
	}
	return res
}

// assetHits turns cached asset findings for the page's resources into hits
// attributed to the resource URL.
func (s *Scanner) assetHits(doc *page.Document, assets map[string]*AssetResult) []hit {
	if len(assets) == 0 {
		return nil
	}
	var hits []hit
	for _, r := range doc.Resources {
		if r.SHA256 == "" {
			continue
		}
		ar := assets[strings.ToLower(r.SHA256)]
		if ar == nil {
			continue
		}
		for _, f := range ar.Findings {
			vc := parseVConf(f.VersionConfidence)
			hits = append(hits, hit{
				sig: -1, ruleID: f.RuleID, techID: f.TechID, typ: page.SigAssetBody,
				item: page.Item{Value: r.URL}, excerpt: f.Excerpt, version: f.Version, vconf: vc,
			})
		}
	}
	return hits
}

const maxUnexplained = 200

// unexplained lists observations no rule accounted for: third-party script
// and stylesheet hosts, generator strings, platform headers and cookie names.
// They are leads for rule discovery, not detections.
func (s *Scanner) unexplained(doc *page.Document, toks *page.Tokens, hits []hit) []Token {
	explained := map[string]bool{}
	for _, h := range hits {
		explained[h.typ.String()+"\x00"+h.item.Key+"\x00"+h.item.Value] = true
		if h.typ.IsURL() {
			if host := hostOf(h.item.Value); host != "" {
				explained["host\x00"+host] = true
			}
		}
	}
	pageHost := hostOf(doc.BaseURL())
	pageSite := toks.Site
	seen := map[Token]bool{}
	var out []Token
	add := func(t Token) {
		if personalLooking(t.Value) {
			return
		}
		if len(out) < maxUnexplained && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	for _, typ := range []page.SignalType{page.SigScriptURL, page.SigStylesheetURL} {
		for _, it := range toks.Items[typ] {
			host := hostOf(it.Value)
			if host == "" || host == pageHost || page.RegistrableDomain(host) == pageSite || explained["host\x00"+host] {
				continue
			}
			add(Token{Type: typ.String() + "_host", Value: host})
		}
	}
	for _, it := range toks.Items[page.SigMeta] {
		if it.Key == "generator" && it.Value != "" && !explained["meta\x00generator\x00"+it.Value] {
			add(Token{Type: "meta_generator", Value: truncate(it.Value)})
		}
	}
	for _, it := range toks.Items[page.SigHeader] {
		switch it.Key {
		case "server", "x-powered-by", "x-generator", "via":
			if !explained["header\x00"+it.Key+"\x00"+it.Value] {
				add(Token{Type: "header_" + it.Key, Value: truncate(it.Value)})
			}
		}
	}
	for _, it := range toks.Items[page.SigCookie] {
		if !explained["cookie\x00"+it.Key+"\x00"+it.Value] {
			add(Token{Type: "cookie_name", Value: it.Key})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// personalLooking reports values that may carry personal data or per-visitor
// identifiers: e-mail addresses, phone-like or long digit runs, long hex or
// base64-like ids. Unexplained tokens are leads about software, so anything
// that looks like a person or a visitor is dropped, not redacted.
func personalLooking(v string) bool {
	if strings.ContainsRune(v, '@') {
		return true
	}
	return longDigitsRe.MatchString(v) || longHexRe.MatchString(v) || longTokenRe.MatchString(v)
}

var (
	longDigitsRe = regexp.MustCompile(`[0-9][0-9 ().+-]{5,}[0-9]`)
	longHexRe    = regexp.MustCompile(`(?i)[0-9a-f]{16,}`)
	longTokenRe  = regexp.MustCompile(`[A-Za-z0-9_-]{32,}`)
)

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
