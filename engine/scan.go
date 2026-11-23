package engine

import (
	"strings"
	"time"

	"github.com/Thewildweb/stackprint/page"
)

// Options tunes a scan.
type Options struct {
	// MinConfidence drops detections below this confidence (0-100).
	MinConfidence int

	// Assets holds earlier asset scan results by SHA-256. Page resources
	// whose hash is listed contribute those findings, attributed to the
	// resource's URL.
	Assets map[string]*AssetResult

	// NoUnexplained skips collecting unexplained tokens.
	NoUnexplained bool
}

// hit is one signal matching one item.
type hit struct {
	sig     int // signal index, -1 for asset or knowledge hits
	ruleID  string
	techID  string
	typ     page.SignalType
	item    page.Item
	excerpt string
	version string
	vconf   vconf // for hits without a signal
	weak    bool
	bound   *BoundNote
}

// Scan tokenises a document and scans it.
func (s *Scanner) Scan(doc *page.Document, opts Options) (res *Result) {
	start := time.Now()
	res = &Result{Site: doc.Site, URL: doc.BaseURL(), EngineVersion: EngineVersion, RulesetVersion: s.set.Version}
	defer func() {
		if r := recover(); r != nil {
			res.Detections = nil
			res.Error = "scan aborted: panic on input"
		}
		res.ScanMicros = time.Since(start).Microseconds()
	}()
	toks := page.Tokenize(doc)
	res.Observed = toks.Observed
	hits := s.match(toks)
	hits = append(hits, s.assetHits(doc, opts.Assets)...)
	hits = append(hits, s.hashHits(doc)...)
	res.Detections = s.resolve(doc, toks, hits, opts)
	if !opts.NoUnexplained {
		res.Unexplained = s.unexplained(doc, toks, hits)
	}
	return res
}

// match runs every signal type's screen over the tokens.
func (s *Scanner) match(toks *page.Tokens) []hit {
	var hits []hit
	site := toks.Site
	for t := page.SignalType(0); t < page.NumSignalTypes; t++ {
		items := toks.Items[t]
		if len(items) == 0 {
			continue
		}
		if t.Keyed() {
			hits = s.matchKeyed(t, items, site, hits)
		}
		hits = s.matchList(t, items, site, hits)
	}
	return hits
}

// matchKeyed evaluates signals selected by item name.
func (s *Scanner) matchKeyed(t page.SignalType, items []page.Item, site string, hits []hit) []hit {
	byKey := s.keyed[t]
	if len(byKey) == 0 {
		return hits
	}
	for _, it := range items {
		for _, id := range byKey[normKey(t, it.Key)] {
			if h, ok := s.evaluate(id, it, it.Value, site); ok {
				hits = append(hits, h)
			}
		}
	}
	return hits
}

// matchList screens item values (or names, for keyed types) with the type's
// index, then evaluates the surviving candidates.
func (s *Scanner) matchList(t page.SignalType, items []page.Item, site string, hits []hit) []hit {
	idx := s.lists[t]
	if idx == nil {
		return hits
	}
	subject := func(it page.Item) string {
		if t.Keyed() {
			return it.Key
		}
		return it.Value
	}

	// Exact matches go straight through a map.
	if len(idx.exact) > 0 || len(idx.exactCI) > 0 {
		for _, it := range items {
			v := subject(it)
			for _, id := range idx.exact[v] {
				if h, ok := s.evaluate(id, it, v, site); ok {
					hits = append(hits, h)
				}
			}
			if len(idx.exactCI) > 0 {
				for _, id := range idx.exactCI[lowerASCII(v)] {
					if h, ok := s.evaluate(id, it, v, site); ok {
						hits = append(hits, h)
					}
				}
			}
		}
	}

	if idx.cs == nil && idx.ci == nil && len(idx.always) == 0 {
		return hits
	}

	// One pass over all items joined by newlines. Anchors never contain a
	// newline, so a hit always lies inside one item.
	var text string
	if len(items) == 1 {
		text = subject(items[0])
	} else {
		var b strings.Builder
		for i, it := range items {
			if i > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(subject(it))
		}
		text = b.String()
	}

	var cand []int
	seen := map[int]bool{}
	collect := func(ac *ahoCorasick, sigs [][]int, txt string) {
		if ac == nil {
			return
		}
		present := make([]bool, len(sigs))
		var found []int
		ac.match(txt, present, &found)
		for _, a := range found {
			for _, id := range sigs[a] {
				if !seen[id] {
					seen[id] = true
					cand = append(cand, id)
				}
			}
		}
	}
	collect(idx.cs, idx.csSig, text)
	if idx.ci != nil {
		collect(idx.ci, idx.ciSig, lowerASCII(text))
	}
	for _, id := range idx.always {
		if !seen[id] {
			seen[id] = true
			cand = append(cand, id)
		}
	}

	for _, id := range cand {
		for _, it := range items {
			if h, ok := s.evaluate(id, it, subject(it), site); ok {
				hits = append(hits, h)
			}
		}
	}
	return hits
}

// evaluate runs one signal against one item; subject is the matched string
// and site the page's registrable domain.
func (s *Scanner) evaluate(id int, it page.Item, subject, site string) (hit, bool) {
	sg := &s.signals[id]
	if sg.firstParty && (site == "" || page.URLSite(it.Value) != site) {
		return hit{}, false
	}
	var sub []string
	start, end := 0, len(subject)
	cmp := subject
	if sg.ci {
		cmp = lowerASCII(subject)
	}
	switch sg.kind {
	case mPresence:
	case mExact:
		if cmp != sg.lit {
			return hit{}, false
		}
	case mPrefix:
		if !strings.HasPrefix(cmp, sg.lit) {
			return hit{}, false
		}
		end = len(sg.lit)
	case mSuffix:
		if !strings.HasSuffix(cmp, sg.lit) {
			return hit{}, false
		}
		start = len(cmp) - len(sg.lit)
	case mContains:
		i := strings.Index(cmp, sg.lit)
		if i < 0 {
			return hit{}, false
		}
		start, end = i, i+len(sg.lit)
	case mRegex:
		loc := sg.re.FindStringSubmatchIndex(subject)
		if loc == nil {
			return hit{}, false
		}
		start, end = loc[0], loc[1]
		sub = make([]string, len(loc)/2)
		for i := range sub {
			if loc[2*i] >= 0 {
				sub[i] = subject[loc[2*i]:loc[2*i+1]]
			}
		}
	}

	ct := &s.techs[sg.tech]
	techID := ct.def.ID
	if ct.family {
		m := strings.ToLower(strings.TrimSpace(expandRefs(sg.member, sub)))
		if m == "" || !ct.memberRe.MatchString(m) {
			return hit{}, false
		}
		techID = ct.prefix + m
	}

	h := hit{sig: id, techID: techID, typ: sg.typ, item: it, weak: sg.weak}
	h.excerpt = excerpt(subject, start, end, sg.typ)
	if sg.versionUnless == nil || !sg.versionUnless.MatchString(it.Value) {
		switch {
		case sg.version != "":
			h.version = NormalizeVersion(resolveVersion(sg.version, sub))
		case sg.versionQuery != "":
			h.version = queryVersion(it.Value, sg.versionQuery)
		}
	}
	return h, true
}

const excerptLen = 160

// excerpt cuts a readable window around [start,end) of subject. URLs and
// short values are kept whole up to the limit.
func excerpt(subject string, start, end int, t page.SignalType) string {
	if len(subject) <= excerptLen {
		return subject
	}
	if t.IsURL() {
		return subject[:excerptLen]
	}
	pad := (excerptLen - (end - start)) / 2
	if pad < 0 {
		pad = 0
	}
	lo, hi := start-pad, end+pad
	if lo < 0 {
		lo = 0
	}
	if hi > len(subject) {
		hi = len(subject)
	}
	if hi-lo > excerptLen {
		hi = lo + excerptLen
	}
	// Keep the cut on UTF-8 boundaries.
	for lo > 0 && subject[lo]&0xC0 == 0x80 {
		lo--
	}
	for hi < len(subject) && subject[hi]&0xC0 == 0x80 {
		hi++
	}
	return subject[lo:hi]
}
