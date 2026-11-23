package engine

import (
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/Thewildweb/stackprint/knowledge"
	"github.com/Thewildweb/stackprint/page"
	"github.com/Thewildweb/stackprint/ruleset"
)

// Result is the outcome of scanning one page.
type Result struct {
	Site           string      `json:"site,omitempty"`
	URL            string      `json:"url,omitempty"`
	EngineVersion  string      `json:"engine_version"`
	RulesetVersion string      `json:"ruleset_version"`
	Observed       []string    `json:"observed,omitempty"`
	Detections     []Detection `json:"detections"`
	Unexplained    []Token     `json:"unexplained,omitempty"`
	ScanMicros     int64       `json:"scan_us"`
	Error          string      `json:"error,omitempty"`
}

// Detection is one technology found on a page.
type Detection struct {
	TechID      string               `json:"tech_id"`
	Name        string               `json:"name"`
	Vendor      string               `json:"vendor,omitempty"`
	Categories  []string             `json:"categories,omitempty"`
	Identifiers *ruleset.Identifiers `json:"identifiers,omitempty"`
	Confidence  int                  `json:"confidence"`
	// MemberRule is false for a family member detected only by the family
	// rule (no rule of its own yet).
	MemberRule *bool `json:"member_rule,omitempty"`

	Version           string `json:"version,omitempty"`
	VersionConfidence string `json:"version_confidence,omitempty"`
	VersionSource     string `json:"version_source,omitempty"`
	VersionRange      *Range `json:"version_range,omitempty"`
	VersionConflict   bool   `json:"version_conflict,omitempty"`
	// OtherVersions are further copies of the technology on the page at other
	// versions, known from exact file hashes (a plugin bundling its own jQuery
	// next to the site's): each is really loaded, so each counts for CVEs.
	OtherVersions     []string    `json:"other_versions,omitempty"`
	CandidateReleases *Candidates `json:"candidate_releases,omitempty"`
	Bounds            []BoundNote `json:"bounds,omitempty"`

	Evidence  []Evidence `json:"evidence"`
	ImpliedBy []string   `json:"implied_by,omitempty"`
}

// Range is a version interval; empty ends are open.
type Range = ruleset.Bound

// Candidates summarises the known releases inside a version range.
type Candidates struct {
	Count    int      `json:"count"`
	First    string   `json:"first,omitempty"`
	Last     string   `json:"last,omitempty"`
	Releases []string `json:"releases,omitempty"` // listed when few
}

// BoundNote is one version bound with what it came from.
type BoundNote struct {
	Kind string `json:"kind"` // signal | file_presence | bundled_version | asset_hash | observed_at
	Range
	RuleID   string    `json:"rule_id,omitempty"`
	Source   string    `json:"source,omitempty"`
	Evidence *Evidence `json:"evidence,omitempty"`
}

// Evidence is one observation supporting a detection.
type Evidence struct {
	Signal  string `json:"signal"` // signal type
	RuleID  string `json:"rule_id"`
	Key     string `json:"key,omitempty"`
	Value   string `json:"value"`
	Version string `json:"version,omitempty"`
}

// Token is an observation no rule explains, a lead for rule discovery.
type Token struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

const maxEvidence = 12

type vcand struct {
	version string
	conf    vconf
	ruleID  string
	item    string
	weak    bool
	high    bool
}

type agg struct {
	id         string
	conf       int
	evidence   []Evidence
	evSeen     map[string]bool
	cands      []vcand
	bounds     []BoundNote
	items      []string // URL items that matched, for folder attribution
	impliedBy  []string
	hasOwnHits bool
}

func (s *Scanner) techFor(id string) (ct *compiledTech, member string, ownRule bool) {
	if i, ok := s.byID[id]; ok {
		ct = &s.techs[i]
		if ct.prefix != "" {
			member = strings.TrimPrefix(id, ct.prefix)
		}
		return ct, member, true
	}
	if f, prefix := s.familyOf(id); f >= 0 {
		return &s.techs[f], id[len(prefix):], false
	}
	return nil, "", false
}

// familyOf returns the family whose prefix id starts with (the shortest
// matching prefix, so "npm/@scope/name" belongs to "npm/*"), or -1.
func (s *Scanner) familyOf(id string) (int, string) {
	for i := 0; i < len(id); i++ {
		if id[i] == '/' {
			if f, ok := s.families[id[:i+1]]; ok {
				return f, id[:i+1]
			}
		}
	}
	return -1, ""
}

func (s *Scanner) resolve(doc *page.Document, toks *page.Tokens, hits []hit, opts Options) []Detection {
	aggs := map[string]*agg{}
	get := func(id string) *agg {
		a := aggs[id]
		if a == nil {
			a = &agg{id: id, evSeen: map[string]bool{}}
			aggs[id] = a
		}
		return a
	}

	// Which items gave a strong (non-weak) version to which technology.
	strongOn := map[string]map[string]bool{}
	for _, h := range hits {
		if h.version != "" && !h.weak {
			if strongOn[h.item.Value] == nil {
				strongOn[h.item.Value] = map[string]bool{}
			}
			strongOn[h.item.Value][h.techID] = true
		}
	}

	for _, h := range hits {
		a := get(h.techID)
		a.hasOwnHits = true
		sg := s.sigFor(h)
		conf, ruleID := 100, h.ruleID
		if sg != nil {
			conf, ruleID = sg.confidence, sg.id
		}
		key := ruleID + "\x00" + h.item.Value
		if !a.evSeen[key] {
			a.evSeen[key] = true
			a.conf += conf
			// Versioned evidence may exceed the cap a little, so the item a
			// version came from is always shown.
			if len(a.evidence) < maxEvidence || (h.version != "" && len(a.evidence) < maxEvidence+4) {
				a.evidence = append(a.evidence, Evidence{Signal: h.typ.String(), RuleID: ruleID, Key: h.item.Key, Value: h.excerpt, Version: h.version})
			}
		}
		if h.typ.IsURL() || h.typ == page.SigAssetBody {
			a.items = append(a.items, h.item.Value)
		}
		if h.version != "" && !(h.weak && strongElsewhere(strongOn[h.item.Value], h.techID)) {
			vc := vcand{version: h.version, conf: h.vconf, ruleID: ruleID, item: h.item.Value}
			if sg != nil {
				vc.conf = sg.vconf
			}
			a.cands = append(a.cands, vc)
		}
		if h.bound != nil {
			a.bounds = append(a.bounds, *h.bound)
		}
		if sg != nil && sg.bound != nil {
			ev := Evidence{Signal: h.typ.String(), RuleID: ruleID, Key: h.item.Key, Value: h.excerpt}
			a.bounds = append(a.bounds, BoundNote{Kind: "signal", Range: *sg.bound, RuleID: ruleID, Evidence: &ev})
		}
	}

	s.applyRelations(aggs)

	// Versions: resolve each detection, technologies referenced by
	// suppress_equal_to first (memoised).
	versions := map[string]string{}
	var resolveOne func(id string, depth int) string
	done := map[string]bool{}
	dets := map[string]*Detection{}
	resolveOne = func(id string, depth int) string {
		if done[id] || depth > 8 {
			return versions[id]
		}
		done[id] = true
		a := aggs[id]
		ct, member, own := s.techFor(id)
		d := s.newDetection(id, a, ct, member, own)
		var suppress []string
		if ct != nil {
			for _, ref := range s.policy(ct).SuppressEqualTo {
				if _, ok := aggs[ref]; ok {
					if v := resolveOne(ref, depth+1); v != "" {
						suppress = append(suppress, v)
					}
				}
			}
		}
		s.finishVersion(doc, toks, d, a, ct, member, suppress, aggs)
		versions[id] = d.Version
		dets[id] = d
		return d.Version
	}
	ids := make([]string, 0, len(aggs))
	for id := range aggs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		resolveOne(id, 0)
	}

	out := make([]Detection, 0, len(dets))
	for _, id := range ids {
		d := dets[id]
		if d.Confidence < opts.MinConfidence {
			continue
		}
		out = append(out, *d)
	}
	return out
}

func (s *Scanner) sigFor(h hit) *compiledSignal {
	if h.sig < 0 {
		return nil
	}
	return &s.signals[h.sig]
}

func (s *Scanner) policy(ct *compiledTech) ruleset.VersionPolicy {
	p := ct.def.Version
	if ct.parent >= 0 && len(p.SuppressEqualTo) == 0 {
		p.SuppressEqualTo = s.techs[ct.parent].def.Version.SuppressEqualTo
	}
	return p
}

// relations returns the effective implies/requires/excludes of a detection
// (a member rule adds to its family's).
func (s *Scanner) relations(id string) (implies, requires, excludes []string) {
	ct, _, _ := s.techFor(id)
	if ct == nil {
		return nil, nil, nil
	}
	add := func(t *ruleset.Technology) {
		implies = append(implies, t.Implies...)
		requires = append(requires, t.Requires...)
		excludes = append(excludes, t.Excludes...)
	}
	add(ct.def)
	if ct.parent >= 0 {
		add(s.techs[ct.parent].def)
	}
	return
}

func (s *Scanner) applyRelations(aggs map[string]*agg) {
	// Implies, to a fixed point.
	for changed := true; changed; {
		changed = false
		for _, id := range sortedKeys(aggs) {
			a := aggs[id]
			imp, _, _ := s.relations(id)
			for _, t := range imp {
				b, ok := aggs[t]
				if !ok {
					b = &agg{id: t, evSeen: map[string]bool{}}
					aggs[t] = b
					changed = true
				}
				if !contains(b.impliedBy, id) {
					b.impliedBy = append(b.impliedBy, id)
					if !b.hasOwnHits && capConf(a.conf) > b.conf {
						b.conf = capConf(a.conf)
					}
				}
			}
		}
	}
	// Requires: drop until stable.
	for changed := true; changed; {
		changed = false
		for _, id := range sortedKeys(aggs) {
			_, req, _ := s.relations(id)
			for _, r := range req {
				if _, ok := aggs[r]; !ok {
					delete(aggs, id)
					changed = true
					break
				}
			}
		}
	}
	// Excludes.
	var drop []string
	for _, id := range sortedKeys(aggs) {
		_, _, exc := s.relations(id)
		drop = append(drop, exc...)
	}
	for _, id := range drop {
		delete(aggs, id)
	}
}

func (s *Scanner) newDetection(id string, a *agg, ct *compiledTech, member string, own bool) *Detection {
	d := &Detection{TechID: id, Confidence: capConf(a.conf), Evidence: a.evidence, ImpliedBy: a.impliedBy}
	if d.Evidence == nil {
		d.Evidence = []Evidence{}
	}
	if ct == nil {
		d.Name = id
		return d
	}
	def := ct.def
	fam := def
	if ct.parent >= 0 {
		fam = s.techs[ct.parent].def
	}
	fill := func(t *ruleset.Technology) {
		if d.Name == "" && t.Name != "" {
			d.Name = strings.ReplaceAll(t.Name, "{member}", member)
		}
		if d.Vendor == "" {
			d.Vendor = t.Vendor
		}
		for _, c := range t.Categories {
			if !contains(d.Categories, c) {
				d.Categories = append(d.Categories, c)
			}
		}
		if !t.Identifiers.IsZero() {
			ids := t.Identifiers.Expand(member)
			if d.Identifiers == nil {
				d.Identifiers = &ids
			} else {
				// A member rule's own identifiers win; the family fills gaps.
				if len(d.Identifiers.CPE) == 0 {
					d.Identifiers.CPE = ids.CPE
				}
				if d.Identifiers.PURL == "" {
					d.Identifiers.PURL = ids.PURL
				}
				if d.Identifiers.WPOrgSlug == "" {
					d.Identifiers.WPOrgSlug = ids.WPOrgSlug
				}
			}
		}
	}
	fill(def)
	if fam != def {
		fill(fam)
	}
	if ct.family || ct.parent >= 0 {
		v := own && !ct.family
		d.MemberRule = &v
	}
	return d
}

// finishVersion picks the point version, collects bounds and intersects them.
func (s *Scanner) finishVersion(doc *page.Document, toks *page.Tokens, d *Detection, a *agg, ct *compiledTech, member string, suppress []string, aggs map[string]*agg) {
	if ct != nil && ct.suppress != nil && member != "" && ct.suppress.MatchString(member) {
		return
	}
	cands := a.cands[:0:0]
	for _, c := range a.cands {
		if c.conf != vHigh && contains(suppress, c.version) {
			continue
		}
		cands = append(cands, c)
	}

	pack := s.know.Get(d.TechID)
	releases := map[string]bool{}
	if pack != nil {
		for _, r := range pack.Releases {
			if v := NormalizeVersion(r.Version); v != "" {
				releases[v] = true
			}
		}
	}

	best := pick(cands, nil)
	if best != nil && len(releases) > 0 && !releases[best.version] {
		if alt := pick(cands, func(c vcand) bool { return releases[c.version] }); alt != nil {
			best = alt
		} else if newerThanAll(best.version, releases) && best.conf != vHigh {
			best = nil
		} else if best.conf != vHigh {
			b := *best
			b.conf = vLow
			best = &b
		}
	}

	// Bounds.
	bounds := append([]BoundNote(nil), a.bounds...)
	if ct != nil && pack != nil {
		bounds = append(bounds, s.knowledgeBounds(doc, toks, d.TechID, ct, member, pack, aggs)...)
	}
	d.Bounds = bounds
	// Exact file hashes naming different versions are several copies, not a
	// contradiction: bound with the rest, then pick one and list the others.
	copies := hashCopies(bounds)
	if len(copies) > 1 {
		var rest []BoundNote
		for _, b := range bounds {
			if !isHashPoint(b) {
				rest = append(rest, b)
			}
		}
		bounds = rest
	}
	lo, hi, conflict := intersect(bounds)
	if conflict {
		d.VersionConflict = true
	} else if lo != nil || hi != nil {
		r := Range{}
		if lo != nil {
			r.Min, r.MinInclusive = lo.v, lo.incl
		}
		if hi != nil {
			r.Max, r.MaxInclusive = hi.v, hi.incl
		}
		d.VersionRange = &r
		if best != nil && !inRange(best.version, lo, hi) {
			if best.conf == vHigh {
				d.VersionConflict = true
			} else if alt := pick(cands, func(c vcand) bool { return inRange(c.version, lo, hi) }); alt != nil {
				best = alt
			} else {
				best = nil
			}
		}
		if len(releases) > 0 {
			d.CandidateReleases = candidates(releases, lo, hi)
			if best == nil && d.CandidateReleases.Count == 1 {
				best = &vcand{version: d.CandidateReleases.First, conf: vMedium, ruleID: "range"}
			}
		}
		// Bounds that pin one version (an exact file hash) give that version.
		if best == nil && lo != nil && hi != nil && lo.incl && hi.incl && CompareVersions(lo.v, hi.v) == 0 {
			best = &vcand{version: lo.v, conf: vMedium, ruleID: "range"}
			for _, b := range bounds {
				if isHashPoint(b) {
					best.conf, best.ruleID = vHigh, "asset_hash"
				}
			}
		}
	}
	if len(copies) > 1 {
		main := copies[len(copies)-1] // the newest copy, unless a signal names one of them
		if best != nil && contains(copies, best.version) {
			main = best.version
		}
		if best == nil || best.version != main {
			best = &vcand{version: main, conf: vHigh, ruleID: "asset_hash"}
		}
		for _, v := range copies {
			if v != main {
				d.OtherVersions = append(d.OtherVersions, v)
			}
		}
	}
	if best != nil {
		d.Version = best.version
		d.VersionConfidence = best.conf.String()
		d.VersionSource = best.ruleID
	}
}

func isHashPoint(b BoundNote) bool {
	return b.Kind == "asset_hash" && b.Range.Min != "" && CompareVersions(b.Range.Min, b.Range.Max) == 0
}

// hashCopies returns the distinct versions exact file-hash bounds name, oldest first.
func hashCopies(bounds []BoundNote) []string {
	var out []string
	for _, b := range bounds {
		if v := NormalizeVersion(b.Range.Min); isHashPoint(b) && v != "" && !contains(out, v) {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return CompareVersions(out[i], out[j]) < 0 })
	return out
}

// pick chooses among version candidates: highest confidence class, then the
// version most items agree on, then the higher version. keep filters (nil =
// all).
func pick(cands []vcand, keep func(vcand) bool) *vcand {
	type tally struct {
		c vcand
		n int
	}
	var best *tally
	byKey := map[string]*tally{}
	for _, c := range cands {
		if keep != nil && !keep(c) {
			continue
		}
		k := c.version
		t := byKey[k]
		if t == nil {
			t = &tally{c: c}
			byKey[k] = t
		}
		t.n++
		if c.conf > t.c.conf {
			t.c.conf, t.c.ruleID, t.c.item = c.conf, c.ruleID, c.item
		}
	}
	for _, t := range byKey {
		switch {
		case best == nil,
			t.c.conf > best.c.conf,
			t.c.conf == best.c.conf && t.n > best.n,
			t.c.conf == best.c.conf && t.n == best.n && CompareVersions(t.c.version, best.c.version) > 0:
			best = t
		}
	}
	if best == nil {
		return nil
	}
	c := best.c
	return &c
}

func newerThanAll(v string, releases map[string]bool) bool {
	for r := range releases {
		if CompareVersions(v, r) <= 0 {
			return false
		}
	}
	return true
}

type end struct {
	v    string
	incl bool
}

// intersect combines bounds into one interval. conflict is true when no
// version satisfies them all.
func intersect(bounds []BoundNote) (lo, hi *end, conflict bool) {
	for _, b := range bounds {
		if v := NormalizeVersion(b.Min); v != "" {
			c := 1
			if lo != nil {
				c = CompareVersions(v, lo.v)
			}
			if lo == nil || c > 0 || (c == 0 && !b.MinInclusive) {
				lo = &end{v, b.MinInclusive}
			}
		}
		if v := NormalizeVersion(b.Max); v != "" {
			c := -1
			if hi != nil {
				c = CompareVersions(v, hi.v)
			}
			if hi == nil || c < 0 || (c == 0 && !b.MaxInclusive) {
				hi = &end{v, b.MaxInclusive}
			}
		}
	}
	if lo != nil && hi != nil {
		c := CompareVersions(lo.v, hi.v)
		if c > 0 || (c == 0 && !(lo.incl && hi.incl)) {
			return nil, nil, true
		}
	}
	return lo, hi, false
}

func inRange(v string, lo, hi *end) bool {
	if lo != nil {
		c := CompareVersions(v, lo.v)
		if c < 0 || (c == 0 && !lo.incl) {
			return false
		}
	}
	if hi != nil {
		c := CompareVersions(v, hi.v)
		if c > 0 || (c == 0 && !hi.incl) {
			return false
		}
	}
	return true
}

const maxListedReleases = 25

func candidates(releases map[string]bool, lo, hi *end) *Candidates {
	var in []string
	for r := range releases {
		if inRange(r, lo, hi) {
			in = append(in, r)
		}
	}
	sort.Slice(in, func(i, j int) bool { return CompareVersions(in[i], in[j]) < 0 })
	c := &Candidates{Count: len(in)}
	if len(in) > 0 {
		c.First, c.Last = in[0], in[len(in)-1]
	}
	if len(in) <= maxListedReleases {
		c.Releases = in
	}
	return c
}

// folderRe returns the regex locating files a detection ships, or nil.
func (s *Scanner) folderRe(id string, ct *compiledTech, member string) *regexp.Regexp {
	if ct.folderRe != nil {
		return ct.folderRe
	}
	if ct.folder == "" {
		return nil
	}
	if v, ok := s.folderCache.Load(id); ok {
		re, _ := v.(*regexp.Regexp)
		return re
	}
	re, err := regexp.Compile(strings.ReplaceAll(ct.folder, "{member}", regexp.QuoteMeta(member)))
	if err != nil {
		re = nil
	}
	s.folderCache.Store(id, re)
	return re
}

// relPath returns the path of rawURL below the folder match, lowercased and
// without query, or "" when the URL is not inside the folder.
func relPath(rawURL string, folder *regexp.Regexp) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	p := u.EscapedPath()
	loc := folder.FindStringIndex(p)
	if loc == nil {
		return ""
	}
	return strings.ToLower(strings.TrimPrefix(p[loc[1]:], "/"))
}

// knowledgeBounds derives bounds from release knowledge: files only some
// releases have, bundled library versions, and the fetch date.
func (s *Scanner) knowledgeBounds(doc *page.Document, toks *page.Tokens, id string, ct *compiledTech, member string, pack *knowledge.Pack, aggs map[string]*agg) []BoundNote {
	var out []BoundNote
	folder := s.folderRe(id, ct, member)
	src := pack.Source

	if folder != nil && len(pack.Files) > 0 {
		markers := map[string]knowledge.FileMarker{}
		for _, f := range pack.Files {
			markers[strings.ToLower(strings.TrimPrefix(f.Path, "/"))] = f
		}
		seen := map[string]bool{}
		for _, it := range toks.Items[page.SigResourceURL] {
			rel := relPath(it.Value, folder)
			if rel == "" || seen[rel] {
				continue
			}
			seen[rel] = true
			if m, ok := markers[rel]; ok {
				out = append(out, BoundNote{
					Kind:     "file_presence",
					Range:    Range{Min: m.After, Max: m.Before},
					Source:   src,
					Evidence: &Evidence{Signal: "resource_url", RuleID: "knowledge:" + id, Value: truncate(it.Value)},
				})
			}
		}
	}

	if folder != nil && len(pack.Bundled) > 0 {
		for _, libID := range sortedKeys(aggs) {
			if libID == id {
				continue
			}
			lib := aggs[libID]
			for _, c := range lib.cands {
				if relPath(c.item, folder) == "" {
					continue // only a copy inside this folder says anything about this technology
				}
				for _, b := range pack.Bundled {
					if b.Lib == libID && NormalizeVersion(b.LibVersion) == c.version {
						out = append(out, BoundNote{
							Kind:     "bundled_version",
							Range:    Range{Min: b.Min, MinInclusive: true, Max: b.Max, MaxInclusive: true},
							Source:   src,
							Evidence: &Evidence{Signal: "bundled", RuleID: c.ruleID, Value: truncate(c.item), Version: libID + "@" + c.version},
						})
					}
				}
			}
		}
	}

	if doc.FetchedAt != nil && len(pack.Releases) > 0 {
		day := doc.FetchedAt.UTC().Format("2006-01-02")
		newest, later := "", false
		for _, r := range pack.Releases {
			v := NormalizeVersion(r.Version)
			if v == "" || r.Date == "" {
				continue
			}
			if r.Date > day {
				later = true
				continue
			}
			if newest == "" || CompareVersions(v, newest) > 0 {
				newest = v
			}
		}
		if later && newest != "" {
			out = append(out, BoundNote{
				Kind:   "observed_at",
				Range:  Range{Max: newest, MaxInclusive: true},
				Source: src,
				Evidence: &Evidence{Signal: "fetched_at", RuleID: "knowledge:" + id,
					Value: "fetched " + day + "; newest release published by then"},
			})
		}
	}
	return out
}

// hashHits turns page resources whose hash a technology release ships into
// detections with a release-range bound.
func (s *Scanner) hashHits(doc *page.Document) []hit {
	if s.know.Len() == 0 {
		return nil
	}
	var hits []hit
	for _, r := range doc.Resources {
		algo, sum := "sha256", r.SHA256
		hhs := s.know.ByHash(sum)
		if len(hhs) == 0 && r.SHA1 != "" {
			algo, sum, hhs = "sha1", r.SHA1, s.know.ByHash(r.SHA1)
		}
		for _, hh := range hhs {
			ev := Evidence{Signal: "asset_hash", RuleID: "knowledge:" + hh.TechID, Value: truncate(r.URL) + " " + algo + ":" + shortHash(sum)}
			src := ""
			if p := s.know.Get(hh.TechID); p != nil {
				src = p.Source
			}
			hits = append(hits, hit{
				sig: -1, techID: hh.TechID, typ: page.SigResourceURL, ruleID: "knowledge:" + hh.TechID,
				item: page.Item{Value: r.URL}, excerpt: ev.Value,
				bound: &BoundNote{Kind: "asset_hash", Source: src, Evidence: &ev,
					Range: Range{Min: hh.Hash.Min, MinInclusive: true, Max: hh.Hash.Max, MaxInclusive: true}},
			})
		}
	}
	return hits
}

// strongElsewhere reports whether another technology than id took a strong
// version from the same item.
func strongElsewhere(techs map[string]bool, id string) bool {
	for t := range techs {
		if t != id {
			return true
		}
	}
	return false
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func truncate(s string) string {
	if len(s) > excerptLen {
		return s[:excerptLen]
	}
	return s
}

func capConf(c int) int {
	if c > 100 {
		return 100
	}
	return c
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
