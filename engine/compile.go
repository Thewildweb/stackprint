// Package engine compiles a stackprint rule set and scans pages with it.
//
// A Scanner is immutable after New, so Scan may be called from many
// goroutines at once. Each page is tokenised once (package page); every
// signal type then gets one Aho-Corasick screen over its items, so the cost
// of a scan grows with the page size, not with the number of rules. Only
// signals whose literal anchor occurs on the page run their full matcher.
package engine

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"sync"

	"github.com/Thewildweb/stackprint/knowledge"
	"github.com/Thewildweb/stackprint/page"
	"github.com/Thewildweb/stackprint/ruleset"
)

// EngineVersion is reported in every result.
const EngineVersion = "0.1.0-dev"

type matcherKind int

const (
	mPresence matcherKind = iota // keyed item present
	mExact
	mPrefix
	mContains
	mSuffix
	mRegex
)

type vconf int

// Version confidence ranks, higher is stronger.
const (
	vLow vconf = iota + 1
	vMedium
	vHigh
)

func (c vconf) String() string {
	switch c {
	case vHigh:
		return "high"
	case vMedium:
		return "medium"
	case vLow:
		return "low"
	}
	return ""
}

func parseVConf(s string) vconf {
	switch s {
	case "high":
		return vHigh
	case "low":
		return vLow
	}
	return vMedium
}

type compiledSignal struct {
	tech   int
	id     string // "<tech id>#<signal id or index>"
	typ    page.SignalType
	key    string // normalised key for keyed types; "" otherwise
	onName bool   // keyed type without key: match against the item name
	kind   matcherKind
	lit    string // literal (lowercased when ci)
	ci     bool
	re     *regexp.Regexp

	firstParty bool

	member        string
	version       string
	versionQuery  string
	versionUnless *regexp.Regexp
	vconf         vconf
	weak          bool
	confidence    int
	bound         *ruleset.Bound
}

type compiledTech struct {
	def      *ruleset.Technology
	family   bool
	prefix   string // "wp-plugin/" for a family or a member of one
	memberRe *regexp.Regexp
	folder   string // regex source, may contain {member}
	folderRe *regexp.Regexp
	suppress *regexp.Regexp
	parent   int // family index for a member rule, -1 otherwise
}

// index screens the items of one signal type (their values, or their names
// for keyed types) for the signals that can match them.
type index struct {
	cs, ci       *ahoCorasick
	csSig, ciSig [][]int // anchor id -> signal ids
	always       []int   // signals without a usable anchor
	exact        map[string][]int
	exactCI      map[string][]int
	hasCI        bool
}

type indexBuilder struct {
	cs, ci       *acBuilder
	csSig, ciSig [][]int
	always       []int
	exact        map[string][]int
	exactCI      map[string][]int
}

func newIndexBuilder() *indexBuilder {
	return &indexBuilder{cs: newACBuilder(), ci: newACBuilder(), exact: map[string][]int{}, exactCI: map[string][]int{}}
}

func (b *indexBuilder) addAnchors(sig int, a anchorSet) {
	ac, lists := b.cs, &b.csSig
	if a.fold {
		ac, lists = b.ci, &b.ciSig
	}
	for _, l := range a.lits {
		id := ac.add(l)
		for len(*lists) <= id {
			*lists = append(*lists, nil)
		}
		(*lists)[id] = appendUnique((*lists)[id], sig)
	}
}

func (b *indexBuilder) add(sig int, s *compiledSignal) {
	switch s.kind {
	case mExact:
		if s.ci {
			b.exactCI[s.lit] = append(b.exactCI[s.lit], sig)
		} else {
			b.exact[s.lit] = append(b.exact[s.lit], sig)
		}
	case mPrefix, mContains, mSuffix:
		if len(s.lit) >= minAnchorLen {
			b.addAnchors(sig, anchorSet{lits: []string{s.lit}, fold: s.ci})
		} else {
			b.always = append(b.always, sig)
		}
	case mRegex:
		if a, ok := regexAnchors(s.re.String()); ok {
			b.addAnchors(sig, a)
		} else {
			b.always = append(b.always, sig)
		}
	default:
		b.always = append(b.always, sig)
	}
}

func (b *indexBuilder) freeze() *index {
	return &index{
		cs: b.cs.build(), ci: b.ci.build(),
		csSig: b.csSig, ciSig: b.ciSig,
		always: b.always, exact: b.exact, exactCI: b.exactCI,
		hasCI: len(b.ciSig) > 0 || len(b.exactCI) > 0,
	}
}

// Scanner is a compiled rule set.
type Scanner struct {
	set      *ruleset.Set
	know     *knowledge.Store
	techs    []compiledTech
	byID     map[string]int
	families map[string]int // prefix -> tech index
	signals  []compiledSignal

	lists [page.NumSignalTypes]*index
	keyed [page.NumSignalTypes]map[string][]int
	// keyedIdx screens the values of keyed items per key, as lists does for
	// list types: a DNS record runs only the signals whose anchors it contains.
	keyedIdx [page.NumSignalTypes]map[string]*index

	folderCache sync.Map // tech id -> *regexp.Regexp (nil when none)
}

// New compiles a validated rule set. know may be nil.
func New(set *ruleset.Set, know *knowledge.Store) (*Scanner, error) {
	if errs := set.Validate(); len(errs) > 0 {
		return nil, fmt.Errorf("invalid rule set (%d problems), first: %w", len(errs), errs[0])
	}
	s := &Scanner{set: set, know: know, byID: map[string]int{}, families: map[string]int{}}

	for i := range set.Technologies {
		t := &set.Technologies[i]
		ct := compiledTech{def: t, parent: -1, folder: t.Folder}
		if t.IsFamily() {
			ct.family = true
			ct.prefix = t.FamilyPrefix()
			ct.memberRe = regexp.MustCompile("^(?:" + t.Member + ")$")
			s.families[ct.prefix] = i
		}
		if t.Version.SuppressMember != "" {
			ct.suppress = regexp.MustCompile(t.Version.SuppressMember)
		}
		s.techs = append(s.techs, ct)
		s.byID[t.ID] = i
	}
	// Members inherit from their family.
	for i := range s.techs {
		ct := &s.techs[i]
		if ct.family {
			continue
		}
		if f, _ := s.familyOf(ct.def.ID); f >= 0 {
			ct.parent = f
			ct.prefix = s.techs[f].prefix
			if ct.folder == "" {
				ct.folder = s.techs[f].folder
			}
			if ct.suppress == nil {
				ct.suppress = s.techs[f].suppress
			}
		}
		if ct.folder != "" && !strings.Contains(ct.folder, "{member}") {
			re, err := regexp.Compile(ct.folder)
			if err != nil {
				return nil, fmt.Errorf("%s: folder: %w", ct.def.ID, err)
			}
			ct.folderRe = re
		}
	}

	builders := [page.NumSignalTypes]*indexBuilder{}
	keyedB := [page.NumSignalTypes]map[string]*indexBuilder{}
	for t := range builders {
		builders[t] = newIndexBuilder()
		s.keyed[t] = map[string][]int{}
		keyedB[t] = map[string]*indexBuilder{}
	}
	for ti := range s.techs {
		def := s.techs[ti].def
		for si := range def.Signals {
			sg := &def.Signals[si]
			cs, err := compileSignal(ti, def, si, sg)
			if err != nil {
				return nil, err
			}
			id := len(s.signals)
			s.signals = append(s.signals, cs)
			c := &s.signals[id]
			if c.typ.Keyed() && !c.onName {
				s.keyed[c.typ][c.key] = append(s.keyed[c.typ][c.key], id)
				b := keyedB[c.typ][c.key]
				if b == nil {
					b = newIndexBuilder()
					keyedB[c.typ][c.key] = b
				}
				b.add(id, c)
				continue
			}
			builders[c.typ].add(id, c)
		}
	}
	for t := range builders {
		s.lists[t] = builders[t].freeze()
		s.keyedIdx[t] = map[string]*index{}
		for k, b := range keyedB[t] {
			s.keyedIdx[t][k] = b.freeze()
		}
	}
	return s, nil
}

func compileSignal(ti int, def *ruleset.Technology, si int, sg *ruleset.Signal) (compiledSignal, error) {
	typ, _ := page.ParseSignalType(sg.Type)
	name := sg.ID
	if name == "" {
		name = fmt.Sprint(si)
	}
	c := compiledSignal{
		tech:         ti,
		id:           def.ID + "#" + name,
		typ:          typ,
		member:       sg.Member,
		version:      sg.Version,
		versionQuery: sg.VersionQuery,
		vconf:        parseVConf(sg.VersionConfidence),
		weak:         sg.WeakVersion,
		confidence:   100,
		bound:        sg.Bound,
		ci:           sg.IgnoreCase,
		firstParty:   sg.FirstParty,
	}
	if sg.Confidence != nil {
		c.confidence = *sg.Confidence
	}
	if sg.VersionUnless != "" {
		re, err := regexp.Compile(sg.VersionUnless)
		if err != nil {
			return c, fmt.Errorf("%s: version_unless: %w", c.id, err)
		}
		c.versionUnless = re
	}
	if typ.Keyed() {
		if sg.Key == "" {
			c.onName = true
		} else {
			c.key = normKey(typ, sg.Key)
		}
	}
	switch {
	case sg.Exact != "":
		c.kind, c.lit = mExact, sg.Exact
	case sg.Prefix != "":
		c.kind, c.lit = mPrefix, sg.Prefix
	case sg.Contains != "":
		c.kind, c.lit = mContains, sg.Contains
	case sg.Suffix != "":
		c.kind, c.lit = mSuffix, sg.Suffix
	case sg.Regex != "":
		re, err := regexp.Compile(sg.Regex)
		if err != nil {
			return c, fmt.Errorf("%s: %w", c.id, err)
		}
		c.kind, c.re = mRegex, re
	default:
		c.kind = mPresence
	}
	if c.ci {
		c.lit = lowerASCII(c.lit)
	}
	return c, nil
}

// normKey normalises an item name the way the tokeniser does for its type.
func normKey(t page.SignalType, k string) string {
	switch t {
	case page.SigHeader, page.SigMeta, page.SigDataAttr:
		return strings.ToLower(k)
	case page.SigDNS:
		return strings.ToUpper(k)
	}
	return k
}

func appendUnique(list []int, v int) []int {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// RulesetVersion is the content version of the compiled rules.
func (s *Scanner) RulesetVersion() string { return s.set.Version }

// Technologies lists the ids of every rule, sorted.
func (s *Scanner) Technologies() []string {
	ids := make([]string, 0, len(s.techs))
	for _, t := range s.techs {
		ids = append(ids, t.def.ID)
	}
	sort.Strings(ids)
	return ids
}

// JSGlobalKeys lists the global paths js_global signals look at, for browser
// fetchers that evaluate them in the page.
func (s *Scanner) JSGlobalKeys() []string {
	var keys []string
	for k := range s.keyed[page.SigJSGlobal] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Anchors lists literals for the signals of one type: every value such a
// signal can match contains at least one of them (lowercased when the signal
// ignores case). A feeder can pre-select candidate items with them, e.g. the
// certificate host names worth putting into documents. unanchored names the
// signals without a usable literal, which a pre-selection would miss.
func (s *Scanner) Anchors(t page.SignalType) (lits, unanchored []string) {
	seen := map[string]bool{}
	add := func(l string, fold bool) {
		if fold {
			l = lowerASCII(l)
		}
		if l != "" && !seen[l] {
			seen[l] = true
			lits = append(lits, l)
		}
	}
	for i := range s.signals {
		c := &s.signals[i]
		if c.typ != t {
			continue
		}
		switch c.kind {
		case mExact, mPrefix, mContains, mSuffix:
			add(c.lit, c.ci)
		case mRegex:
			// Any mandatory literal will do for a pre-selection (sound, if
			// broad), so neither the screen's minimum length nor its cap.
			re, err := syntax.Parse(c.re.String(), syntax.Perl)
			if err != nil {
				unanchored = append(unanchored, c.id)
				continue
			}
			ls, fold := mandatory(re.Simplify())
			if len(ls) == 0 {
				unanchored = append(unanchored, c.id)
				continue
			}
			for _, l := range ls {
				add(l, fold)
			}
		default:
			unanchored = append(unanchored, c.id)
		}
	}
	sort.Strings(lits)
	sort.Strings(unanchored)
	return lits, unanchored
}

// Matchers lists the signals of one type as RE2 expressions (literal
// matchers quoted, ignore_case as (?i)), so a feeder can select exactly the
// items the rules can match, e.g. in a database that speaks RE2.
func (s *Scanner) Matchers(t page.SignalType) []string {
	var out []string
	seen := map[string]bool{}
	for i := range s.signals {
		c := &s.signals[i]
		if c.typ != t {
			continue
		}
		var e string
		switch c.kind {
		case mExact:
			e = "^" + regexp.QuoteMeta(c.lit) + "$"
		case mPrefix:
			e = "^" + regexp.QuoteMeta(c.lit)
		case mSuffix:
			e = regexp.QuoteMeta(c.lit) + "$"
		case mContains:
			e = regexp.QuoteMeta(c.lit)
		case mRegex:
			e = c.re.String()
		default:
			e = ""
		}
		if c.ci && c.kind != mRegex {
			e = "(?i)" + e
		}
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	sort.Strings(out)
	return out
}
