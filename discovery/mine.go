package discovery

import (
	"sort"
	"strings"
)

// Options tune mining.
type Options struct {
	MinSupport int // sites a token must occur on (default 10)
	// MaxSupport drops tokens present on more than this fraction of pages
	// (default 0.9): browser built-in globals, universal classes.
	MaxSupport   float64
	MinPrecision float64 // P(label | token) (default 0.9)
	MinRecall    float64 // P(token | label) (default 0.05)
	GapRecall    float64 // minimum recall for a recall-gap token (default 0.3)
	GapLift      float64 // minimum lift for a recall-gap token (default 20)
	PerLabel     int     // candidates kept per label (default 15)
	Unknown      int     // unexplained tokens reported (default 200)
	Examples     int     // example sites kept per candidate (default 5)
	// Expand runs label expansion rounds (default 1, -1 = none): a page
	// carrying at least two of a label's strong tokens (precision >= 0.98)
	// joins the label. Labels from detections miss pages where the defining
	// signal is absent (a removed generator tag); without expansion, the very
	// tokens that would recover them look imprecise.
	Expand int
}

func (o *Options) defaults() {
	if o.MinSupport == 0 {
		o.MinSupport = 10
	}
	if o.MaxSupport == 0 {
		o.MaxSupport = 0.9
	}
	if o.MinPrecision == 0 {
		o.MinPrecision = 0.9
	}
	if o.MinRecall == 0 {
		o.MinRecall = 0.05
	}
	if o.GapRecall == 0 {
		o.GapRecall = 0.3
	}
	if o.GapLift == 0 {
		o.GapLift = 20
	}
	if o.PerLabel == 0 {
		o.PerLabel = 15
	}
	if o.Unknown == 0 {
		o.Unknown = 200
	}
	if o.Examples == 0 {
		o.Examples = 5
	}
	if o.Expand == 0 {
		o.Expand = 1
	}
}

type pageRec struct {
	site   string
	tokens []int32
	labels []int32
}

// Explained is the set of a page's tokens that a current rule matched (see
// EvidenceTokens); unexplained tokens are leads for new rules.
type Explained map[Token]bool

// Corpus accumulates labelled, tokenised pages. One page per site is the
// intended unit; statistics count pages.
type Corpus struct {
	labelID  map[string]int32
	labels   []string
	labelCnt []int
	tokID    map[Token]int32
	toks     []Token
	tokCnt   []int
	expCnt   []int // pages where a rule matched the token
	pages    []pageRec
}

// NewCorpus returns an empty corpus.
func NewCorpus() *Corpus {
	return &Corpus{labelID: map[string]int32{}, tokID: map[Token]int32{}}
}

// Pages is the number of pages added.
func (c *Corpus) Pages() int { return len(c.pages) }

// Add records one page's tokens and labels (detected technology ids).
// explained (may be nil) marks the tokens a rule matched on this page.
func (c *Corpus) Add(site string, tokens []Token, labels []string, explained ...Explained) {
	var exp Explained
	if len(explained) > 0 {
		exp = explained[0]
	}
	pr := pageRec{site: site}
	for _, t := range tokens {
		id, ok := c.tokID[t]
		if !ok {
			id = int32(len(c.toks))
			c.tokID[t] = id
			c.toks = append(c.toks, t)
			c.tokCnt = append(c.tokCnt, 0)
			c.expCnt = append(c.expCnt, 0)
		}
		c.tokCnt[id]++
		if exp[t] {
			c.expCnt[id]++
		}
		pr.tokens = append(pr.tokens, id)
	}
	seen := map[string]bool{}
	for _, l := range labels {
		if seen[l] {
			continue
		}
		seen[l] = true
		id, ok := c.labelID[l]
		if !ok {
			id = int32(len(c.labels))
			c.labelID[l] = id
			c.labels = append(c.labels, l)
			c.labelCnt = append(c.labelCnt, 0)
		}
		c.labelCnt[id]++
		pr.labels = append(pr.labels, id)
	}
	c.pages = append(c.pages, pr)
}

// Candidate is a token that predicts a label.
type Candidate struct {
	Label      string  `json:"label"`
	Type       string  `json:"type"`
	Token      string  `json:"token"`
	Support    int     `json:"support"`     // pages with the token
	WithLabel  int     `json:"with_label"`  // ... that carry the label
	LabelPages int     `json:"label_pages"` // pages with the label
	Precision  float64 `json:"precision"`
	Recall     float64 `json:"recall"`
	// BasePrecision is the precision against detection labels only, before
	// expansion; ExpandedPages how many pages expansion added to the label.
	BasePrecision float64 `json:"base_precision"`
	ExpandedPages int     `json:"expanded_pages,omitempty"`
	// Gain is the number of pages with the token but without the label: new
	// detections if the token became a signal — recall gained, or false
	// positives. Review these first.
	Gain int `json:"gain"`
	// Lift is P(label | token) / P(label).
	Lift         float64  `json:"lift"`
	GainExamples []string `json:"gain_examples,omitempty"`
	Examples     []string `json:"examples,omitempty"`
}

// Unexplained is a frequent token no label accounts for.
type Unexplained struct {
	Type          string   `json:"type"`
	Token         string   `json:"token"`
	Support       int      `json:"support"`
	BestLabel     string   `json:"best_label,omitempty"`
	BestPrecision float64  `json:"best_precision,omitempty"`
	CoTokens      []string `json:"co_tokens,omitempty"` // tokens on largely the same pages (Jaccard >= 0.5)
	ExplainedRate float64  `json:"explained_rate,omitempty"`
	Examples      []string `json:"examples,omitempty"`
}

// Report is the outcome of a mining run.
type Report struct {
	Pages      int            `json:"pages"`
	Labels     map[string]int `json:"labels"`
	Candidates []Candidate    `json:"candidates"`
	// Gaps are tokens strongly tied to a label (high lift, high recall) that
	// also occur on many pages without it: usually pages the current rules
	// miss. Their gain examples decide whether they become signals.
	Gaps        []Candidate   `json:"gaps"`
	Unexplained []Unexplained `json:"unexplained"`
}

// Mine computes candidates and unexplained tokens.
func (c *Corpus) Mine(o Options) *Report {
	o.defaults()
	maxCnt := int(o.MaxSupport * float64(len(c.pages)))
	frequent := func(t int32) bool { return c.tokCnt[t] >= o.MinSupport && c.tokCnt[t] <= maxCnt }

	key := func(t, l int32) uint64 { return uint64(uint32(t))<<32 | uint64(uint32(l)) }
	count := func() (map[uint64]int, []int) {
		pair := map[uint64]int{}
		lc := make([]int, len(c.labels))
		for _, p := range c.pages {
			for _, l := range p.labels {
				lc[l]++
			}
			for _, t := range p.tokens {
				if !frequent(t) {
					continue
				}
				for _, l := range p.labels {
					pair[key(t, l)]++
				}
			}
		}
		return pair, lc
	}

	// Pass 1: token x label co-occurrence for frequent tokens.
	basePair, baseCnt := count()
	pair, labelCnt := basePair, baseCnt
	expanded := make([]int, len(c.labels))
	for round := 0; round < o.Expand; round++ {
		strong := map[int32][]int32{} // token -> labels it strongly predicts
		for k, co := range pair {
			t, l := int32(k>>32), int32(uint32(k))
			if co >= o.MinSupport && float64(co)/float64(c.tokCnt[t]) >= 0.98 && !selfReferential(c.toks[t], c.labels[l]) {
				strong[t] = append(strong[t], l)
			}
		}
		added := 0
		for i := range c.pages {
			p := &c.pages[i]
			has := map[int32]bool{}
			for _, l := range p.labels {
				has[l] = true
			}
			votes := map[int32]int{}
			for _, t := range p.tokens {
				for _, l := range strong[t] {
					votes[l]++
				}
			}
			for l, v := range votes {
				if v >= 2 && !has[l] {
					p.labels = append(p.labels, l)
					expanded[l]++
					added++
				}
			}
		}
		if added == 0 {
			break
		}
		pair, labelCnt = count()
	}

	rep := &Report{Pages: len(c.pages), Labels: map[string]int{}}
	for i, l := range c.labels {
		rep.Labels[l] = labelCnt[i]
	}

	type scored struct {
		t, l int32
		co   int
		p, r float64
	}
	byLabel := map[int32][]scored{}
	gapByLabel := map[int32][]scored{}
	bestPrec := map[int32]float64{}
	bestLabel := map[int32]int32{}
	for k, co := range pair {
		t, l := int32(k>>32), int32(uint32(k))
		p := float64(co) / float64(c.tokCnt[t])
		r := float64(co) / float64(labelCnt[l])
		if p > bestPrec[t] {
			bestPrec[t], bestLabel[t] = p, l
		}
		if co < o.MinSupport || selfReferential(c.toks[t], c.labels[l]) {
			continue
		}
		lift := p / (float64(labelCnt[l]) / float64(len(c.pages)))
		switch {
		case p >= o.MinPrecision && r >= o.MinRecall:
			byLabel[l] = append(byLabel[l], scored{t, l, co, p, r})
		case r >= o.GapRecall && lift >= o.GapLift:
			gapByLabel[l] = append(gapByLabel[l], scored{t, l, co, p, r})
		}
	}

	type ckey struct{ t, l int32 }
	chosen := map[ckey]*Candidate{}
	candByTok := map[int32][]int32{}
	gapChosen := map[ckey]*Candidate{}
	keep := func(src map[int32][]scored, dst map[ckey]*Candidate) {
		for l, list := range src {
			sort.Slice(list, func(i, j int) bool {
				fi := list[i].p * list[i].r
				fj := list[j].p * list[j].r
				if fi != fj {
					return fi > fj
				}
				return c.toks[list[i].t] < c.toks[list[j].t]
			})
			if len(list) > o.PerLabel {
				list = list[:o.PerLabel]
			}
			for _, s := range list {
				typ, v := c.toks[s.t].Split()
				dst[ckey{s.t, l}] = &Candidate{
					Label: c.labels[l], Type: typ, Token: v,
					Support: c.tokCnt[s.t], WithLabel: s.co, LabelPages: labelCnt[l],
					Precision: round3(s.p), Recall: round3(s.r), Gain: c.tokCnt[s.t] - s.co,
					Lift:          round3(s.p / (float64(labelCnt[l]) / float64(len(c.pages)))),
					BasePrecision: round3(float64(basePair[key(s.t, l)]) / float64(c.tokCnt[s.t])),
					ExpandedPages: expanded[l],
				}
				candByTok[s.t] = append(candByTok[s.t], l)
			}
		}
	}
	keep(byLabel, chosen)
	keep(gapByLabel, gapChosen)

	// Unexplained: frequent tokens no rule matched on most of their pages.
	// Without explained sets (older callers), fall back to a low best-label
	// precision.
	haveExp := false
	for _, n := range c.expCnt {
		if n > 0 {
			haveExp = true
			break
		}
	}
	var unk []int32
	for t := range c.toks {
		id := int32(t)
		if !frequent(id) {
			continue
		}
		if haveExp {
			if float64(c.expCnt[id]) < 0.5*float64(c.tokCnt[id]) {
				unk = append(unk, id)
			}
		} else if bestPrec[id] < 0.5 {
			unk = append(unk, id)
		}
	}
	sort.Slice(unk, func(i, j int) bool {
		if c.tokCnt[unk[i]] != c.tokCnt[unk[j]] {
			return c.tokCnt[unk[i]] > c.tokCnt[unk[j]]
		}
		return c.toks[unk[i]] < c.toks[unk[j]]
	})
	if len(unk) > o.Unknown {
		unk = unk[:o.Unknown]
	}
	unkIdx := map[int32]int{}
	for i, t := range unk {
		unkIdx[t] = i
	}
	coUnk := make([]map[int32]int, len(unk))
	for i := range coUnk {
		coUnk[i] = map[int32]int{}
	}

	// Pass 2: examples and co-occurrence among unexplained tokens.
	unkEx := make([][]string, len(unk))
	for _, p := range c.pages {
		labels := map[int32]bool{}
		for _, l := range p.labels {
			labels[l] = true
		}
		var here []int32
		for _, t := range p.tokens {
			if i, ok := unkIdx[t]; ok {
				here = append(here, t)
				if len(unkEx[i]) < o.Examples {
					unkEx[i] = append(unkEx[i], p.site)
				}
			}
			for _, l := range candByTok[t] {
				cand := chosen[ckey{t, l}]
				if cand == nil {
					cand = gapChosen[ckey{t, l}]
				}
				if labels[l] {
					if len(cand.Examples) < o.Examples {
						cand.Examples = append(cand.Examples, p.site)
					}
				} else if len(cand.GainExamples) < o.Examples {
					cand.GainExamples = append(cand.GainExamples, p.site)
				}
			}
		}
		for _, a := range here {
			for _, b := range here {
				if a != b {
					coUnk[unkIdx[a]][b]++
				}
			}
		}
	}

	rep.Candidates = sortedCandidates(chosen)
	rep.Gaps = sortedCandidates(gapChosen)

	for i, t := range unk {
		typ, v := c.toks[t].Split()
		u := Unexplained{Type: typ, Token: v, Support: c.tokCnt[t], Examples: unkEx[i],
			ExplainedRate: round3(float64(c.expCnt[t]) / float64(c.tokCnt[t]))}
		if bp := bestPrec[t]; bp > 0 {
			u.BestLabel, u.BestPrecision = c.labels[bestLabel[t]], round3(bp)
		}
		// Co-tokens: unexplained tokens with a page-set Jaccard similarity of at
		// least 0.5, most similar first. Similarity rather than raw counts, so a
		// product's own tokens rank above generic ones that happen to co-occur.
		type co struct {
			t int32
			j float64
		}
		var cos []co
		for b, n := range coUnk[i] {
			j := float64(n) / float64(c.tokCnt[t]+c.tokCnt[b]-n)
			if j >= 0.5 {
				cos = append(cos, co{b, j})
			}
		}
		sort.Slice(cos, func(x, y int) bool {
			return cos[x].j > cos[y].j || (cos[x].j == cos[y].j && c.toks[cos[x].t] < c.toks[cos[y].t])
		})
		for k, cc := range cos {
			if k == 15 {
				break
			}
			ct, cv := c.toks[cc.t].Split()
			u.CoTokens = append(u.CoTokens, ct+":"+cv)
		}
		rep.Unexplained = append(rep.Unexplained, u)
	}
	return rep
}

func sortedCandidates[K comparable](m map[K]*Candidate) []Candidate {
	out := make([]Candidate, 0, len(m))
	for _, c := range m {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Label != b.Label {
			return a.Label < b.Label
		}
		if a.Precision*a.Recall != b.Precision*b.Recall {
			return a.Precision*a.Recall > b.Precision*b.Recall
		}
		return a.Type+a.Token < b.Type+b.Token
	})
	return out
}

// selfReferential drops tokens that merely restate a family member's id
// (the plugin folder path for wp-plugin/<slug>).
func selfReferential(t Token, label string) bool {
	i := strings.LastIndexByte(label, '/')
	if i < 0 {
		return false
	}
	member := label[i+1:]
	_, v := t.Split()
	return strings.Contains(v, "/"+member+"/") || strings.Contains(v, "@"+member)
}

func round3(f float64) float64 {
	return float64(int(f*1000+0.5)) / 1000
}
