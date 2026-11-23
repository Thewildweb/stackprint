package engine

import (
	"regexp/syntax"
	"strings"
)

// minAnchorLen is the shortest literal worth screening with. Shorter literals
// match nearly every page, so such signals are always evaluated instead.
const minAnchorLen = 3

// maxAnchors caps how many alternative anchors one regex may contribute.
const maxAnchors = 16

// anchorSet is a set of literals at least one of which occurs in every string
// a pattern matches. fold means the literals are lowercased and must be
// looked up in lowercased text.
type anchorSet struct {
	lits []string
	fold bool
}

// regexAnchors derives an anchor set from a regular expression, or returns
// ok=false when no safe set exists (the signal is then always evaluated).
//
// The guarantee that matters is soundness: every match must contain one of
// the anchors, or real matches would be screened out. So only parts of the
// expression that are mandatory contribute: concatenations, captures and
// repetitions with min >= 1. Optional parts and character classes break a
// literal run. An alternation contributes the union of its branches' sets,
// and only if every branch has one.
func regexAnchors(expr string) (anchorSet, bool) {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return anchorSet{}, false
	}
	re = re.Simplify()
	lits, fold := mandatory(re)
	if len(lits) == 0 || len(lits) > maxAnchors {
		return anchorSet{}, false
	}
	for _, l := range lits {
		if len(l) < minAnchorLen {
			return anchorSet{}, false
		}
		if fold && !isASCII(l) {
			return anchorSet{}, false
		}
	}
	if fold {
		for i := range lits {
			lits[i] = strings.ToLower(lits[i])
		}
	}
	return anchorSet{lits: dedupe(lits), fold: fold}, true
}

// mandatory returns literals one of which every match of re contains (nil
// when none is known), and whether any of them is case-folded.
func mandatory(re *syntax.Regexp) ([]string, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		return []string{string(re.Rune)}, re.Flags&syntax.FoldCase != 0
	case syntax.OpCapture:
		return mandatory(re.Sub[0])
	case syntax.OpPlus:
		return mandatory(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return mandatory(re.Sub[0])
		}
		return nil, false
	case syntax.OpConcat:
		var best []string
		bestFold := false
		consider := func(lits []string, fold bool) {
			if len(lits) == 0 {
				return
			}
			if best == nil || minLen(lits) > minLen(best) {
				best, bestFold = lits, fold
			}
		}
		// Adjacent literal children form one longer run.
		var run strings.Builder
		runFold := false
		flush := func() {
			if run.Len() > 0 {
				consider([]string{run.String()}, runFold)
			}
			run.Reset()
			runFold = false
		}
		for _, sub := range re.Sub {
			if sub.Op == syntax.OpLiteral {
				f := sub.Flags&syntax.FoldCase != 0
				if run.Len() > 0 && f != runFold {
					flush()
				}
				run.WriteString(string(sub.Rune))
				runFold = f
				continue
			}
			flush()
			consider(mandatory(sub))
		}
		flush()
		return best, bestFold
	case syntax.OpAlternate:
		var all []string
		fold := false
		for _, sub := range re.Sub {
			lits, f := mandatory(sub)
			if len(lits) == 0 {
				return nil, false
			}
			all = append(all, lits...)
			fold = fold || f
		}
		return all, fold
	}
	return nil, false
}

func minLen(lits []string) int {
	m := -1
	for _, l := range lits {
		if m < 0 || len(l) < m {
			m = len(l)
		}
	}
	return m
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// lowerASCII lowercases ASCII letters only, byte for byte, so offsets and
// non-ASCII bytes are preserved.
func lowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}
