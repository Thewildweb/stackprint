package discovery

import (
	"fmt"
	"testing"
)

func TestMineFindsPreciseToken(t *testing.T) {
	c := NewCorpus()
	for i := 0; i < 50; i++ {
		c.Add(fmt.Sprint("l", i), []Token{tok(TClass, "acme-widget"), tok(TClass, "row")}, []string{"acme"})
	}
	for i := 0; i < 200; i++ {
		c.Add(fmt.Sprint("o", i), []Token{tok(TClass, "row")}, nil)
	}
	c.Add("fp", []Token{tok(TClass, "acme-widget")}, nil)
	rep := c.Mine(Options{MinSupport: 5})
	if len(rep.Candidates) != 1 {
		t.Fatalf("candidates %+v", rep.Candidates)
	}
	cd := rep.Candidates[0]
	if cd.Token != "acme-widget" || cd.Gain != 1 || cd.GainExamples[0] != "fp" || cd.Recall != 1 {
		t.Fatalf("candidate %+v", cd)
	}
	for _, u := range rep.Unexplained {
		if u.Token == "acme-widget" {
			t.Fatal("explained token reported as unexplained")
		}
	}
}

// A CMS whose generator tag is often removed: the token on every page of it
// looks imprecise against generator-only labels, and is reported as a gap.
func TestMineReportsRecallGap(t *testing.T) {
	c := NewCorpus()
	for i := 0; i < 50; i++ {
		c.Add(fmt.Sprint("gen", i), []Token{tok(TClass, "cms-options"), tok(TClass, "row")}, []string{"cms"})
	}
	for i := 0; i < 40; i++ {
		c.Add(fmt.Sprint("nogen", i), []Token{tok(TClass, "cms-options"), tok(TClass, "row")}, nil)
	}
	for i := 0; i < 5000; i++ {
		c.Add(fmt.Sprint("other", i), []Token{tok(TClass, "row")}, nil)
	}
	rep := c.Mine(Options{MinSupport: 5})
	if len(rep.Candidates) != 0 {
		t.Fatalf("precision 50/90 must not pass as a candidate: %+v", rep.Candidates)
	}
	if len(rep.Gaps) != 1 || rep.Gaps[0].Token != "cms-options" || rep.Gaps[0].Gain != 40 || len(rep.Gaps[0].GainExamples) == 0 {
		t.Fatalf("gaps %+v", rep.Gaps)
	}
}

// Expansion: pages with two near-certain tokens of a label join it, which
// lifts the precision of a third token they share.
func TestMineExpansion(t *testing.T) {
	c := NewCorpus()
	for i := 0; i < 100; i++ {
		c.Add(fmt.Sprint("l", i), []Token{tok(TClass, "s1"), tok(TClass, "s2"), tok(TClass, "x")}, []string{"p"})
	}
	// Two pages lost the defining signal; s1, s2 stay >= 0.98 precise.
	for i := 0; i < 2; i++ {
		c.Add(fmt.Sprint("u", i), []Token{tok(TClass, "s1"), tok(TClass, "s2"), tok(TClass, "x")}, nil)
	}
	for i := 0; i < 500; i++ {
		c.Add(fmt.Sprint("o", i), []Token{tok(TClass, "row")}, nil)
	}
	rep := c.Mine(Options{MinSupport: 5, MinPrecision: 0.999})
	found := false
	for _, cd := range rep.Candidates {
		if cd.Token == "x" {
			found = true
			if cd.ExpandedPages != 2 || cd.Precision != 1 || cd.BasePrecision >= 1 {
				t.Fatalf("expansion stats %+v", cd)
			}
		}
	}
	if !found {
		t.Fatalf("x not a candidate after expansion: %+v", rep.Candidates)
	}
}

func TestBrowserGlobalsDropped(t *testing.T) {
	if !browserGlobal["XPathResult"] || browserGlobal["jQuery"] || browserGlobal["$"] {
		t.Fatal("built-in list wrong")
	}
}
