package engine

import (
	"os"
	"reflect"
	"regexp/syntax"
	"testing"

	"github.com/Thewildweb/stackprint/page"
	"github.com/Thewildweb/stackprint/ruleset"
)

// unscreenedKeyed is matchKeyed without the per-key index: every signal of an
// item's key runs on it (the engine before keyed screening).
func (s *Scanner) unscreenedKeyed(t page.SignalType, items []page.Item, site string, hits []hit) []hit {
	for _, it := range items {
		for _, id := range s.keyed[t][normKey(t, it.Key)] {
			if h, ok := s.evaluate(id, it, it.Value, site); ok {
				hits = append(hits, h)
			}
		}
	}
	return hits
}

// sampleValue builds a string a signal is likely to match: its literal, or a
// regex's shortest form with the anchors around it.
func sampleValue(c *compiledSignal) string {
	if c.re == nil {
		return "x." + c.lit
	}
	re, err := syntax.Parse(c.re.String(), syntax.Perl)
	if err != nil {
		return "x"
	}
	var b []rune
	var walk func(r *syntax.Regexp)
	walk = func(r *syntax.Regexp) {
		switch r.Op {
		case syntax.OpLiteral:
			b = append(b, r.Rune...)
		case syntax.OpConcat, syntax.OpCapture:
			for _, sub := range r.Sub {
				walk(sub)
			}
		case syntax.OpAlternate:
			walk(r.Sub[0])
		case syntax.OpPlus, syntax.OpRepeat:
			walk(r.Sub[0])
		case syntax.OpCharClass:
			if len(r.Rune) > 0 {
				b = append(b, r.Rune[0])
			}
		case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
			b = append(b, 'a')
		}
	}
	walk(re.Simplify())
	return "ns1." + string(b)
}

// TestKeyedScreeningSameHits runs every 8th keyed signal of the real rule set
// (all of them take ~35 s unscreened) on values made to match it, plus values
// that match nothing, against every signal of the key, and checks the
// screened match gives exactly the hits, in order, of evaluating every signal.
func TestKeyedScreeningSameHits(t *testing.T) {
	set, err := ruleset.Load(os.DirFS(".."), "rules")
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(set, nil)
	if err != nil {
		t.Fatal(err)
	}
	var toks page.Tokens
	toks.Site = "example.com"
	matched := 0
	for typ := page.SignalType(0); typ < page.NumSignalTypes; typ++ {
		if !typ.Keyed() {
			continue
		}
		for key, ids := range s.keyed[typ] {
			for i, id := range ids {
				if i%8 != 0 {
					continue
				}
				v := sampleValue(&s.signals[id])
				toks.Items[typ] = append(toks.Items[typ], page.Item{Key: key, Value: v})
			}
			toks.Items[typ] = append(toks.Items[typ], page.Item{Key: key, Value: "nothing-matches-this"})
		}
	}
	for typ := page.SignalType(0); typ < page.NumSignalTypes; typ++ {
		items := toks.Items[typ]
		if len(items) == 0 {
			continue
		}
		got := s.matchKeyed(typ, items, toks.Site, nil)
		want := s.unscreenedKeyed(typ, items, toks.Site, nil)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%v: screened %d hits, unscreened %d", typ, len(got), len(want))
		}
		matched += len(want)
	}
	// The sample values must exercise the screen, not only the misses.
	if matched < 500 {
		t.Fatalf("only %d keyed hits: the sample values don't match the signals", matched)
	}
	t.Logf("%d keyed hits identical", matched)
}

// TestKeyedScreeningDNS: a DNS record runs only the signals whose anchors it
// contains, and still matches a host-suffix rule.
func TestKeyedScreeningDNS(t *testing.T) {
	s := scanner(t, `
- id: acme-dns
  name: Acme DNS
  categories: [cms]
  signals:
    - {id: ns, type: dns, key: NS, regex: '(?:^|[ .])acmedns\.nl$', confidence: 100}
  provenance: {method: manual}
- id: other-dns
  name: Other DNS
  categories: [cms]
  signals:
    - {id: ns, type: dns, key: NS, regex: '(?:^|[ .])otherdns\.com$', confidence: 100}
  provenance: {method: manual}
`)
	idx := s.keyedIdx[page.SigDNS]["NS"]
	if idx == nil {
		t.Fatal("no NS index")
	}
	if c := idx.candidates([]string{"ns1.acmedns.nl"}); len(c) != 1 {
		t.Fatalf("candidates for ns1.acmedns.nl: %v, want only acme-dns", c)
	}
	res := s.Scan(&page.Document{Site: "example.nl", DNS: map[string][]string{"NS": {"ns1.acmedns.nl"}}}, Options{})
	if find(res, "acme-dns") == nil || find(res, "other-dns") != nil {
		t.Fatalf("detections: %+v", res.Detections)
	}
}
