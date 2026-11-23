package stackprint

import "testing"

func TestEmbeddedRulesValidate(t *testing.T) {
	set, err := EmbeddedRules()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range set.Validate() {
		t.Error(e)
	}
}

func TestRuleFixtures(t *testing.T) {
	sc, set, err := Load("", "")
	if err != nil {
		t.Fatal(err)
	}
	failures, n := RunTests(sc, set)
	for _, f := range failures {
		t.Error(f)
	}
	if n == 0 {
		t.Fatal("no fixtures ran")
	}
	t.Logf("%d fixtures, %d technologies", n, len(set.Technologies))
}

// go:embed skips files starting with "_" or "." unless the pattern says all:;
// the embedded rule set must be exactly the rules directory.
func TestEmbeddedMatchesDirectory(t *testing.T) {
	emb, err := EmbeddedRules()
	if err != nil {
		t.Fatal(err)
	}
	_, dir, err := Load("rules", "")
	if err != nil {
		t.Fatal(err)
	}
	if emb.Version != dir.Version {
		t.Fatalf("embedded rules %s != rules/ %s: a rule file is not embedded", emb.Version, dir.Version)
	}
}
