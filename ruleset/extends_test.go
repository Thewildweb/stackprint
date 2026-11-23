package ruleset

import (
	"testing"
	"testing/fstest"
)

func TestExtendsMergesSignals(t *testing.T) {
	fsys := fstest.MapFS{
		"r/categories.yaml": {Data: []byte("- {id: cms, name: CMS}\n")},
		"r/technologies/a.yaml": {Data: []byte(`
id: acme
name: Acme
categories: [cms]
signals: [{id: gen, type: meta, key: generator, prefix: Acme}]
provenance: {method: convention}
`)},
		"r/technologies/z.yaml": {Data: []byte(`
- extends: acme
  signals: [{id: cookie, type: cookie, key: acme_session}]
  provenance: {method: mined, basis: seen with the generator}
  tests:
    - name: cookie
      page: {url: "https://example.test/", cookies: [{name: acme_session}]}
      expect: {}
`)},
	}
	set, err := Load(fsys, "r")
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Technologies) != 1 || len(set.Extensions) != 1 {
		t.Fatalf("techs %d ext %d", len(set.Technologies), len(set.Extensions))
	}
	sigs := set.Technologies[0].Signals
	if len(sigs) != 2 || sigs[1].ID != "ext-cookie" || sigs[1].Note == "" {
		t.Fatalf("signals %+v", sigs)
	}
	if len(set.Technologies[0].Tests) != 1 {
		t.Fatal("extension test not merged")
	}
	for _, e := range set.Validate() {
		t.Error(e)
	}

	fsys["r/technologies/z.yaml"] = &fstest.MapFile{Data: []byte("- extends: nope\n  signals: [{type: cookie, key: x}]\n")}
	if _, err := Load(fsys, "r"); err == nil {
		t.Fatal("unknown extends target must fail")
	}
}
