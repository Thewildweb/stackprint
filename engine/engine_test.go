package engine

import (
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Thewildweb/stackprint/knowledge"
	"github.com/Thewildweb/stackprint/page"
	"github.com/Thewildweb/stackprint/ruleset"
)

const testCategories = `
- {id: cms, name: CMS}
- {id: wp-plugin, name: WP plugin}
- {id: js-library, name: Library}
`

// scanner builds a scanner from inline YAML rules and optional knowledge.
func scanner(t *testing.T, rules string, packs ...knowledge.Pack) *Scanner {
	t.Helper()
	fsys := fstest.MapFS{
		"rules/categories.yaml":     {Data: []byte(testCategories)},
		"rules/technologies/t.yaml": {Data: []byte(rules)},
	}
	set, err := ruleset.Load(fsys, "rules")
	if err != nil {
		t.Fatal(err)
	}
	var know *knowledge.Store
	if len(packs) > 0 {
		know = knowledge.NewStore(packs)
	}
	sc, err := New(set, know)
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func find(res *Result, id string) *Detection {
	for i := range res.Detections {
		if res.Detections[i].TechID == id {
			return &res.Detections[i]
		}
	}
	return nil
}

func TestRegexAnchorsSound(t *testing.T) {
	// Every string a regex matches must contain one of its anchors.
	cases := []struct {
		expr    string
		matches []string
	}{
		{`/wp-content/plugins/([a-z0-9-]+)/`, []string{"/wp-content/plugins/akismet/x.js"}},
		{`woocommerce|wc-block`, []string{"x woocommerce y", "wc-block-cart"}},
		{`(?i)Powered by Shopify`, []string{"POWERED BY SHOPIFY", "powered by shopify"}},
		{`^nginx(?:/([0-9.]+))?`, []string{"nginx", "nginx/1.24.0"}},
		{`jquery[.-]([0-9]+\.[0-9]+)(?:\.min)?\.js`, []string{"/jquery-3.6.min.js", "/jquery.3.6.js"}},
		{`(?:aspmx\.l|smtp)\.google\.com$`, []string{"aspmx.l.google.com", "smtp.google.com"}},
		{`ab?cdef`, []string{"acdef", "abcdef"}},
		{`x(abc)+y`, []string{"xabcabcy"}},
	}
	for _, c := range cases {
		re := regexp.MustCompile(c.expr)
		a, ok := regexAnchors(c.expr)
		for _, m := range c.matches {
			if !re.MatchString(m) {
				t.Fatalf("%s: test string %q does not match", c.expr, m)
			}
			if !ok {
				continue // no anchor: always evaluated, trivially sound
			}
			subject := m
			if a.fold {
				subject = lowerASCII(m)
			}
			found := false
			for _, l := range a.lits {
				if strings.Contains(subject, l) {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: match %q contains none of anchors %v", c.expr, m, a.lits)
			}
		}
	}
	// Optional parts must not become anchors.
	if a, ok := regexAnchors(`(?:foo)?barbaz`); !ok || a.lits[0] != "barbaz" {
		t.Errorf("optional group: got %+v %v", a, ok)
	}
	if _, ok := regexAnchors(`a|bc`); ok {
		t.Error("short alternation branch must disable the anchor")
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.10", "1.9", 1}, {"3.8", "3.8.0", -1}, {"3.8.0", "3.8.1", -1},
		{"1.0.beta", "1.0.0", -1}, {"10.7.0", "10.7.0", 0}, {"2", "10", -1},
	} {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%s,%s)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestQueryVersion(t *testing.T) {
	for in, want := range map[string]string{
		"/a.js?ver=1.2.3":           "1.2.3",
		"/a.js?x=1&ver=6.4":         "6.4",
		"/a.js?ver=2.7.0-wc.10.7.0": "",
		"/a.js?ver=abc":             "",
		"/a.js":                     "",
	} {
		if got := queryVersion(in, "ver"); got != want {
			t.Errorf("queryVersion(%s)=%q want %q", in, got, want)
		}
	}
}

const pluginRules = `
- id: wordpress
  name: WordPress
  categories: [cms]
  signals:
    - {type: resource_url, contains: /wp-content/}
    - {type: meta, key: generator, regex: '^WordPress ([0-9.]+)', version: '\1', version_confidence: high}
  provenance: {method: manual}
- id: wp-plugin/*
  name: 'plugin {member}'
  categories: [wp-plugin]
  member: '[a-z0-9][a-z0-9-]*'
  folder: '/wp-content/plugins/{member}/'
  implies: [wordpress]
  version_policy: {suppress_equal_to: [wordpress]}
  signals:
    - type: resource_url
      regex: '/wp-content/plugins/([a-z0-9-]+)/'
      member: '\1'
      version_query: ver
      weak_version: true
  provenance: {method: manual}
- id: npm/swiper
  name: Swiper
  categories: [js-library]
  signals:
    - {type: resource_url, regex: '/swiper(?:\.min)?\.js', version_query: ver}
  provenance: {method: manual}
`

func doc(html string) *page.Document {
	return &page.Document{URL: "https://example.test/", HTML: html}
}

func TestWeakVersionYieldsToLibrary(t *testing.T) {
	sc := scanner(t, pluginRules)
	res := sc.Scan(doc(`
		<script src="/wp-content/plugins/builder/assets/lib/swiper/swiper.min.js?ver=8.4.5"></script>
		<script src="/wp-content/plugins/builder/app.js?ver=3.20.1"></script>`), Options{})
	b := find(res, "wp-plugin/builder")
	if b == nil || b.Version != "3.20.1" {
		t.Fatalf("plugin version: %+v", b)
	}
	if s := find(res, "npm/swiper"); s == nil || s.Version != "8.4.5" {
		t.Fatalf("swiper version: %+v", s)
	}
}

func TestBoundsFromKnowledge(t *testing.T) {
	pack := knowledge.Pack{
		TechID: "wp-plugin/builder",
		Source: "test releases",
		Releases: []knowledge.Release{
			{Version: "3.1.0", Date: "2023-01-10"}, {Version: "3.2.0", Date: "2023-03-01"},
			{Version: "3.3.0", Date: "2023-06-01"}, {Version: "3.4.0", Date: "2023-09-01"},
			{Version: "3.5.0", Date: "2024-01-15"},
		},
		Files: []knowledge.FileMarker{
			{Path: "assets/js/new-widget.js", After: "3.1.0"}, // added in 3.2.0
		},
		Bundled: []knowledge.BundledLib{
			{Lib: "npm/swiper", LibVersion: "8.4.5", Min: "3.1.0", Max: "3.3.0"},
		},
	}
	sc := scanner(t, pluginRules, pack)
	d := doc(`
		<script src="/wp-content/plugins/builder/assets/lib/swiper/swiper.min.js?ver=8.4.5"></script>
		<script src="/wp-content/plugins/builder/assets/js/new-widget.js"></script>`)
	res := sc.Scan(d, Options{})
	b := find(res, "wp-plugin/builder")
	if b == nil {
		t.Fatal("not detected")
	}
	// file marker: > 3.1.0; bundled swiper 8.4.5: 3.1.0..3.3.0
	r := b.VersionRange
	if r == nil || r.Min != "3.1.0" || r.MinInclusive || r.Max != "3.3.0" || !r.MaxInclusive {
		t.Fatalf("range %+v bounds %+v", r, b.Bounds)
	}
	if b.CandidateReleases == nil || b.CandidateReleases.Count != 2 {
		t.Fatalf("candidates %+v", b.CandidateReleases)
	}
	kinds := map[string]bool{}
	for _, bn := range b.Bounds {
		kinds[bn.Kind] = true
		if bn.Evidence == nil {
			t.Errorf("bound without evidence: %+v", bn)
		}
	}
	if !kinds["file_presence"] || !kinds["bundled_version"] {
		t.Fatalf("bound kinds %v", kinds)
	}

	// A fetch date before 3.3.0 was released narrows to the single 3.2.0.
	at := time.Date(2023, 4, 1, 0, 0, 0, 0, time.UTC)
	d.FetchedAt = &at
	res = sc.Scan(d, Options{})
	b = find(res, "wp-plugin/builder")
	if b.Version != "3.2.0" || b.VersionSource != "range" {
		t.Fatalf("observed_at narrowing: version %q source %q range %+v", b.Version, b.VersionSource, b.VersionRange)
	}
}

func TestConflictingBounds(t *testing.T) {
	pack := knowledge.Pack{
		TechID: "wp-plugin/builder",
		Files: []knowledge.FileMarker{
			{Path: "new.js", After: "3.0"},
			{Path: "old.js", Before: "2.0"},
		},
	}
	sc := scanner(t, pluginRules, pack)
	res := sc.Scan(doc(`<script src="/wp-content/plugins/builder/new.js"></script><script src="/wp-content/plugins/builder/old.js"></script>`), Options{})
	b := find(res, "wp-plugin/builder")
	if !b.VersionConflict || b.VersionRange != nil || len(b.Bounds) != 2 {
		t.Fatalf("conflict not reported: %+v", b)
	}
}

func TestReleaseListDropsImpossibleVersion(t *testing.T) {
	pack := knowledge.Pack{TechID: "wp-plugin/builder", Releases: []knowledge.Release{{Version: "1.0"}, {Version: "1.1"}}}
	sc := scanner(t, pluginRules, pack)
	res := sc.Scan(doc(`<script src="/wp-content/plugins/builder/a.js?ver=9.9"></script>`), Options{})
	if b := find(res, "wp-plugin/builder"); b.Version != "" {
		t.Fatalf("impossible version kept: %q", b.Version)
	}
	res = sc.Scan(doc(`<script src="/wp-content/plugins/builder/a.js?ver=0.9"></script>`), Options{})
	if b := find(res, "wp-plugin/builder"); b.Version != "0.9" || b.VersionConfidence != "low" {
		t.Fatalf("unlisted old version: %q %q", b.Version, b.VersionConfidence)
	}
}

func TestAssetHashBound(t *testing.T) {
	pack := knowledge.Pack{TechID: "wp-plugin/builder", Hashes: []knowledge.FileHash{{SHA256: "ABCDEF", Min: "2.0", Max: "2.3"}}}
	sc := scanner(t, pluginRules, pack)
	d := doc(``)
	d.Resources = []page.Resource{{URL: "https://example.test/wp-content/plugins/builder/x.js", SHA256: "abcdef"}}
	res := sc.Scan(d, Options{})
	b := find(res, "wp-plugin/builder")
	if b == nil || b.VersionRange == nil || b.VersionRange.Min != "2.0" || b.VersionRange.Max != "2.3" {
		t.Fatalf("hash bound: %+v", b)
	}
}

func TestAssetSHA1Bound(t *testing.T) {
	pack := knowledge.Pack{TechID: "wp-plugin/builder", Hashes: []knowledge.FileHash{{SHA1: "79CD35", Min: "2.1", Max: "2.1"}}}
	sc := scanner(t, pluginRules, pack)
	d := doc(``)
	d.Resources = []page.Resource{{URL: "https://example.test/js/app.js", SHA1: "79cd35"}}
	res := sc.Scan(d, Options{})
	b := find(res, "wp-plugin/builder")
	if b == nil || b.Version != "2.1" {
		t.Fatalf("sha1 hash: %+v", b)
	}
	if ev := b.Bounds[0].Evidence; ev == nil || !strings.Contains(ev.Value, "sha1:79cd35") {
		t.Fatalf("sha1 evidence: %+v", b.Bounds)
	}
}

func TestAssetHashCopies(t *testing.T) {
	pack := knowledge.Pack{TechID: "wp-plugin/builder", Hashes: []knowledge.FileHash{
		{SHA1: "aa", Min: "1.9.0", Max: "1.9.0"}, {SHA1: "bb", Min: "3.7.1", Max: "3.7.1"}}}
	sc := scanner(t, pluginRules, pack)
	d := doc(``)
	d.Resources = []page.Resource{{URL: "https://cdn.example/bundle.js", SHA1: "aa"}, {URL: "https://example.test/jq.js", SHA1: "bb"}}
	b := find(sc.Scan(d, Options{}), "wp-plugin/builder")
	if b == nil || b.Version != "3.7.1" || b.VersionConflict || len(b.OtherVersions) != 1 || b.OtherVersions[0] != "1.9.0" {
		t.Fatalf("copies: %+v", b)
	}
}

func TestImpliesAndSuppression(t *testing.T) {
	sc := scanner(t, pluginRules)
	res := sc.Scan(doc(`<meta name="generator" content="WordPress 6.5.3"><script src="/wp-content/plugins/p/a.js?ver=6.5.3"></script>`), Options{})
	if w := find(res, "wordpress"); w == nil || w.Version != "6.5.3" {
		t.Fatalf("wordpress: %+v", w)
	}
	if p := find(res, "wp-plugin/p"); p == nil || p.Version != "" {
		t.Fatalf("core version leaked into plugin: %+v", p)
	}

	// Implied only: plugin path on a page without other WordPress markers
	// still implies WordPress.
	sc2 := scanner(t, strings.Replace(pluginRules, "    - {type: resource_url, contains: /wp-content/}\n", "", 1))
	res = sc2.Scan(doc(`<script src="/wp-content/plugins/p/a.js"></script>`), Options{})
	if w := find(res, "wordpress"); w == nil || len(w.ImpliedBy) == 0 {
		t.Fatalf("implied wordpress: %+v", w)
	}
}

func TestRequiresAndExcludes(t *testing.T) {
	sc := scanner(t, `
- id: a
  name: A
  signals: [{type: html, contains: aaa-marker}]
  provenance: {method: manual}
- id: b
  name: B
  requires: [a]
  signals: [{type: html, contains: bbb-marker}]
  provenance: {method: manual}
- id: c
  name: C
  excludes: [a]
  signals: [{type: html, contains: ccc-marker}]
  provenance: {method: manual}
`)
	res := sc.Scan(doc(`bbb-marker`), Options{})
	if find(res, "b") != nil {
		t.Error("b without its requirement")
	}
	res = sc.Scan(doc(`aaa-marker bbb-marker ccc-marker`), Options{})
	if find(res, "b") == nil || find(res, "a") != nil || find(res, "c") == nil {
		t.Errorf("relations: %+v", res.Detections)
	}
}

func TestUnexplained(t *testing.T) {
	sc := scanner(t, pluginRules)
	d := doc(`<meta name="generator" content="SomeCMS 2.0"><script src="https://widgets.vendor.example/w.js"></script><script src="/local.js"></script>`)
	d.Headers = [][2]string{{"Server", "MysteryServer"}, {"Set-Cookie", "sess_x=1; Path=/"}}
	res := sc.Scan(d, Options{})
	want := map[Token]bool{
		{Type: "meta_generator", Value: "SomeCMS 2.0"}:             true,
		{Type: "script_url_host", Value: "widgets.vendor.example"}: true,
		{Type: "header_server", Value: "MysteryServer"}:            true,
		{Type: "cookie_name", Value: "sess_x"}:                     true,
	}
	for _, tok := range res.Unexplained {
		delete(want, tok)
	}
	if len(want) > 0 {
		t.Fatalf("missing unexplained tokens %v in %v", want, res.Unexplained)
	}
}

func TestAssetScanFeedsPage(t *testing.T) {
	sc := scanner(t, pluginRules+`
- id: npm/lodash
  name: Lodash
  categories: [js-library]
  signals:
    - {type: asset_body, regex: 'lodash v?([0-9]+\.[0-9]+\.[0-9]+)', version: '\1', version_confidence: high}
  provenance: {method: manual}
`)
	ar := sc.ScanAsset(&page.Asset{SHA256: "FF00", Body: "/** @license lodash 4.17.21 */ var x;"})
	if len(ar.Findings) != 1 || ar.Findings[0].Version != "4.17.21" {
		t.Fatalf("asset findings %+v", ar.Findings)
	}
	d := doc(``)
	d.Resources = []page.Resource{{URL: "https://example.test/js/vendor.js", SHA256: "ff00"}}
	res := sc.Scan(d, Options{Assets: map[string]*AssetResult{"ff00": ar}})
	if l := find(res, "npm/lodash"); l == nil || l.Version != "4.17.21" || l.VersionConfidence != "high" {
		t.Fatalf("asset finding on page: %+v", l)
	}
}

func TestTokenizerSingleParse(t *testing.T) {
	d := &page.Document{
		URL: "https://www.example.test/shop/",
		HTML: `<html class="no-js"><head>
			<meta name="generator" content="X 1">
			<link rel="stylesheet" href="css/a.css?v=1">
			<script src="//cdn.example.org/lib.js"></script>
			<script>var cfg={"url":"https:\/\/example.test\/wp-content\/plugins\/p\/x.js"};</script>
			<!-- built by Y -->
			</head><body id="top" class="home page" data-theme="dark"><img data-src="/img/a.png"></body></html>`,
	}
	tk := page.Tokenize(d)
	vals := func(t page.SignalType) []string {
		var out []string
		for _, it := range tk.Items[t] {
			out = append(out, it.Key+"="+it.Value)
		}
		return out
	}
	check := func(typ page.SignalType, want string) {
		t.Helper()
		for _, v := range vals(typ) {
			if strings.Contains(v, want) {
				return
			}
		}
		t.Errorf("%s: %q not in %v", typ, want, vals(typ))
	}
	check(page.SigStylesheetURL, "https://www.example.test/shop/css/a.css?v=1")
	check(page.SigScriptURL, "https://cdn.example.org/lib.js")
	check(page.SigResourceURL, "https://example.test/wp-content/plugins/p/x.js")
	check(page.SigResourceURL, "https://www.example.test/img/a.png")
	check(page.SigMeta, "generator=X 1")
	check(page.SigComment, "built by Y")
	check(page.SigClass, "=home")
	check(page.SigID, "=top")
	check(page.SigDataAttr, "data-theme=dark")
	check(page.SigInlineScript, "var cfg")
}

func TestUnexplainedDropsPersonalData(t *testing.T) {
	sc := scanner(t, pluginRules)
	d := doc(`<meta name="generator" content="Site by jan@example.test">`)
	d.Headers = [][2]string{
		{"Set-Cookie", "visitor_0612345678=1"},
		{"Set-Cookie", "sess_9f86d081884c7d659a2feaa0c55ad015=1"},
		{"Set-Cookie", "plain_cookie=1"},
	}
	res := sc.Scan(d, Options{})
	for _, tok := range res.Unexplained {
		if strings.Contains(tok.Value, "@") || strings.Contains(tok.Value, "0612345678") || strings.Contains(tok.Value, "9f86d081") {
			t.Errorf("personal-looking token kept: %+v", tok)
		}
	}
	found := false
	for _, tok := range res.Unexplained {
		if tok.Value == "plain_cookie" {
			found = true
		}
	}
	if !found {
		t.Errorf("ordinary token dropped: %v", res.Unexplained)
	}
}
