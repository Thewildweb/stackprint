# stackprint

stackprint detects the technologies a website uses, with versions where the
page gives them away: CMS, WordPress plugins and themes, JavaScript
libraries, web servers, analytics and marketing tags, mail and DNS
providers. It reads what a fetcher observed about a page (response headers,
cookies, HTML, loaded scripts and stylesheets, DNS records, optionally JS
globals and asset bodies) and reports each technology with its version,
confidence and the evidence behind it.

It is built for bulk work, from millions of crawled homepages to crawl
archives, and for joining detections to vulnerability data. Versions come
with ranges and the bounds that produced them, so a CVE join can say
*affected*, *not affected* or *possibly affected* instead of "runs plugin X".

Status: early development. The rule set is small and growing. Rules are only
added from observations in our own crawl data, reviewed with their evidence;
see [CONTRIBUTING.md](CONTRIBUTING.md).

## Quick start

```bash
go install github.com/Thewildweb/stackprint/cmd/stackprint@latest

echo '{"url":"https://example.test/","headers":[["Server","nginx/1.24.0"]],"html":"<meta name=\"generator\" content=\"WordPress 6.5.3\">"}' \
  | stackprint scan
```

```go
sc, _ := stackprint.Default()
res := sc.Scan(&page.Document{URL: u, HTML: body, Headers: hdrs}, engine.Options{})
for _, d := range res.Detections {
    fmt.Println(d.TechID, d.Version, d.Confidence)
}
```

## Input: one document per page

A page document is JSON, independent of who fetched the page (an HTTP
client, a headless browser, a WARC reader). Every field except `url` is
optional; `observed` lists the signal groups the fetcher actually collected,
so a missing group means "not observed" rather than "none found".

```json
{
  "url": "https://example.test/",
  "final_url": "https://www.example.test/",
  "site": "example.test",
  "fetched_at": "2026-11-22T10:00:00Z",
  "fetcher": {"name": "my-crawler", "kind": "http"},
  "status": 200,
  "headers": [["Server", "nginx"], ["Set-Cookie", "a=1; Path=/"]],
  "cookies": [{"name": "a", "value": "1"}],
  "html": "<!doctype html>...",
  "html_truncated": false,
  "resources": [{"url": "https://cdn.example.test/app.js", "kind": "script", "sha256": "..."}],
  "js_globals": {"jQuery.fn.jquery": "3.7.1"},
  "dns": {"MX": ["10 mx.example.test"], "NS": ["ns1.example.net"], "TXT": ["v=spf1 ..."]},
  "tls": {"issuer": "C=US, O=Let's Encrypt, CN=R11"},
  "observed": ["headers", "cookies", "html", "dns", "tls"]
}
```

The engine parses the HTML once and derives everything else from it: script
and stylesheet URLs, every referenced URL (including those inside inline
code), meta tags, class names, ids, data-* attributes, comments and inline
scripts. `fetched_at` lets the engine rule out releases published after the
fetch, which matters for archived crawls.

Asset bodies (JS and CSS files) are scanned separately with
`stackprint scan-assets` and cached by SHA-256. Pass the results to page
scans with `-assets`; findings in a file are attributed to the URL the page
loaded it from.

## Output: detections with evidence

```json
{
  "tech_id": "wp-plugin/woocommerce",
  "name": "WooCommerce",
  "categories": ["ecommerce", "wp-plugin"],
  "identifiers": {"cpe": ["cpe:2.3:a:woocommerce:woocommerce"], "wporg_slug": "woocommerce"},
  "confidence": 100,
  "version": "10.7.0",
  "version_confidence": "high",
  "version_source": "wp-plugin/woocommerce#generator",
  "version_range": {"min": "10.6.0", "min_inclusive": true, "max": "10.7.2", "max_inclusive": true},
  "candidate_releases": {"count": 4, "first": "10.6.0", "last": "10.7.2"},
  "bounds": [{"kind": "file_presence", "min": "10.5.3", "evidence": {"...": "..."}}],
  "evidence": [{"signal": "meta", "rule_id": "wp-plugin/woocommerce#generator", "key": "generator", "value": "WooCommerce 10.7.0"}]
}
```

- `tech_id` is a stable id. Families cover open-ended sets with one rule:
  `wp-plugin/<slug>`, `wp-theme/<slug>`, `npm/<package>`, `cdnjs/<library>`.
  Every plugin in `/wp-content/plugins/<slug>/` is detected without a rule
  of its own; member rules add markers and version hints.
- `identifiers` link to CPE (NVD), package URLs (OSV) and wordpress.org
  slugs, for vulnerability joins.
- `unexplained` (per page) lists observations no rule accounts for:
  third-party script hosts, generator strings, server headers, cookie names.
  They feed rule discovery.

## Versions and bounds

A point version comes from the strongest signal (a generator tag or banner
over a `?ver=` query string), with the version most items agree on winning
ties. Clean-up mirrors how WordPress sites actually behave: a plugin asset
carrying the core version is not the plugin's version, a library bundled in
a plugin folder carries the library's version, and a child theme's version is
its own counter.

With release knowledge loaded (`-knowledge dir`, JSON packs per technology)
signals also bound the version:

| bound | from |
|---|---|
| `file_presence` | a loaded file exists only in some releases |
| `bundled_version` | a library loaded from the technology's own folder is at a version only some releases ship |
| `asset_hash` | a loaded file's hash (`sha256` or `sha1` of the decoded body) matches a file only some releases ship |
| `observed_at` | releases published after the fetch date are impossible |
| `signal` | a rule states a bound directly |

Bounds are intersected into `version_range` and snapped to the release
list (`candidate_releases`). A point version outside the range is replaced
or dropped; contradicting bounds are reported as `version_conflict` with all
bounds kept, never resolved silently. One exception: when exact file hashes
name several versions, the page loads several copies (a plugin bundling its
own jQuery next to the site's). The detection then gives one `version` and
lists the rest in `other_versions`; every copy is really loaded.

## Rules

Rules live in `rules/` as YAML, one technology (or family) per entry, each
with signals, provenance and test fixtures:

```yaml
- id: wordpress
  name: WordPress
  categories: [cms]
  identifiers: {cpe: ["cpe:2.3:a:wordpress:wordpress"]}
  signals:
    - id: generator
      type: meta
      key: generator
      regex: '^WordPress(?: ([0-9][0-9.]*))?'
      version: '\1'
      version_confidence: high
  provenance:
    method: convention
    basis: WordPress prints a generator meta tag unless removed.
  tests:
    - name: generator
      page: {url: "https://example.test/", html: '<meta name="generator" content="WordPress 6.4.2">'}
      expect: {version: 6.4.2}
```

Signal types: `url`, `header`, `cookie`, `meta`, `html`, `script_url`,
`stylesheet_url`, `resource_url`, `inline_script`, `inline_style`, `class`,
`id`, `data_attr`, `comment`, `js_global`, `dns`, `tls_issuer`, `asset_body`.
Matchers: `exact`, `prefix`, `contains`, `suffix`, `regex` (RE2), or key
presence for keyed types. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full
format.

```bash
stackprint validate        # structural checks
stackprint test            # run every rule's fixtures
```

## Discovering rules

`stackprint mine` scans a corpus of page documents with the current rules,
labels each page with what they detect, breaks every page into normalised
tokens and reports:

- **candidates**: tokens that occur (almost) only on pages with a label, per
  label, with precision, recall and the pages they would newly match;
- **recall gaps**: tokens strongly tied to a label (high lift and recall)
  that also occur on many unlabelled pages, usually the pages the current
  rules miss;
- **unexplained tokens**: frequent tokens no label predicts, grouped with
  the tokens they co-occur with, leads for technologies not in the rules.

```bash
stackprint mine -pages corpus.ndjson -corpus nl-homepages-2026-11 -report report.md -out report.json
```

A candidate becomes a rule only after review: replay the corpus with the
new signal, check the pages it adds, record the statistics as provenance.

## Speed

Every signal contributes literal anchors; each signal type gets one
Aho-Corasick pass per page and only signals whose anchor occurs run their
full matcher, so scan time grows with page size, not rule count. A scanner
is immutable and safe for concurrent use. On a 20,000-page corpus of real
homepages (bodies up to 1 MiB) the CLI scans about 1,400 pages per second
on 12 cores including JSON decoding, with a median of 2.6 ms per page.

## Layout

```
page/        input contract, single-parse tokeniser
ruleset/     rule format, loader, validation
engine/      compile, match, versions and bounds, relations, assets
knowledge/   release knowledge packs
discovery/   tokens and miner for rule discovery
rules/       the rule set (embedded into the binary)
cmd/stackprint/  CLI
python/      Python client (subprocess)
```

## Licence

MIT, see [LICENSE](LICENSE). The rules are covered by the same licence.
