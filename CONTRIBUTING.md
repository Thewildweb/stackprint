# Contributing rules

## Where rules may come from

stackprint's rules are our own: every signal must be backed by an
observation we can show. Three kinds of basis are accepted, recorded in
`provenance.method`:

- `convention`: the technology documents or visibly follows a convention
  that identifies it (a generator tag it prints, the URL layout of a package
  CDN, a vendor-documented script host, a default header). `basis` says what
  the convention is.
- `mined`: the signal came out of `stackprint mine` over a named corpus and
  was confirmed on replay. Record the corpus, support, precision, recall and
  the run, and in `basis` what the replay showed.
- `manual`: observed by hand on real pages; `basis` says where and how.

Public provenance holds aggregate figures only. Lists of example sites stay
with whoever ran the mining.

## What is not allowed

Other technology detectors and their rule sets are useful to know that a
technology *exists*. They are not a source of rules:

- Do not copy regular expressions, patterns, JSON entries, descriptions,
  icons, category lists or CPE mappings from Wappalyzer, its forks
  (webappanalyzer, the HTTP Archive fork and others, GPL-3.0) or any other
  detector or commercial dataset. The last open Wappalyzer and its forks are
  GPL-3.0; the current Wappalyzer extension and service are proprietary, and
  their terms forbid reuse of their data.
- Do not run such rule sets to label a corpus for mining. Running an open
  (GPL) rule set privately to *measure* where our recall is low is fine; a
  gap found that way is a lead to investigate in our own data, not a rule.
- Facts about which technologies exist (names, vendors, websites) and public
  registries (wordpress.org, npm, cdnjs, the NVD CPE dictionary, OSV) are
  fine to use as reference data.

If a signal cannot be backed by our own observation, it does not go in.

## Keeping private data out

This repository is the generic engine, the rule set and the tooling. Anything
specific to whoever runs it stays outside: adapters for an internal crawler,
database and storage names, credentials, corpus exports, mining reports and
the example sites behind a rule's statistics. Keep those in a separate
private repository, or under `local/` (ignored by git). Rules record only
aggregate figures and a neutral corpus name such as `nl-homepages-2026-11`.

## Rule format

One YAML file holds one technology or a list of related ones under
`rules/technologies/`. Categories are in `rules/categories.yaml`.

```yaml
- id: wp-plugin/*                 # a family: one rule detects every member
  name: 'WordPress plugin {member}'
  categories: [wp-plugin]
  member: '[a-z0-9][a-z0-9._-]{0,99}'     # a member id must match this
  folder: '/wp-content/plugins/{member}/' # files the member ships (for version bounds)
  implies: [wordpress]
  requires: []
  excludes: []
  identifiers: {wporg_slug: '{member}'}   # also cpe: [...], purl: ...
  version_policy:
    suppress_equal_to: [wordpress]  # drop a non-high version equal to WordPress's
    suppress_member: 'child'        # members matching this never get a version
  signals:
    - id: path
      type: resource_url
      regex: '/wp-content/plugins/([a-zA-Z0-9][a-zA-Z0-9._-]*)/'
      member: '\1'                  # families: member id from captures
      version_query: ver            # version from a URL query parameter
      weak_version: true            # yield to another technology's version from the same URL
      version_unless: '/vendor/'    # no version from items matching this
  provenance: {method: convention, basis: ...}
  tests:
    - name: plugin path with version
      page: {url: "https://example.test/", html: '<script src="/wp-content/plugins/x/a.js?ver=1.2"></script>'}
      expect: {tech: wp-plugin/x, version: "1.2"}
```

Signal fields:

| field | meaning |
|---|---|
| `type` | `url`, `header`, `cookie`, `meta`, `html`, `script_url`, `stylesheet_url`, `resource_url`, `inline_script`, `inline_style`, `class`, `id`, `data_attr`, `comment`, `js_global`, `dns`, `tls_issuer`, `asset_body` |
| `key` | for keyed types (`header`, `cookie`, `meta`, `data_attr`, `js_global`, `dns`): the item name; the matcher then applies to the value. Without `key`, the matcher applies to item names |
| `exact` / `prefix` / `contains` / `suffix` / `regex` | one matcher; none means key presence. Regexes are RE2, unanchored; use `(?i)` for case-insensitivity |
| `ignore_case` | literal matchers ignore ASCII case |
| `first_party` | URL types only: the URL must be on the page's registrable domain |
| `confidence` | 0-100 added to the detection (default 100; sums are capped at 100) |
| `version` | template over captures: `\1`, `v\1`, `\1?yes:no` |
| `version_query` | take the version from this query parameter (plain dotted versions only) |
| `version_confidence` | `high` (the technology states its version), `medium` (default), `low` |
| `bound` | `{min, min_inclusive, max, max_inclusive}`: what a match implies about the version |

Test `expect` fields: `tech` (defaults to the rule id), `absent`,
`version`, `no_version`, `min_confidence`, `range_min`, `range_max`.

Every rule needs at least one test, including a negative one where a
signal could plausibly over-match. Run `stackprint validate` and
`stackprint test` (or `go test ./...`) before proposing a change.
