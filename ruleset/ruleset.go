// Package ruleset defines the stackprint rule format and loads rule sets.
//
// A rule set is a directory with a categories.yaml and one YAML file per
// technology under technologies/ (any depth). A technology file holds one
// technology, or a YAML list of technologies that belong together (for
// example a family and its first members).
package ruleset

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/Thewildweb/stackprint/page"
	"go.yaml.in/yaml/v3"
)

// Technology is one detectable technology, or a family of them.
//
// A family has an id ending in "/*" (for example "wp-plugin/*"). Its signals
// carry a Member template that names the member from the match (the plugin
// slug), so one family rule detects every member without a rule per member.
// A member rule ("wp-plugin/woocommerce") adds signals and metadata to one
// member and inherits the family's folder, categories and relations.
type Technology struct {
	ID string `yaml:"id"`

	// Extends names an existing technology this entry only adds signals (and
	// tests) to, instead of defining a new one. Generated rule files use it so
	// curated rules stay untouched. An extension has no id or metadata of its
	// own; it keeps its provenance.
	Extends string `yaml:"extends,omitempty"`

	Name        string      `yaml:"name"`
	Vendor      string      `yaml:"vendor,omitempty"`
	Website     string      `yaml:"website,omitempty"`
	Categories  []string    `yaml:"categories,omitempty"`
	Identifiers Identifiers `yaml:"identifiers,omitempty"`
	Status      string      `yaml:"status,omitempty"` // active (default) | deprecated
	Description string      `yaml:"description,omitempty"`

	Implies  []string `yaml:"implies,omitempty"`
	Requires []string `yaml:"requires,omitempty"`
	Excludes []string `yaml:"excludes,omitempty"`

	// Member is the regular expression a family member id must fully match
	// (families only), e.g. "[a-z0-9][a-z0-9_.-]*".
	Member string `yaml:"member,omitempty"`

	// Folder is a regular expression matching the URL path prefix of files
	// this technology ships (for a family, "{member}" stands for the member
	// id), e.g. "/wp-content/plugins/{member}/". It attributes loaded files
	// to their owner for version bounds.
	Folder string `yaml:"folder,omitempty"`

	Version VersionPolicy `yaml:"version_policy,omitempty"`

	Signals    []Signal   `yaml:"signals,omitempty"`
	Provenance Provenance `yaml:"provenance,omitempty"`
	Tests      []Test     `yaml:"tests,omitempty"`

	// File is the rule file this technology was loaded from.
	File string `yaml:"-"`
}

// Identifiers link a technology to external catalogues (CVE joins, package
// registries). Templates may use "{member}" in a family.
type Identifiers struct {
	CPE       []string `yaml:"cpe,omitempty" json:"cpe,omitempty"`               // cpe:2.3:a:<vendor>:<product>
	PURL      string   `yaml:"purl,omitempty" json:"purl,omitempty"`             // pkg:npm/jquery
	WPOrgSlug string   `yaml:"wporg_slug,omitempty" json:"wporg_slug,omitempty"` // wordpress.org plugin/theme slug
}

// IsZero reports whether no identifier is set.
func (i Identifiers) IsZero() bool {
	return len(i.CPE) == 0 && i.PURL == "" && i.WPOrgSlug == ""
}

// Expand substitutes "{member}" in every identifier.
func (i Identifiers) Expand(member string) Identifiers {
	r := strings.NewReplacer("{member}", member)
	out := Identifiers{PURL: r.Replace(i.PURL), WPOrgSlug: r.Replace(i.WPOrgSlug)}
	for _, c := range i.CPE {
		out.CPE = append(out.CPE, r.Replace(c))
	}
	return out
}

// VersionPolicy holds version clean-up rules for a technology.
type VersionPolicy struct {
	// SuppressEqualTo drops a non-high version candidate equal to the
	// detected version of any listed technology (a plugin asset carrying the
	// WordPress core version as cache buster).
	SuppressEqualTo []string `yaml:"suppress_equal_to,omitempty"`

	// SuppressMember drops every version of a family member whose id matches
	// this regular expression (child themes carry the child's own version
	// counter, not the parent's).
	SuppressMember string `yaml:"suppress_member,omitempty"`
}

// Signal is one way to observe a technology.
type Signal struct {
	ID   string `yaml:"id,omitempty"`
	Type string `yaml:"type"`

	// Key selects items by name for keyed types (header, cookie, meta,
	// data_attr, js_global, dns); the match then applies to the value. With
	// no Key, the match applies to the item name for keyed types.
	Key string `yaml:"key,omitempty"`

	// Exactly one matcher, or none (Key presence alone).
	Exact    string `yaml:"exact,omitempty"`
	Prefix   string `yaml:"prefix,omitempty"`
	Contains string `yaml:"contains,omitempty"`
	Suffix   string `yaml:"suffix,omitempty"`
	Regex    string `yaml:"regex,omitempty"`

	// IgnoreCase makes literal matchers case-insensitive. Regexes use (?i).
	IgnoreCase bool `yaml:"ignore_case,omitempty"`

	// FirstParty restricts a URL signal to URLs on the page's own registrable
	// domain (files hotlinked from other sites say nothing about this one).
	FirstParty bool `yaml:"first_party,omitempty"`

	// Member names the family member from regex captures ("\1"). Required on
	// family signals.
	Member string `yaml:"member,omitempty"`

	// Version is a template over regex captures ("\1", "\1?a:b"); VersionQuery
	// takes the version from a URL query parameter instead ("ver").
	Version           string `yaml:"version,omitempty"`
	VersionQuery      string `yaml:"version_query,omitempty"`
	VersionConfidence string `yaml:"version_confidence,omitempty"` // high | medium (default) | low

	// VersionUnless is a regular expression: when the matched item matches
	// it, the signal still detects but gives no version (paths inside a
	// vendored library folder carry the library's version).
	VersionUnless string `yaml:"version_unless,omitempty"`

	// WeakVersion drops this signal's version when the same item also gave a
	// version to another technology (a bundled library's URL inside a plugin
	// folder carries the library's version, not the plugin's).
	WeakVersion bool `yaml:"weak_version,omitempty"`

	// Confidence this signal adds to the detection (0-100, default 100).
	Confidence *int `yaml:"confidence,omitempty"`

	// Bound states what a match implies about the installed version.
	Bound *Bound `yaml:"bound,omitempty"`

	Note string `yaml:"note,omitempty"`
}

// Bound is a version interval; empty ends are open.
type Bound struct {
	Min          string `yaml:"min,omitempty" json:"min,omitempty"`
	MinInclusive bool   `yaml:"min_inclusive,omitempty" json:"min_inclusive,omitempty"`
	Max          string `yaml:"max,omitempty" json:"max,omitempty"`
	MaxInclusive bool   `yaml:"max_inclusive,omitempty" json:"max_inclusive,omitempty"`
}

// Provenance records where a rule came from. Public rules carry aggregate
// evidence only (counts and rates over a named corpus), never site lists.
type Provenance struct {
	Method      string  `yaml:"method,omitempty"` // convention | mined | manual
	Basis       string  `yaml:"basis,omitempty"`  // why the signal identifies the technology
	Corpus      string  `yaml:"corpus,omitempty"` // corpus id and date the stats come from
	Support     int     `yaml:"support,omitempty"`
	Precision   float64 `yaml:"precision,omitempty"`
	Recall      float64 `yaml:"recall,omitempty"`
	ReviewedBy  string  `yaml:"reviewed_by,omitempty"`
	ReviewedAt  string  `yaml:"reviewed_at,omitempty"`
	MinedRun    string  `yaml:"mined_run,omitempty"`
	Description string  `yaml:"notes,omitempty"`
}

// Test is a rule fixture: a synthetic page and what must (not) be detected.
type Test struct {
	Name   string        `yaml:"name"`
	Page   page.Document `yaml:"page"`
	Expect Expect        `yaml:"expect"`
}

// Expect describes the expected detection for a Test. Tech defaults to the
// rule's own id (for a family, set it to a member id).
type Expect struct {
	Tech          string `yaml:"tech,omitempty"`
	Absent        bool   `yaml:"absent,omitempty"`
	Version       string `yaml:"version,omitempty"`
	NoVersion     bool   `yaml:"no_version,omitempty"`
	MinConfidence int    `yaml:"min_confidence,omitempty"`
	MaxConfidence int    `yaml:"max_confidence,omitempty"` // a weak signal alone stays weak
	RangeMin      string `yaml:"range_min,omitempty"`
	RangeMax      string `yaml:"range_max,omitempty"`
}

// Category is one entry of categories.yaml.
type Category struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`
}

// Set is a loaded rule set.
type Set struct {
	Categories   []Category
	Technologies []Technology
	// Extensions are the entries with Extends, already merged into
	// Technologies by Load; kept for reporting.
	Extensions []Technology
	// Version identifies the exact rule content: "sha256:<12 hex>" over every
	// loaded file, so two scanners report the same version only when they
	// run the same rules.
	Version string
}

// Load reads a rule set from fsys rooted at dir.
func Load(fsys fs.FS, dir string) (*Set, error) {
	set := &Set{}
	h := sha256.New()

	var files []string
	err := fs.WalkDir(fsys, dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !e.IsDir() && (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	for _, p := range files {
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil, err
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(p, dir), "/")
		h.Write([]byte(rel))
		h.Write([]byte{0})
		h.Write(data)
		h.Write([]byte{0})

		if path.Base(p) == "categories.yaml" {
			var cats []Category
			if err := yaml.Unmarshal(data, &cats); err != nil {
				return nil, fmt.Errorf("%s: %w", rel, err)
			}
			set.Categories = append(set.Categories, cats...)
			continue
		}
		techs, err := parseTechFile(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", rel, err)
		}
		for i := range techs {
			techs[i].File = rel
			if techs[i].Extends != "" {
				set.Extensions = append(set.Extensions, techs[i])
			} else {
				set.Technologies = append(set.Technologies, techs[i])
			}
		}
	}
	set.Version = "sha256:" + hex.EncodeToString(h.Sum(nil))[:12]
	if err := set.applyExtensions(); err != nil {
		return nil, err
	}
	return set, nil
}

// applyExtensions merges extension entries into their targets: signals get
// an "ext-" id prefix (so rule ids stay unique and show where they came from)
// and tests default to the target technology.
func (s *Set) applyExtensions() error {
	byID := map[string]int{}
	for i, t := range s.Technologies {
		byID[t.ID] = i
	}
	for _, e := range s.Extensions {
		i, ok := byID[e.Extends]
		if !ok {
			return fmt.Errorf("%s: extends unknown technology %q", e.File, e.Extends)
		}
		if e.ID != "" || e.Name != "" || len(e.Categories) > 0 || e.Member != "" || e.Folder != "" {
			return fmt.Errorf("%s: extension of %q may only carry signals, provenance and tests", e.File, e.Extends)
		}
		t := &s.Technologies[i]
		for j, sg := range e.Signals {
			if sg.ID == "" {
				sg.ID = fmt.Sprint(j)
			}
			sg.ID = "ext-" + sg.ID
			if sg.Note == "" && e.Provenance.Basis != "" {
				sg.Note = "extension (" + e.Provenance.Method + "): " + e.Provenance.Basis
			}
			t.Signals = append(t.Signals, sg)
		}
		for _, tc := range e.Tests {
			t.Tests = append(t.Tests, tc)
		}
	}
	return nil
}

// parseTechFile accepts a single technology mapping or a list of them.
func parseTechFile(data []byte) ([]Technology, error) {
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, err
	}
	if len(node.Content) == 0 {
		return nil, nil
	}
	root := node.Content[0]
	var techs []Technology
	if root.Kind == yaml.SequenceNode {
		if err := root.Decode(&techs); err != nil {
			return nil, err
		}
		return techs, nil
	}
	var t Technology
	if err := root.Decode(&t); err != nil {
		return nil, err
	}
	return []Technology{t}, nil
}

// IsFamily reports whether the technology is a family ("prefix/*").
func (t *Technology) IsFamily() bool { return strings.HasSuffix(t.ID, "/*") }

// FamilyPrefix returns "wp-plugin/" for "wp-plugin/*" and "" otherwise.
func (t *Technology) FamilyPrefix() string {
	if !t.IsFamily() {
		return ""
	}
	return strings.TrimSuffix(t.ID, "*")
}

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.@+-]*(/([a-z0-9@][a-z0-9_.@+-]*|\*))*$`)

// Validate checks the set for structural errors: unknown categories,
// duplicate ids, bad signal definitions and dangling relations. It returns
// every problem found.
func (s *Set) Validate() []error {
	var errs []error
	cats := map[string]bool{}
	for _, c := range s.Categories {
		cats[c.ID] = true
	}
	ids := map[string]string{}
	families := map[string]bool{}
	for _, t := range s.Technologies {
		if t.IsFamily() {
			families[t.FamilyPrefix()] = true
		}
	}
	for i := range s.Technologies {
		t := &s.Technologies[i]
		where := fmt.Sprintf("%s (%s)", t.ID, t.File)
		if !idRe.MatchString(t.ID) {
			errs = append(errs, fmt.Errorf("%s: invalid id", where))
		}
		if prev, dup := ids[t.ID]; dup {
			errs = append(errs, fmt.Errorf("%s: duplicate id, also in %s", where, prev))
		}
		ids[t.ID] = t.File
		if t.Name == "" && !isMemberOf(t.ID, families) {
			errs = append(errs, fmt.Errorf("%s: missing name", where))
		}
		for _, c := range t.Categories {
			if !cats[c] {
				errs = append(errs, fmt.Errorf("%s: unknown category %q", where, c))
			}
		}
		if t.IsFamily() {
			if t.Member == "" {
				errs = append(errs, fmt.Errorf("%s: family without member pattern", where))
			} else if _, err := regexp.Compile("^(?:" + t.Member + ")$"); err != nil {
				errs = append(errs, fmt.Errorf("%s: member pattern: %v", where, err))
			}
		}
		if t.Version.SuppressMember != "" {
			if _, err := regexp.Compile(t.Version.SuppressMember); err != nil {
				errs = append(errs, fmt.Errorf("%s: suppress_member: %v", where, err))
			}
		}
		if t.Provenance.Method == "" {
			errs = append(errs, fmt.Errorf("%s: provenance.method missing", where))
		}
		for j := range t.Signals {
			for _, e := range validateSignal(t, &t.Signals[j]) {
				errs = append(errs, fmt.Errorf("%s: signal %d: %v", where, j, e))
			}
		}
	}
	for _, t := range s.Technologies {
		for _, rel := range [][]string{t.Implies, t.Requires, t.Excludes} {
			for _, r := range rel {
				if _, ok := ids[r]; !ok && !isMemberOf(r, families) {
					errs = append(errs, fmt.Errorf("%s: relation to unknown technology %q", t.ID, r))
				}
			}
		}
		for _, r := range t.Version.SuppressEqualTo {
			if _, ok := ids[r]; !ok {
				errs = append(errs, fmt.Errorf("%s: suppress_equal_to unknown technology %q", t.ID, r))
			}
		}
	}
	return errs
}

func isMemberOf(id string, families map[string]bool) bool {
	for i := 0; i < len(id); i++ {
		if id[i] == '/' && families[id[:i+1]] {
			return true
		}
	}
	return false
}

func validateSignal(t *Technology, sg *Signal) []error {
	var errs []error
	typ, ok := page.ParseSignalType(sg.Type)
	if !ok {
		return []error{fmt.Errorf("unknown type %q", sg.Type)}
	}
	n := 0
	for _, m := range []string{sg.Exact, sg.Prefix, sg.Contains, sg.Suffix, sg.Regex} {
		if m != "" {
			n++
		}
	}
	if n > 1 {
		errs = append(errs, fmt.Errorf("more than one matcher"))
	}
	if n == 0 && (sg.Key == "" || !typ.Keyed()) {
		errs = append(errs, fmt.Errorf("no matcher (only a keyed type with key may omit it)"))
	}
	if sg.FirstParty && !typ.IsURL() {
		errs = append(errs, fmt.Errorf("first_party on non-URL type %s", sg.Type))
	}
	if sg.Key != "" && !typ.Keyed() {
		errs = append(errs, fmt.Errorf("key on non-keyed type %s", sg.Type))
	}
	for name, expr := range map[string]string{"regex": sg.Regex, "version_unless": sg.VersionUnless} {
		if expr == "" {
			continue
		}
		if _, err := regexp.Compile(expr); err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", name, err))
		}
	}
	if sg.Version != "" && sg.VersionQuery != "" {
		errs = append(errs, fmt.Errorf("both version and version_query"))
	}
	if t.IsFamily() && sg.Member == "" {
		errs = append(errs, fmt.Errorf("family signal without member"))
	}
	if !t.IsFamily() && sg.Member != "" {
		errs = append(errs, fmt.Errorf("member on a non-family technology"))
	}
	if (strings.Contains(sg.Version, `\`) || strings.Contains(sg.Member, `\`)) && sg.Regex == "" {
		errs = append(errs, fmt.Errorf("capture reference without regex"))
	}
	switch sg.VersionConfidence {
	case "", "high", "medium", "low":
	default:
		errs = append(errs, fmt.Errorf("version_confidence %q", sg.VersionConfidence))
	}
	if sg.Confidence != nil && (*sg.Confidence < 0 || *sg.Confidence > 100) {
		errs = append(errs, fmt.Errorf("confidence out of range"))
	}
	return errs
}
