// Package stackprint detects the technologies a website uses (CMS, plugins,
// themes, libraries, servers, services) and their versions, from the
// observable datapoints of a fetched page: DNS records, response headers and
// cookies, the HTML, the scripts and stylesheets it loads, and optionally JS
// globals and asset bodies.
//
// The rule set ships inside the package (rules/), so a binary's detection
// behaviour is pinned by its build. Use Default for that set, or Load for a
// rule directory on disk.
package stackprint

import (
	"embed"
	"fmt"
	"os"
	"sync"

	"github.com/Thewildweb/stackprint/engine"
	"github.com/Thewildweb/stackprint/knowledge"
	"github.com/Thewildweb/stackprint/ruleset"
)

//go:embed all:rules
var embedded embed.FS

var (
	defaultOnce    sync.Once
	defaultScanner *engine.Scanner
	defaultSet     *ruleset.Set
	defaultErr     error
)

// EmbeddedRules returns the rule set compiled into this package.
func EmbeddedRules() (*ruleset.Set, error) {
	return ruleset.Load(embedded, "rules")
}

// Default returns a scanner over the embedded rules without release
// knowledge. It is built once and shared.
func Default() (*engine.Scanner, error) {
	defaultOnce.Do(func() {
		defaultSet, defaultErr = EmbeddedRules()
		if defaultErr == nil {
			defaultScanner, defaultErr = engine.New(defaultSet, nil)
		}
	})
	return defaultScanner, defaultErr
}

// Load builds a scanner from a rule directory (empty = embedded rules) and
// an optional knowledge directory.
func Load(rulesDir, knowledgeDir string) (*engine.Scanner, *ruleset.Set, error) {
	var set *ruleset.Set
	var err error
	if rulesDir == "" {
		set, err = EmbeddedRules()
	} else {
		set, err = ruleset.Load(os.DirFS(rulesDir), ".")
	}
	if err != nil {
		return nil, nil, fmt.Errorf("rules: %w", err)
	}
	var know *knowledge.Store
	if knowledgeDir != "" {
		know, err = knowledge.Load(os.DirFS(knowledgeDir), ".")
		if err != nil {
			return nil, nil, fmt.Errorf("knowledge: %w", err)
		}
	}
	sc, err := engine.New(set, know)
	if err != nil {
		return nil, nil, err
	}
	return sc, set, nil
}

// TestFailure is a rule fixture that did not produce what it expects.
type TestFailure struct {
	Tech, File, Test, Problem string
}

func (f TestFailure) String() string {
	return fmt.Sprintf("%s (%s) %q: %s", f.Tech, f.File, f.Test, f.Problem)
}

// RunTests runs every rule's fixtures against sc and returns the failures
// and the number of fixtures run.
func RunTests(sc *engine.Scanner, set *ruleset.Set) (failures []TestFailure, n int) {
	for _, t := range set.Technologies {
		for _, tc := range t.Tests {
			n++
			doc := tc.Page
			res := sc.Scan(&doc, engine.Options{NoUnexplained: true})
			want := tc.Expect.Tech
			if want == "" {
				want = t.ID
			}
			fail := func(format string, a ...any) {
				failures = append(failures, TestFailure{Tech: t.ID, File: t.File, Test: tc.Name, Problem: fmt.Sprintf(format, a...)})
			}
			if res.Error != "" {
				fail("scan error: %s", res.Error)
				continue
			}
			var got *engine.Detection
			for i := range res.Detections {
				if res.Detections[i].TechID == want {
					got = &res.Detections[i]
				}
			}
			e := tc.Expect
			switch {
			case e.Absent && got != nil:
				fail("%s detected, expected absent", want)
			case e.Absent:
			case got == nil:
				fail("%s not detected", want)
			default:
				if e.Version != "" && got.Version != e.Version {
					fail("version %q, want %q", got.Version, e.Version)
				}
				if e.NoVersion && got.Version != "" {
					fail("version %q, want none", got.Version)
				}
				if e.MinConfidence > 0 && got.Confidence < e.MinConfidence {
					fail("confidence %d, want >= %d", got.Confidence, e.MinConfidence)
				}
				if e.MaxConfidence > 0 && got.Confidence > e.MaxConfidence {
					fail("confidence %d, want <= %d", got.Confidence, e.MaxConfidence)
				}
				if e.RangeMin != "" || e.RangeMax != "" {
					r := got.VersionRange
					if r == nil || r.Min != e.RangeMin || r.Max != e.RangeMax {
						fail("range %+v, want min %q max %q", r, e.RangeMin, e.RangeMax)
					}
				}
			}
		}
	}
	return failures, n
}
