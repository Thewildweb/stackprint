package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/Thewildweb/stackprint/discovery"
	"github.com/Thewildweb/stackprint/engine"
	"github.com/Thewildweb/stackprint/page"
)

// cmdMine scans a corpus of page documents with the current rules (the
// labels), tokenises every page and reports candidate signals per label and
// frequent unexplained tokens.
func cmdMine(args []string) error {
	fs := flag.NewFlagSet("mine", flag.ExitOnError)
	var c common
	c.register(fs, true)
	pagesFile := fs.String("pages", "", "page documents (NDJSON; default stdin)")
	out := fs.String("out", "", "write the full report as JSON here")
	md := fs.String("report", "", "write a Markdown review report here")
	corpus := fs.String("corpus", "", "corpus name recorded in the report (e.g. nl-homepages-2026-11-22)")
	minConf := fs.Int("label-confidence", 80, "minimum detection confidence for a page to carry a label")
	var o discovery.Options
	fs.IntVar(&o.MinSupport, "min-support", 10, "minimum pages per token")
	fs.Float64Var(&o.MinPrecision, "min-precision", 0.9, "minimum P(label|token)")
	fs.Float64Var(&o.MinRecall, "min-recall", 0.05, "minimum P(token|label)")
	fs.IntVar(&o.PerLabel, "per-label", 15, "candidates kept per label")
	fs.IntVar(&o.Unknown, "unknown", 200, "unexplained tokens reported")
	fs.IntVar(&o.Expand, "expand", 1, "label expansion rounds (-1 = none)")
	fs.Float64Var(&o.GapRecall, "gap-recall", 0.3, "minimum recall for a recall-gap token")
	fs.Float64Var(&o.GapLift, "gap-lift", 20, "minimum lift for a recall-gap token")
	workers := fs.Int("c", runtime.NumCPU(), "concurrent scans")
	fs.Parse(args)

	sc, _, err := c.load()
	if err != nil {
		return err
	}
	var in io.Reader = os.Stdin
	if *pagesFile != "" {
		f, err := os.Open(*pagesFile)
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
	}

	type rec struct {
		site   string
		tokens []discovery.Token
		labels []string
		exp    discovery.Explained
	}
	lines := make(chan []byte, *workers*2)
	recs := make(chan rec, *workers*2)
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for line := range lines {
				var d page.Document
				if json.Unmarshal(line, &d) != nil {
					continue
				}
				toks := page.Tokenize(&d)
				res := sc.Scan(&d, engine.Options{NoUnexplained: true})
				var labels []string
				var evidence [][4]string
				for _, det := range res.Detections {
					if det.Confidence >= *minConf && len(det.Evidence) > 0 {
						labels = append(labels, det.TechID)
					}
					for _, ev := range det.Evidence {
						evidence = append(evidence, [4]string{ev.Signal, ev.Key, ev.Value, det.TechID})
					}
				}
				site := d.Site
				if site == "" {
					site = d.BaseURL()
				}
				ptoks := discovery.PageTokens(&d, toks)
				recs <- rec{site, ptoks, labels, discovery.ExplainedSet(toks.Site, ptoks, evidence)}
			}
		}()
	}
	readErr := make(chan error, 1)
	go func() {
		s := bufio.NewScanner(in)
		s.Buffer(make([]byte, 1<<20), maxLine)
		for s.Scan() {
			lines <- append([]byte(nil), s.Bytes()...)
		}
		close(lines)
		readErr <- s.Err()
	}()
	go func() { wg.Wait(); close(recs) }()

	cp := discovery.NewCorpus()
	for r := range recs {
		cp.Add(r.site, r.tokens, r.labels, r.exp)
	}
	if err := <-readErr; err != nil {
		return err
	}
	rep := cp.Mine(o)
	fmt.Fprintf(os.Stderr, "%d pages, %d labels, %d candidates, %d recall gaps, %d unexplained tokens\n",
		rep.Pages, len(rep.Labels), len(rep.Candidates), len(rep.Gaps), len(rep.Unexplained))

	if *out != "" {
		b, _ := json.MarshalIndent(struct {
			Corpus  string `json:"corpus,omitempty"`
			Ruleset string `json:"ruleset_version"`
			*discovery.Report
		}{*corpus, sc.RulesetVersion(), rep}, "", "  ")
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			return err
		}
	}
	if *md != "" {
		if err := os.WriteFile(*md, []byte(markdownReport(rep, *corpus, sc.RulesetVersion(), o)), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func markdownReport(rep *discovery.Report, corpus, ruleset string, o discovery.Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Mining report\n\nCorpus: %s, %d pages. Ruleset %s.\n", corpus, rep.Pages, ruleset)
	fmt.Fprintf(&b, "Thresholds: support >= %d, precision >= %.2f, recall >= %.2f.\n\n", o.MinSupport, o.MinPrecision, o.MinRecall)
	b.WriteString("Labels come from the current rules; pages carrying two or more of a label's strong tokens (precision >= 0.98) are added to it before scoring. " +
		"Base precision is measured against the detection labels alone. ")
	b.WriteString("Precision is P(label | token) and recall P(token | label), both over labelled pages. " +
		"**Gain** counts pages with the token but without the label: the detections a new signal would add. " +
		"Check the gain examples before accepting a candidate.\n\n")

	b.WriteString("## Candidates per label\n\n")
	last := ""
	for _, c := range rep.Candidates {
		if c.Label != last {
			fmt.Fprintf(&b, "\n### %s (%d pages, %d added by expansion)\n\n| type | token | support | precision | base precision | recall | gain | gain examples |\n|---|---|---:|---:|---:|---:|---:|---|\n", c.Label, c.LabelPages, c.ExpandedPages)
			last = c.Label
		}
		fmt.Fprintf(&b, "| %s | `%s` | %d | %.3f | %.3f | %.3f | %d | %s |\n", c.Type, esc(c.Token), c.Support, c.Precision, c.BasePrecision, c.Recall, c.Gain, strings.Join(c.GainExamples, ", "))
	}

	b.WriteString("\n## Recall gaps\n\nTokens strongly tied to a label (lift and recall high) that also occur on pages without it. " +
		"Usually pages the current rules miss (a removed generator tag, combined assets); sometimes a shared dependency. " +
		"Decide from the gain examples.\n")
	last = ""
	for _, c := range rep.Gaps {
		if c.Label != last {
			fmt.Fprintf(&b, "\n### %s (%d pages)\n\n| type | token | support | precision | lift | recall | gain | gain examples |\n|---|---|---:|---:|---:|---:|---:|---|\n", c.Label, c.LabelPages)
			last = c.Label
		}
		fmt.Fprintf(&b, "| %s | `%s` | %d | %.3f | %.0f | %.3f | %d | %s |\n", c.Type, esc(c.Token), c.Support, c.Precision, c.Lift, c.Recall, c.Gain, strings.Join(c.GainExamples, ", "))
	}

	b.WriteString("\n## Frequent unexplained tokens\n\nTokens on many pages that no current rule matched on most of them. " +
		"Groups of co-occurring tokens usually point at one technology the rules do not know yet.\n\n" +
		"| type | token | support | best label (precision) | co-occurring | examples |\n|---|---|---:|---|---|---|\n")
	us := append([]discovery.Unexplained(nil), rep.Unexplained...)
	sort.SliceStable(us, func(i, j int) bool { return us[i].Support > us[j].Support })
	for _, u := range us {
		best := ""
		if u.BestLabel != "" {
			best = fmt.Sprintf("%s (%.2f)", u.BestLabel, u.BestPrecision)
		}
		fmt.Fprintf(&b, "| %s | `%s` | %d | %s | %s | %s |\n", u.Type, esc(u.Token), u.Support, best, esc(strings.Join(u.CoTokens, " ")), strings.Join(u.Examples, ", "))
	}
	return b.String()
}

func esc(s string) string { return strings.ReplaceAll(s, "|", `\|`) }
