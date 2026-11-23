package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/Thewildweb/stackprint/discovery"
	"github.com/Thewildweb/stackprint/engine"
	"github.com/Thewildweb/stackprint/page"
)

// cmdTokens is the streaming form of mine for corpora too large to hold in
// memory: it scans every page once and writes long-format TSV for an external
// aggregator (a database, clickhouse-local, DuckDB):
//
//	tokens: site, type, token, explained (1 = a rule matched it on this page)
//	labels: site, tech_id, version, confidence
//
// and optionally the full scan results as NDJSON. Rows are unordered.
func cmdTokens(args []string) error {
	fs := flag.NewFlagSet("tokens", flag.ExitOnError)
	var c common
	c.register(fs, true)
	pagesFile := fs.String("pages", "", "page documents (NDJSON; default stdin)")
	tokOut := fs.String("tokens-out", "", "token TSV (required)")
	labOut := fs.String("labels-out", "", "label TSV (required)")
	resOut := fs.String("results-out", "", "scan results NDJSON (optional)")
	minConf := fs.Int("label-confidence", 80, "minimum detection confidence for a label")
	workers := fs.Int("c", runtime.NumCPU(), "concurrent scans")
	fs.Parse(args)
	if *tokOut == "" || *labOut == "" {
		return fmt.Errorf("tokens: -tokens-out and -labels-out are required")
	}
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
	open := func(p string) (*bufio.Writer, func() error, error) {
		f, err := os.Create(p)
		if err != nil {
			return nil, nil, err
		}
		w := bufio.NewWriterSize(f, 1<<20)
		return w, func() error {
			if err := w.Flush(); err != nil {
				return err
			}
			return f.Close()
		}, nil
	}
	tw, tclose, err := open(*tokOut)
	if err != nil {
		return err
	}
	lw, lclose, err := open(*labOut)
	if err != nil {
		return err
	}
	var rw *bufio.Writer
	rclose := func() error { return nil }
	if *resOut != "" {
		if rw, rclose, err = open(*resOut); err != nil {
			return err
		}
	}

	type out struct{ tok, lab, res []byte }
	lines := make(chan []byte, *workers*2)
	outs := make(chan out, *workers*2)
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
				res := sc.Scan(&d, engine.Options{NoUnexplained: rw == nil})
				site := d.Site
				if site == "" {
					site = toks.Site
				}
				site = tsvField(site)
				var lab strings.Builder
				var evidence [][4]string
				for _, det := range res.Detections {
					if det.Confidence >= *minConf && len(det.Evidence) > 0 {
						fmt.Fprintf(&lab, "%s\t%s\t%s\t%d\n", site, tsvField(det.TechID), tsvField(det.Version), det.Confidence)
					}
					for _, ev := range det.Evidence {
						evidence = append(evidence, [4]string{ev.Signal, ev.Key, ev.Value, det.TechID})
					}
				}
				ptoks := discovery.PageTokens(&d, toks)
				exp := discovery.ExplainedSet(toks.Site, ptoks, evidence)
				var tok strings.Builder
				for _, t := range ptoks {
					typ, v := t.Split()
					e := 0
					if exp[t] {
						e = 1
					}
					fmt.Fprintf(&tok, "%s\t%s\t%s\t%d\n", site, typ, tsvField(v), e)
				}
				o := out{tok: []byte(tok.String()), lab: []byte(lab.String())}
				if rw != nil {
					o.res, _ = json.Marshal(res)
				}
				outs <- o
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
	go func() { wg.Wait(); close(outs) }()

	n := 0
	for o := range outs {
		tw.Write(o.tok)
		lw.Write(o.lab)
		if rw != nil {
			rw.Write(o.res)
			rw.WriteByte('\n')
		}
		n++
	}
	if err := <-readErr; err != nil {
		return err
	}
	for _, cl := range []func() error{tclose, lclose, rclose} {
		if err := cl(); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "%d pages\n", n)
	return nil
}

// tsvField makes a value safe for one TSV cell (TabSeparated escaping).
func tsvField(s string) string {
	if !strings.ContainsAny(s, "\t\n\r\\") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, "\t", `\t`, "\n", `\n`, "\r", `\r`)
	return r.Replace(s)
}
