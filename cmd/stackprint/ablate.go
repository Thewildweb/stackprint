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

	"github.com/Thewildweb/stackprint/engine"
	"github.com/Thewildweb/stackprint/page"
)

// groups a fetcher can capture, and how to remove each from a document.
var ablateGroups = []struct {
	name   string
	remove func(d *page.Document)
}{
	{"headers", func(d *page.Document) { d.Headers = keepSetCookie(d.Headers) }},
	{"cookies", func(d *page.Document) { d.Cookies = nil; d.Headers = dropSetCookie(d.Headers) }},
	{"html", func(d *page.Document) { d.HTML = "" }},
	{"resources", func(d *page.Document) { d.Resources = nil }},
	{"resource_headers", func(d *page.Document) {
		rs := make([]page.Resource, len(d.Resources))
		copy(rs, d.Resources)
		for i := range rs {
			rs[i].Headers = nil
		}
		d.Resources = rs
	}},
	{"js_globals", func(d *page.Document) { d.JSGlobals = nil }},
	{"storage", func(d *page.Document) { d.Storage = nil }},
	{"dns", func(d *page.Document) { d.DNS = nil }},
	{"tls", func(d *page.Document) { d.TLS = nil }},
}

func keepSetCookie(h [][2]string) [][2]string {
	var out [][2]string
	for _, x := range h {
		if strings.EqualFold(x[0], "set-cookie") {
			out = append(out, x)
		}
	}
	return out
}

func dropSetCookie(h [][2]string) [][2]string {
	var out [][2]string
	for _, x := range h {
		if !strings.EqualFold(x[0], "set-cookie") {
			out = append(out, x)
		}
	}
	return out
}

type ablateStats struct {
	detLost  int
	verLost  int
	techLost map[string]int
	verTech  map[string]int
}

// cmdAblate measures what each signal group contributes: for every page, the
// detections (and versions) that disappear when that group alone is removed.
func cmdAblate(args []string) error {
	fs := flag.NewFlagSet("ablate", flag.ExitOnError)
	var c common
	c.register(fs, true)
	pagesFile := fs.String("pages", "", "page documents (NDJSON; default stdin)")
	minConf := fs.Int("min-confidence", 50, "count detections at or above this confidence")
	top := fs.Int("top", 12, "technologies listed per group")
	workers := fs.Int("c", runtime.NumCPU(), "concurrent pages")
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

	type pageOut struct {
		total, versioned int
		lost             [][]string // per group: tech ids lost
		verLost          [][]string
	}
	detect := func(d *page.Document) map[string]string {
		res := sc.Scan(d, engine.Options{MinConfidence: *minConf, NoUnexplained: true})
		m := map[string]string{}
		for _, det := range res.Detections {
			m[det.TechID] = det.Version
		}
		return m
	}

	lines := make(chan []byte, *workers*2)
	outs := make(chan pageOut, *workers*2)
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
				base := detect(&d)
				po := pageOut{total: len(base), lost: make([][]string, len(ablateGroups)), verLost: make([][]string, len(ablateGroups))}
				for _, v := range base {
					if v != "" {
						po.versioned++
					}
				}
				for gi, g := range ablateGroups {
					cp := d
					g.remove(&cp)
					got := detect(&cp)
					for id, v := range base {
						gv, ok := got[id]
						if !ok {
							po.lost[gi] = append(po.lost[gi], id)
						} else if v != "" && gv == "" {
							po.verLost[gi] = append(po.verLost[gi], id)
						}
					}
				}
				outs <- po
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

	stats := make([]ablateStats, len(ablateGroups))
	for i := range stats {
		stats[i] = ablateStats{techLost: map[string]int{}, verTech: map[string]int{}}
	}
	pages, total, versioned := 0, 0, 0
	for po := range outs {
		pages++
		total += po.total
		versioned += po.versioned
		for gi := range ablateGroups {
			stats[gi].detLost += len(po.lost[gi])
			stats[gi].verLost += len(po.verLost[gi])
			for _, id := range po.lost[gi] {
				stats[gi].techLost[familyKey(id)]++
			}
			for _, id := range po.verLost[gi] {
				stats[gi].verTech[familyKey(id)]++
			}
		}
	}
	if err := <-readErr; err != nil {
		return err
	}

	fmt.Printf("# Signal-group ablation\n\n%d pages, %d detections (confidence >= %d), %d with a version. Ruleset %s.\n\n",
		pages, total, *minConf, versioned, sc.RulesetVersion())
	fmt.Println("A detection or version counts for a group when removing that group alone makes it disappear.")
	fmt.Println()
	fmt.Println("| group | detections only via group | % of detections | versions only via group | % of versions |")
	fmt.Println("|---|---:|---:|---:|---:|")
	for gi, g := range ablateGroups {
		st := stats[gi]
		fmt.Printf("| %s | %d | %.1f | %d | %.1f |\n", g.name, st.detLost, pct(st.detLost, total), st.verLost, pct(st.verLost, versioned))
	}
	for gi, g := range ablateGroups {
		st := stats[gi]
		if st.detLost == 0 && st.verLost == 0 {
			continue
		}
		fmt.Printf("\n## %s\n\ndetections: %s\n\nversions: %s\n", g.name, topList(st.techLost, *top), topList(st.verTech, *top))
	}
	return nil
}

// familyKey groups family members ("wp-plugin/x" -> "wp-plugin/*") so the
// per-group lists stay readable.
func familyKey(id string) string {
	for _, p := range []string{"wp-plugin/", "wp-theme/", "npm/", "cdnjs/"} {
		if strings.HasPrefix(id, p) {
			return p + "*"
		}
	}
	return id
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}

func topList(m map[string]int, n int) string {
	type kv struct {
		k string
		v int
	}
	var l []kv
	for k, v := range m {
		l = append(l, kv{k, v})
	}
	sort.Slice(l, func(i, j int) bool { return l[i].v > l[j].v || (l[i].v == l[j].v && l[i].k < l[j].k) })
	var parts []string
	for i, x := range l {
		if i == n {
			break
		}
		parts = append(parts, fmt.Sprintf("%s %d", x.k, x.v))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}
