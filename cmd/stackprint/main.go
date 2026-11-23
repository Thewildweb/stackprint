// Command stackprint scans pages for the technologies they use.
//
//	stackprint scan [-rules dir] [-knowledge dir] [-assets file] [-c N] < pages.ndjson > results.ndjson
//	stackprint scan-assets [-rules dir] < assets.ndjson > asset-results.ndjson
//	stackprint test [-rules dir]
//	stackprint validate [-rules dir]
//	stackprint list [-rules dir]
//	stackprint js-keys [-rules dir]
//	stackprint mine -pages pages.ndjson -report report.md -out report.json
//	stackprint version
//
// scan reads one page document (JSON, see package page) per line and writes
// one result per line in input order. It flushes after every line, so it can
// also run as a long-lived worker behind a pipe.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/Thewildweb/stackprint"
	"github.com/Thewildweb/stackprint/engine"
	"github.com/Thewildweb/stackprint/page"
	"github.com/Thewildweb/stackprint/ruleset"
)

const maxLine = 64 << 20

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "scan":
		err = cmdScan(args)
	case "scan-assets":
		err = cmdScanAssets(args)
	case "test":
		err = cmdTest(args)
	case "validate":
		err = cmdValidate(args)
	case "list":
		err = cmdList(args)
	case "js-keys":
		err = cmdJSKeys(args)
	case "mine":
		err = cmdMine(args)
	case "tokens":
		err = cmdTokens(args)
	case "ablate":
		err = cmdAblate(args)
	case "version":
		fmt.Println("stackprint", engine.EngineVersion)
		return
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "stackprint:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: stackprint <command> [flags]

commands:
  scan         scan page documents (NDJSON stdin -> NDJSON stdout)
  scan-assets  scan asset bodies (NDJSON stdin -> NDJSON stdout)
  test         run the fixtures in the rule files
  validate     check the rule files
  list         list technology ids
  js-keys      list JS global paths browser fetchers should evaluate
  mine         mine candidate signals from a corpus of page documents
  tokens       stream per-page tokens and labels as TSV, for corpora too large for mine
  ablate       measure what each signal group contributes to detections
  version      print the engine version
`)
}

type common struct {
	rules, knowledge string
}

func (c *common) register(fs *flag.FlagSet, withKnowledge bool) {
	fs.StringVar(&c.rules, "rules", "", "rule directory (default: rules built into the binary)")
	if withKnowledge {
		fs.StringVar(&c.knowledge, "knowledge", "", "release knowledge directory (optional)")
	}
}

func (c *common) load() (*engine.Scanner, *ruleset.Set, error) {
	return stackprint.Load(c.rules, c.knowledge)
}

func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var c common
	c.register(fs, true)
	assetsFile := fs.String("assets", "", "NDJSON of earlier scan-assets results, matched to page resources by sha256")
	workers := fs.Int("c", runtime.NumCPU(), "concurrent scans")
	minConf := fs.Int("min-confidence", 0, "drop detections below this confidence")
	noUnexplained := fs.Bool("no-unexplained", false, "do not report unexplained tokens")
	fs.Parse(args)

	sc, _, err := c.load()
	if err != nil {
		return err
	}
	opts := engine.Options{MinConfidence: *minConf, NoUnexplained: *noUnexplained}
	if *assetsFile != "" {
		if opts.Assets, err = loadAssets(*assetsFile); err != nil {
			return err
		}
	}
	return pipeline(os.Stdin, os.Stdout, *workers, func(line []byte) any {
		var d page.Document
		if err := json.Unmarshal(line, &d); err != nil {
			return &engine.Result{EngineVersion: engine.EngineVersion, RulesetVersion: sc.RulesetVersion(), Detections: []engine.Detection{}, Error: "bad input: " + err.Error()}
		}
		return sc.Scan(&d, opts)
	})
}

func cmdScanAssets(args []string) error {
	fs := flag.NewFlagSet("scan-assets", flag.ExitOnError)
	var c common
	c.register(fs, false)
	workers := fs.Int("c", runtime.NumCPU(), "concurrent scans")
	fs.Parse(args)
	sc, _, err := c.load()
	if err != nil {
		return err
	}
	return pipeline(os.Stdin, os.Stdout, *workers, func(line []byte) any {
		var a page.Asset
		if err := json.Unmarshal(line, &a); err != nil {
			return map[string]string{"error": "bad input: " + err.Error()}
		}
		return sc.ScanAsset(&a)
	})
}

func loadAssets(path string) (map[string]*engine.AssetResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]*engine.AssetResult{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), maxLine)
	for sc.Scan() {
		var r engine.AssetResult
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil || r.SHA256 == "" {
			continue
		}
		out[strings.ToLower(r.SHA256)] = &r
	}
	return out, sc.Err()
}

// pipeline runs fn over input lines with n workers and writes results in
// input order, flushing after each.
func pipeline(in io.Reader, out io.Writer, n int, fn func([]byte) any) error {
	if n < 1 {
		n = 1
	}
	type job struct {
		seq  int
		line []byte
	}
	type done struct {
		seq int
		out []byte
	}
	jobs := make(chan job, n*2)
	results := make(chan done, n*2)

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				b, err := json.Marshal(fn(j.line))
				if err != nil {
					b = []byte(fmt.Sprintf(`{"error":%q}`, err.Error()))
				}
				results <- done{j.seq, b}
			}
		}()
	}

	readErr := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(in)
		sc.Buffer(make([]byte, 1<<20), maxLine)
		seq := 0
		for sc.Scan() {
			line := sc.Bytes()
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			jobs <- job{seq, append([]byte(nil), line...)}
			seq++
		}
		close(jobs)
		readErr <- sc.Err()
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	w := bufio.NewWriter(out)
	pending := map[int][]byte{}
	next := 0
	var werr error
	for r := range results {
		if werr != nil {
			continue // drain so workers can finish
		}
		pending[r.seq] = r.out
		for {
			b, ok := pending[next]
			if !ok {
				break
			}
			delete(pending, next)
			w.Write(b)
			w.WriteByte('\n')
			next++
		}
		werr = w.Flush()
	}
	if werr != nil {
		return werr
	}
	return <-readErr
}

func cmdTest(args []string) error {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	var c common
	c.register(fs, true)
	fs.Parse(args)
	sc, set, err := c.load()
	if err != nil {
		return err
	}
	failures, n := stackprint.RunTests(sc, set)
	for _, f := range failures {
		fmt.Println("FAIL", f)
	}
	fmt.Printf("%d fixtures, %d failed, %d technologies, ruleset %s\n", n, len(failures), len(set.Technologies), set.Version)
	if len(failures) > 0 {
		return fmt.Errorf("%d fixture(s) failed", len(failures))
	}
	return nil
}

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	var c common
	c.register(fs, false)
	fs.Parse(args)
	set, err := loadSet(c.rules)
	if err != nil {
		return err
	}
	errs := set.Validate()
	for _, e := range errs {
		fmt.Println(e)
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d problem(s)", len(errs))
	}
	fmt.Printf("ok: %d technologies, %d categories, ruleset %s\n", len(set.Technologies), len(set.Categories), set.Version)
	return nil
}

func loadSet(dir string) (*ruleset.Set, error) {
	if dir == "" {
		return stackprint.EmbeddedRules()
	}
	return ruleset.Load(os.DirFS(dir), ".")
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	var c common
	c.register(fs, false)
	fs.Parse(args)
	set, err := loadSet(c.rules)
	if err != nil {
		return err
	}
	for _, t := range set.Technologies {
		fmt.Printf("%s\t%s\t%s\n", t.ID, t.Name, strings.Join(t.Categories, ","))
	}
	return nil
}

func cmdJSKeys(args []string) error {
	fs := flag.NewFlagSet("js-keys", flag.ExitOnError)
	var c common
	c.register(fs, false)
	fs.Parse(args)
	sc, _, err := c.load()
	if err != nil {
		return err
	}
	for _, k := range sc.JSGlobalKeys() {
		fmt.Println(k)
	}
	return nil
}
