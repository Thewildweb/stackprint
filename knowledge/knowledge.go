// Package knowledge holds per-technology release facts that let the engine
// bound a detected technology's version: its release list, files that exist
// only in some releases, libraries it bundles per release, and hashes of the
// files it ships.
//
// Packs are generated from public release archives (wordpress.org, npm) by
// the release generator. They are plain JSON so any tool can produce them.
package knowledge

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

// Pack is the release knowledge for one technology.
type Pack struct {
	TechID   string       `json:"tech_id"`
	Source   string       `json:"source,omitempty"` // where the facts come from, e.g. "wordpress.org plugin API 2026-11-22"
	Releases []Release    `json:"releases,omitempty"`
	Files    []FileMarker `json:"files,omitempty"`
	Bundled  []BundledLib `json:"bundled,omitempty"`
	Hashes   []FileHash   `json:"hashes,omitempty"`
}

// Release is one published version.
type Release struct {
	Version string `json:"version"`
	Date    string `json:"date,omitempty"` // YYYY-MM-DD
}

// FileMarker is a file (path relative to the technology's folder) that exists
// only in some releases. A page loading it bounds the installed version to
// After < v < Before (exclusive; empty = open). After is the newest release
// known NOT to have the file — not necessarily the one before the first
// release that has it, as intermediate releases may not have been read.
type FileMarker struct {
	Path   string `json:"path"`
	After  string `json:"after,omitempty"`
	Before string `json:"before,omitempty"`
}

// BundledLib says the releases Min..Max (inclusive) of the technology ship
// library Lib at version LibVersion.
type BundledLib struct {
	Lib        string `json:"lib"`
	LibVersion string `json:"lib_version"`
	Min        string `json:"min"`
	Max        string `json:"max"`
}

// FileHash says the file with this SHA-256 (or SHA-1; set at least one, of the
// decoded body) is shipped by releases Min..Max (inclusive) of the technology.
type FileHash struct {
	SHA256 string `json:"sha256,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	Path   string `json:"path,omitempty"`
	Min    string `json:"min"`
	Max    string `json:"max"`
}

// Store indexes packs by technology id.
type Store struct {
	packs map[string]*Pack
	// byHash maps a file hash to the (technology, range) entries shipping it.
	byHash map[string][]HashHit
}

// HashHit is one technology release range that ships a given file.
type HashHit struct {
	TechID string
	Hash   FileHash
}

// NewStore builds a Store from packs; packs for the same id are merged.
func NewStore(packs []Pack) *Store {
	s := &Store{packs: map[string]*Pack{}, byHash: map[string][]HashHit{}}
	for i := range packs {
		p := packs[i]
		if p.TechID == "" {
			continue
		}
		if cur, ok := s.packs[p.TechID]; ok {
			cur.Releases = append(cur.Releases, p.Releases...)
			cur.Files = append(cur.Files, p.Files...)
			cur.Bundled = append(cur.Bundled, p.Bundled...)
			cur.Hashes = append(cur.Hashes, p.Hashes...)
			if cur.Source == "" {
				cur.Source = p.Source
			}
		} else {
			cp := p
			s.packs[p.TechID] = &cp
		}
	}
	for id, p := range s.packs {
		for _, h := range p.Hashes {
			// SHA-1 and SHA-256 hex differ in length, so one index holds both.
			for _, key := range []string{h.SHA256, h.SHA1} {
				if key = strings.ToLower(key); key != "" {
					s.byHash[key] = append(s.byHash[key], HashHit{TechID: id, Hash: h})
				}
			}
		}
	}
	return s
}

// Get returns the pack for a technology id, or nil.
func (s *Store) Get(id string) *Pack {
	if s == nil {
		return nil
	}
	return s.packs[id]
}

// ByHash returns the technologies shipping a file with this hash (SHA-256 or
// SHA-1 hex).
func (s *Store) ByHash(sha string) []HashHit {
	if s == nil {
		return nil
	}
	return s.byHash[strings.ToLower(sha)]
}

// Len is the number of technologies with knowledge.
func (s *Store) Len() int {
	if s == nil {
		return 0
	}
	return len(s.packs)
}

// Load reads every *.json (a pack or a list of packs) and *.ndjson (one pack
// per line) file under dir.
func Load(fsys fs.FS, dir string) (*Store, error) {
	var packs []Pack
	var files []string
	err := fs.WalkDir(fsys, dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !e.IsDir() && (strings.HasSuffix(p, ".json") || strings.HasSuffix(p, ".ndjson")) {
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
		got, err := parse(data, strings.HasSuffix(p, ".ndjson"))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		packs = append(packs, got...)
	}
	return NewStore(packs), nil
}

func parse(data []byte, ndjson bool) ([]Pack, error) {
	if ndjson {
		var out []Pack
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 1<<20), 64<<20)
		for sc.Scan() {
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 {
				continue
			}
			var p Pack
			if err := json.Unmarshal(line, &p); err != nil {
				return nil, err
			}
			out = append(out, p)
		}
		return out, sc.Err()
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var out []Pack
		err := json.Unmarshal(trimmed, &out)
		return out, err
	}
	var p Pack
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return nil, err
	}
	return []Pack{p}, nil
}
