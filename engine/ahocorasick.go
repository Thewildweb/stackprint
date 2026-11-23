package engine

// ahoCorasick is a byte-level multi-pattern substring matcher. It answers one
// question very fast: of a fixed set of literal "anchor" strings, which ones
// occur somewhere in a given text? A single linear pass over the text reports
// every matching anchor, regardless of how many anchors are registered.
//
// This is the heart of the engine's throughput. Each rule signal
// contributes mandatory literal anchors; the automaton screens a whole page
// body in one pass, and only the signals whose anchor was found ever have
// their (comparatively expensive) regex evaluated.
//
// The implementation is the classic goto/failure/output automaton built over a
// per-node child map. It is built once and is read-only during matching, so a
// single automaton is safe to query from many goroutines concurrently.
type ahoCorasick struct {
	nodes []acNode
}

type acNode struct {
	children map[byte]int // next state by input byte
	fail     int          // failure link
	// outputs lists the anchor IDs that end at this node (directly or via
	// failure links), precomputed at build time.
	outputs []int
}

// acBuilder accumulates anchors before the automaton is frozen.
type acBuilder struct {
	nodes   []acNode
	anchors map[string]int // anchor text -> anchor ID (dedup)
}

func newACBuilder() *acBuilder {
	return &acBuilder{
		nodes:   []acNode{{children: map[byte]int{}}}, // root
		anchors: map[string]int{},
	}
}

// add registers an anchor and returns its stable ID. Repeated anchors share an
// ID so the same literal used by many patterns is stored once.
func (b *acBuilder) add(anchor string) int {
	if id, ok := b.anchors[anchor]; ok {
		return id
	}
	id := len(b.anchors)
	b.anchors[anchor] = id

	cur := 0
	for i := 0; i < len(anchor); i++ {
		c := anchor[i]
		next, ok := b.nodes[cur].children[c]
		if !ok {
			next = len(b.nodes)
			b.nodes = append(b.nodes, acNode{children: map[byte]int{}})
			b.nodes[cur].children[c] = next
		}
		cur = next
	}
	b.nodes[cur].outputs = append(b.nodes[cur].outputs, id)
	return id
}

// build computes failure and output links via BFS and returns the frozen
// automaton. If no anchors were added, it returns nil (callers treat nil as
// "matches nothing").
func (b *acBuilder) build() *ahoCorasick {
	if len(b.anchors) == 0 {
		return nil
	}

	queue := make([]int, 0, len(b.nodes))
	// Depth-1 nodes fail to the root.
	for _, child := range b.nodes[0].children {
		b.nodes[child].fail = 0
		queue = append(queue, child)
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		for c, child := range b.nodes[cur].children {
			queue = append(queue, child)

			// Follow failure links from cur's failure state to find the
			// longest proper suffix that has a transition on c.
			f := b.nodes[cur].fail
			for f != 0 {
				if _, ok := b.nodes[f].children[c]; ok {
					break
				}
				f = b.nodes[f].fail
			}
			if next, ok := b.nodes[f].children[c]; ok && next != child {
				b.nodes[child].fail = next
			} else {
				b.nodes[child].fail = 0
			}

			// Inherit outputs from the failure state.
			fail := b.nodes[child].fail
			b.nodes[child].outputs = append(b.nodes[child].outputs, b.nodes[fail].outputs...)
		}
	}

	return &ahoCorasick{nodes: b.nodes}
}

// match scans text and marks present[id]=true for every registered anchor that
// occurs in text. present must be at least as long as the number of distinct
// anchors. Every anchor seen for the first time in this call (a false->true
// flip) is appended to *hits, letting the caller enumerate matches and then
// reset only the touched entries — reusing both buffers across many pages with
// no per-scan allocation. Pass hits == nil to skip hit collection.
func (ac *ahoCorasick) match(text string, present []bool, hits *[]int) {
	if ac == nil {
		return
	}
	cur := 0
	for i := 0; i < len(text); i++ {
		c := text[i]
		for cur != 0 {
			if _, ok := ac.nodes[cur].children[c]; ok {
				break
			}
			cur = ac.nodes[cur].fail
		}
		if next, ok := ac.nodes[cur].children[c]; ok {
			cur = next
		} else {
			cur = 0
		}
		for _, id := range ac.nodes[cur].outputs {
			if !present[id] {
				present[id] = true
				if hits != nil {
					*hits = append(*hits, id)
				}
			}
		}
	}
}
