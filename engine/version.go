package engine

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// versionRe accepts what we treat as a version: dotted numbers with an
// optional pre-release/build suffix ("3.7.1", "10.7.0-beta.2", "6.4").
var versionRe = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)*(?:[-+._]?[0-9a-z]+(?:[.-][0-9a-z]+)*)?$`)

// NormalizeVersion trims and lowercases v, strips a leading "v" and returns
// "" when the result does not look like a version.
func NormalizeVersion(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "v")
	if v == "" || len(v) > 40 || !versionRe.MatchString(v) {
		return ""
	}
	return v
}

// CompareVersions orders dotted versions numerically (1.10 > 1.9). A text
// part sorts below a number ("1.0.beta" < "1.0.0"), and a version below a
// longer one with the same prefix (3.8 < 3.8.0 < 3.8.1).
func CompareVersions(a, b string) int {
	pa, pb := splitVersion(a), splitVersion(b)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, errA := strconv.Atoi(pa[i])
		nb, errB := strconv.Atoi(pb[i])
		switch {
		case errA == nil && errB == nil:
			if na != nb {
				return cmpInt(na, nb)
			}
		case errA == nil:
			return 1
		case errB == nil:
			return -1
		default:
			if c := strings.Compare(pa[i], pb[i]); c != 0 {
				return c
			}
		}
	}
	return cmpInt(len(pa), len(pb))
}

func splitVersion(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '-' || r == '_' || r == '+' })
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// queryVersion returns the version in query parameter param of rawURL.
func queryVersion(rawURL, param string) string {
	q := strings.IndexByte(rawURL, '?')
	if q < 0 {
		return ""
	}
	vals, err := url.ParseQuery(rawURL[q+1:])
	if err != nil && len(vals) == 0 {
		return ""
	}
	v := vals.Get(param)
	if v == "" {
		return ""
	}
	// Only a plain dotted version counts. A hybrid value such as
	// "2.7.0-wc.10.7.0" names a bundled library and its host at once; rules
	// that understand the form read it with a regex instead.
	v = strings.TrimPrefix(strings.ToLower(v), "v")
	if !plainVersionRe.MatchString(v) {
		return ""
	}
	return NormalizeVersion(dropCacheBuster(v))
}

// dropCacheBuster cuts a dotted version at the first part that looks like a
// timestamp or build counter appended for cache busting
// ("3.7.1.1788768375" -> "3.7.1"). A version that starts with one is kept.
func dropCacheBuster(v string) string {
	parts := strings.Split(v, ".")
	for i, p := range parts {
		if i > 0 && len(p) >= 7 {
			return strings.Join(parts[:i], ".")
		}
	}
	return v
}

var plainVersionRe = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)*$`)

// resolveVersion turns a version template into a concrete version using the
// submatches of a successful match (index 0 is the whole match).
//
//	"\1"     -> submatches[1]
//	"\1?a:b" -> "a" if submatches[1] is non-empty else "b"
//	"1.2"    -> literal "1.2"
//	"v\1"    -> "v" + submatches[1]
func resolveVersion(tpl string, submatches []string) string {
	if tpl == "" {
		return ""
	}
	if q := strings.IndexByte(tpl, '?'); q >= 0 && strings.HasPrefix(tpl, `\`) {
		ref := tpl[1:q]
		if idx, err := strconv.Atoi(ref); err == nil {
			rest := tpl[q+1:]
			present, absent, _ := strings.Cut(rest, ":")
			if idx < len(submatches) && submatches[idx] != "" {
				return expandRefs(present, submatches)
			}
			return expandRefs(absent, submatches)
		}
	}
	return expandRefs(tpl, submatches)
}

// expandRefs substitutes \N references in s with the corresponding submatch.
// Unknown references expand to empty.
func expandRefs(s string, submatches []string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
			j := i + 1
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			if idx, err := strconv.Atoi(s[i+1 : j]); err == nil && idx < len(submatches) {
				b.WriteString(submatches[idx])
			}
			i = j - 1
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
