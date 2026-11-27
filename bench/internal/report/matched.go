package report

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
)

// A rule ID is "AEG-family-number". These families are not content rules: the
// protocol rules (method, content type, body size, control characters, path
// traversal in the raw path, transfer encoding, double encoding, the limits of
// an inspection and a body that cannot be parsed), the route rules, the schema
// rules (a declared field that fails its declaration, an undeclared field) and
// the scanner rules (a scanner's User-Agent, a probe or backup path).
const (
	familyProtocol = "PROTO"
	familyRoute    = "ROUTE"
	familySchema   = "SCHEMA"
	familyScanner  = "SCANNER"
)

// contentFamilies are the families of the content rules, which look for an
// attack in what a request says.
var contentFamilies = []string{
	"SQLI", "XSS", "CMDI", "CODEI", "LDAP", "SSTI", "JNDI", "CRLF", "LFI", "RFI", "SSRF", "XXE", "NOSQL",
	"PPOLL", "SESSION",
}

// family returns the family of a rule ID, "" for an ID of another form.
func family(id string) string {
	rest, ok := strings.CutPrefix(id, "AEG-")
	if !ok {
		return ""
	}
	name, _, ok := strings.Cut(rest, "-")
	if !ok {
		return ""
	}
	return name
}

// Matched splits the detected cases of a Counts by what matched them. The five
// numbers add up to the cases blocked or flagged.
type Matched struct {
	// Content counts the cases in which at least one content rule matched. In
	// the others, route rules aside, ProtocolOnly, SchemaOnly and ScannerOnly
	// count those with rules of that one family alone, and Other the rest:
	// more than one of these families, a family not known here, a route rule
	// alone or no rule at all.
	Content, ProtocolOnly, SchemaOnly, ScannerOnly, Other int
}

// matchedOf is the split of one detected case with these rules.
func matchedOf(rules []string) Matched {
	var other []string
	for _, id := range rules {
		f := family(id)
		if slices.Contains(contentFamilies, f) {
			return Matched{Content: 1}
		}
		// A route rule that does not block is no detection, so beside another
		// rule it says nothing about why a case was detected.
		if f != familyRoute {
			other = append(other, f)
		}
	}
	slices.Sort(other)
	switch names := slices.Compact(other); {
	case len(names) != 1:
	case names[0] == familyProtocol:
		return Matched{ProtocolOnly: 1}
	case names[0] == familySchema:
		return Matched{SchemaOnly: 1}
	case names[0] == familyScanner:
		return Matched{ScannerOnly: 1}
	}
	return Matched{Other: 1}
}

func (m *Matched) add(o Matched) {
	m.Content += o.Content
	m.ProtocolOnly += o.ProtocolOnly
	m.SchemaOnly += o.SchemaOnly
	m.ScannerOnly += o.ScannerOnly
	m.Other += o.Other
}

// RuleCount counts the detected cases of one split and expectation that matched
// protocol rules only, among them Rule. A case with several of those rules is
// counted under each.
type RuleCount struct {
	Rule, Split string
	Expected    cases.Expected
	Cases       int
}

type ruleKey struct {
	rule, split string
	expected    cases.Expected
}

func ruleCounts(count map[ruleKey]int) (out []RuleCount) {
	for _, k := range slices.SortedFunc(maps.Keys(count), func(a, b ruleKey) int {
		return cmp.Or(
			cmp.Compare(a.expected, b.expected),
			cmp.Compare(a.rule, b.rule),
			cmp.Compare(a.split, b.split),
		)
	}) {
		out = append(out, RuleCount{k.rule, k.split, k.expected, count[k]})
	}
	return out
}

// matchedExplanation says what the parts of the detections are, and what they
// cannot show.
func matchedExplanation() string {
	last := len(contentFamilies) - 1
	return fmt.Sprintf(`
Each detection, of an attack or of a legitimate request, is also counted by what
matched, from the rule IDs (AEG-family-number) of the case; the five parts add up
to the detections. Content rule: at least one rule of the families
%s or %s,
which look for an attack in what a request says. The other four parts hold the
cases without a content rule, route rules aside. Protocol only (AEG-PROTO-\*):
checks of the method, content type, body size, control characters, raw path and
transfer encoding, the limits of an inspection and a body that cannot be parsed.
Schema only (AEG-SCHEMA-\*): a declared field that fails its declaration (its
type, length, range, enum values or pattern), or a field that is not declared.
Scanner only (AEG-SCANNER-\*): a scanner's User-Agent, or a probe
or backup path. Anything else: more than one of these three, a block by a route
rule alone, or a block without a rule.

In enforce mode the first blocking match ends the inspection. The protocol checks
(the method, content type, body size and path among them) come first, then the
scanner checks of the User-Agent and of probe and backup paths, and only then are
the values of the request read. So a detection by protocol rules only or by
scanner rules only does not say that no content rule would have matched it, and
the content rule figures say what the content rules did in this configuration,
not what they would do if those refusals were switched off.
`, strings.Join(contentFamilies[:last], ", "), contentFamilies[last])
}
