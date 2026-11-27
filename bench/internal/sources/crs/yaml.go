package crs

import (
	"bytes"
	"errors"
	"io"
	"regexp"

	"gopkg.in/yaml.v3"
)

// documents reads the first YAML document of content into first. more
// reports that something follows it, which the upstream runner does not read.
func documents(content []byte) (first yaml.Node, more bool, err error) {
	dec := yaml.NewDecoder(bytes.NewReader(content))
	if err := dec.Decode(&first); err != nil {
		if errors.Is(err, io.EOF) {
			return first, false, nil
		}
		return first, false, err
	}
	var next yaml.Node
	return first, !errors.Is(dec.Decode(&next), io.EOF), nil
}

// field is one entry of a YAML mapping.
type field struct {
	key   string
	value *yaml.Node
}

// fields are the entries of a YAML mapping, in file order.
type fields []field

// get returns the value with the given key, or nil.
func (fs fields) get(key string) *yaml.Node {
	for _, f := range fs {
		if f.key == key {
			return f.value
		}
	}
	return nil
}

// mapping reads n as a mapping with scalar keys, each used once. Otherwise it
// returns what is wrong with n, to follow the name of the thing read. Aliases
// are not followed here or below: the test format does not need them.
func mapping(n *yaml.Node) (fields, string) {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil, "is not a mapping"
	}
	out := make(fields, 0, len(n.Content)/2)
	seen := make(map[string]bool, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, ok := scalar(n.Content[i])
		if !ok {
			return nil, "is not a mapping"
		}
		// Which value the upstream runner would use is not defined.
		if seen[key] {
			return nil, "names a key twice"
		}
		seen[key] = true
		out = append(out, field{key, n.Content[i+1]})
	}
	return out, ""
}

// scalar returns the text of a scalar: as written for a number or a boolean,
// decoded for a !!binary value.
func scalar(n *yaml.Node) (string, bool) {
	if n == nil || n.Kind != yaml.ScalarNode {
		return "", false
	}
	var s string
	if err := n.Decode(&s); err != nil {
		return "", false
	}
	return s, true
}

func isNull(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null"
}

var numberPattern = regexp.MustCompile(`^[0-9]{1,12}$`)

// number returns the digits of a rule or test ID.
func number(n *yaml.Node) (string, bool) {
	if n == nil || n.Kind != yaml.ScalarNode || !numberPattern.MatchString(n.Value) {
		return "", false
	}
	return n.Value, true
}

// listLength returns the length of a list; a list left out is empty.
func listLength(n *yaml.Node) (int, bool) {
	switch {
	case n == nil || isNull(n):
		return 0, true
	case n.Kind == yaml.SequenceNode:
		return len(n.Content), true
	}
	return 0, false
}
