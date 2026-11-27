package gotestwaf

import (
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
)

// Reasons for which the tool cannot load a test case file. It reads all its
// files at once and stops at the first of these.
const (
	cannotLoad          = "the tool cannot load this file: "
	reasonKind          = cannotLoad + "a placeholder is neither a name nor a mapping"
	reasonKeys          = cannotLoad + "a placeholder mapping does not have exactly one name"
	reasonConfig        = cannotLoad + "a placeholder's configuration is not a mapping"
	reasonConfigured    = cannotLoad + "a configured placeholder is not one of the tool's"
	reasonGraphQLMethod = cannotLoad + "GraphQL needs the method GET or POST"
	reasonRawMethod     = cannotLoad + "RawRequest needs a method that is a string"
	reasonRawPath       = cannotLoad + "the RawRequest path is not a string"
	reasonRawBody       = cannotLoad + "the RawRequest body is not a string"
	reasonRawHeaders    = cannotLoad + "the RawRequest headers are not a mapping"
	reasonRawHeader     = cannotLoad + "a RawRequest header is not a string"
	reasonRepeatedKey   = "a placeholder's configuration names a key twice"
	reasonRepeatedName  = "a RawRequest names a header twice"
)

// known are the tool's placeholders.
var known = []string{
	"GraphQL", "gRPC", "Header", "HTMLForm", "HTMLMultipartForm", "JSONBody", "JSONRequest",
	"RawRequest", "RequestBody", "SOAPBody", "URLParam", "URLPath", "UserAgent", "XMLBody",
}

// readPlaceholder reads one entry of a placeholder list: a name, or a
// mapping of one name to that placeholder's configuration. A name is taken
// as it is, known or not; the tool finds out when it sends.
func readPlaceholder(n *yaml.Node) (p placeholder, reason string) {
	n = resolve(n)
	if name, ok := text(n); ok {
		return placeholder{name: name}, ""
	}
	if n.Kind != yaml.MappingNode {
		return p, reasonKind
	}
	if len(n.Content) != 2 {
		return p, reasonKeys
	}
	name, ok := text(n.Content[0])
	if !ok {
		return p, reasonKeys
	}
	if !slices.Contains(known, name) {
		return p, reasonConfigured
	}
	config, reason := readMapping(n.Content[1])
	if reason != "" {
		return p, reason
	}
	p.name = name
	switch name {
	case "GraphQL":
		if method, ok := text(config["method"]); !ok || method != "GET" && method != "POST" {
			return p, reasonGraphQLMethod
		}
	case "RawRequest":
		p.raw, reason = readRaw(config)
	}
	return p, reason
}

// readRaw reads the configuration of a RawRequest. Hosts in its templates
// are replaced like hosts in a payload.
func readRaw(config map[string]*yaml.Node) (c *rawConfig, reason string) {
	c = &rawConfig{path: "/"}
	var ok bool
	if c.method, ok = text(config["method"]); !ok {
		return nil, reasonRawMethod
	}
	if n, set := config["path"]; set {
		if c.path, ok = text(n); !ok {
			return nil, reasonRawPath
		}
		if c.path == "" {
			c.path = "/"
		}
	}
	if n, set := config["body"]; set {
		if c.body, ok = text(n); !ok {
			return nil, reasonRawBody
		}
	}
	if n, set := config["headers"]; set {
		n = resolve(n)
		if n.Kind != yaml.MappingNode {
			return nil, reasonRawHeaders
		}
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			name, okName := text(n.Content[i])
			value, okValue := text(n.Content[i+1])
			if !okName || !okValue {
				return nil, reasonRawHeader
			}
			if seen[name] {
				return nil, reasonRepeatedName
			}
			seen[name] = true
			c.headers = append(c.headers, header{name, value})
		}
	}

	// The marker survives: only the bytes that spell a host change, and a
	// brace spells none.
	c.path, c.body = cases.RewriteCallbacks(c.path), cases.RewriteCallbacks(c.body)
	for i, h := range c.headers {
		c.headers[i].value = cases.RewriteCallbacks(h.value)
	}
	return c, ""
}

// readMapping reads a placeholder's configuration: a mapping with string
// keys, each used once. The tool would use the last of two equal keys;
// such a file is left out instead.
func readMapping(n *yaml.Node) (map[string]*yaml.Node, string) {
	n = resolve(n)
	if n.Kind != yaml.MappingNode {
		return nil, reasonConfig
	}
	out := make(map[string]*yaml.Node, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, ok := text(n.Content[i])
		if !ok {
			return nil, reasonConfig
		}
		if _, ok := out[key]; ok {
			return nil, reasonRepeatedKey
		}
		out[key] = n.Content[i+1]
	}
	return out, ""
}

// resolve follows an alias to the node it names.
func resolve(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.AliasNode && n.Alias != nil {
		return n.Alias
	}
	return n
}

// yaml11Words are plain scalars that the tool's YAML 1.1 reader takes for
// booleans and this package's reader takes for strings.
var yaml11Words = []string{"y", "Y", "yes", "Yes", "YES", "n", "N", "no", "No", "NO", "on", "On", "ON", "off", "Off", "OFF"}

// text returns the value of a scalar that the tool reads as a string. A
// number, a boolean, a null or a binary value is not one.
func text(n *yaml.Node) (string, bool) {
	n = resolve(n)
	if n == nil || n.Kind != yaml.ScalarNode || n.ShortTag() != "!!str" {
		return "", false
	}
	if n.Style == 0 && slices.Contains(yaml11Words, n.Value) {
		return "", false
	}
	return n.Value, true
}
