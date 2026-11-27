package gotestwaf

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/textproto"
	"strconv"
	"strings"
)

const (
	// soapFile is the file of the tool's source that defines what its
	// SOAPBody placeholder sends.
	soapFile = "internal/payload/placeholder/soapbody.go"
	// soapConstant is the format string of the envelope in that file.
	soapConstant = "soapBodyPayloadWrapper"
	// soapGap is where the format string takes a value.
	soapGap = "%s"
)

// soapEnvelope is what the tool's SOAPBody placeholder sends around a
// payload. The text is the tool's; it is read from the tree and not kept
// here.
type soapEnvelope struct {
	// parts are the pieces of the envelope around its three gaps, which take
	// the element name, its content and the element name again.
	parts [4]string
	// action is the value of the SOAPAction header.
	action string
}

// readSOAP reads the envelope from the tool's source in the tree. The file
// is parsed as Go source and looked at, never compiled or run: the envelope
// is the one string literal of the constant, and the action is the one
// string literal that a Header.Add call sets SOAPAction to. Anything else
// (no file, no such constant or call, more than one, a value that is not a
// plain literal, an envelope whose gaps are not exactly three "%s") gives
// nil, and no SOAPBody case is then imported.
func readSOAP(fsys fs.FS) *soapEnvelope {
	content, err := readFile(fsys, soapFile)
	if err != nil || len(content) > maxFileBytes {
		return nil
	}
	file, err := parser.ParseFile(token.NewFileSet(), "", content, parser.SkipObjectResolution)
	if err != nil {
		return nil
	}

	var envelopes, actions []string
	plain := true
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.ValueSpec:
			for i, name := range n.Names {
				if name.Name != soapConstant {
					continue
				}
				value, ok := "", i < len(n.Values)
				if ok {
					value, ok = stringLiteral(n.Values[i])
				}
				plain = plain && ok
				envelopes = append(envelopes, value)
			}
		case *ast.CallExpr:
			add, ok := n.Fun.(*ast.SelectorExpr)
			if !ok || len(n.Args) != 2 {
				return true
			}
			name, ok := stringLiteral(n.Args[0])
			if !ok || textproto.CanonicalMIMEHeaderKey(name) != "Soapaction" {
				return true
			}
			receiver, isField := add.X.(*ast.SelectorExpr)
			value, ok := stringLiteral(n.Args[1])
			plain = plain && ok && add.Sel.Name == "Add" && isField && receiver.Sel.Name == "Header"
			actions = append(actions, value)
		}
		return true
	})
	if !plain || len(envelopes) != 1 || len(actions) != 1 || !isConstant(file, soapConstant) {
		return nil
	}
	// The tool fills the envelope in with a format call; only "%s" gaps are
	// filled in here, so any other "%" is refused.
	if strings.Count(envelopes[0], soapGap) != 3 || strings.Count(envelopes[0], "%") != 3 {
		return nil
	}
	return &soapEnvelope{parts: [4]string(strings.Split(envelopes[0], soapGap)), action: actions[0]}
}

// stringLiteral returns the value of an expression that is one string
// literal.
func stringLiteral(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	return value, err == nil
}

// isConstant reports whether name is declared as a constant of the file
// itself, not as a variable or inside a function.
func isConstant(file *ast.File, name string) bool {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			if value, ok := spec.(*ast.ValueSpec); ok {
				for _, n := range value.Names {
					if n.Name == name {
						return true
					}
				}
			}
		}
	}
	return false
}
