package cases

import (
	"encoding/base64"
	"unicode/utf8"
)

// Lines returns case lines that FromLine and Merge read back as c: one line
// per source reference and payload, or per reference when c has no payload.
// Each line is named by its source case ID. Bytes a JSON string cannot carry
// go into body_base64 and payload_base64; WriteLines fails on a case whose
// method, path, query or headers are not valid UTF-8.
func Lines(c Case) []Line {
	payloads := c.Payloads
	if len(payloads) == 0 {
		payloads = [][]byte{nil}
	}
	out := make([]Line, 0, len(c.Sources)*len(payloads))
	for _, ref := range c.Sources {
		for _, p := range payloads {
			l := Line{
				Name:         ref.CaseID,
				Category:     c.Category,
				Method:       c.Method,
				Path:         c.Path,
				Query:        [][]string{},
				RawQuery:     c.RawQuery,
				Headers:      make(map[string]string, len(c.Headers)),
				Source:       ref.Source,
				SourceCaseID: ref.CaseID,
				Expected:     c.Expected,
				Placement:    c.Placement,
				Encoder:      c.Encoder,
			}
			for name, value := range c.Headers {
				l.Headers[name] = value
			}
			l.Body, l.BodyBase64 = textOrEncoded(c.Body)
			l.Payload, l.PayloadBase64 = textOrEncoded(p)
			out = append(out, l)
		}
	}
	return out
}

// textOrEncoded returns b as text, or as base64 when it is not valid UTF-8.
func textOrEncoded(b []byte) (text, encoded string) {
	if utf8.Valid(b) {
		return string(b), ""
	}
	return "", base64.StdEncoding.EncodeToString(b)
}
