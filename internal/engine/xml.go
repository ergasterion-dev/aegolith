package engine

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ergasterion-dev/aegolith/internal/detect"
	"github.com/ergasterion-dev/aegolith/internal/model"
)

// Namespaces whose elements a browser renders as markup.
const (
	xhtmlNamespace = "http://www.w3.org/1999/xhtml"
	svgNamespace   = "http://www.w3.org/2000/svg"
)

// xmlEnd is how reading an XML body by value ended.
type xmlEnd int

const (
	xmlDone      xmlEnd = iota // read to the end, or stopped by s.stop or the budget
	xmlCut                     // the body ended early because it was cut (bodyCut)
	xmlMalformed               // a tokenizer error or a malformed leading declaration
	xmlTooDeep                 // nesting deeper than MaxDepth
)

// checkXML inspects an XML body by value.
//
// The XXE rule reads the raw body in windows first, as it always has. Then
// the body is tokenized with encoding/xml in strict mode and the text
// detectors read, on field "body":
//   - character data: adjacent runs (CDATA included, and runs separated
//     only by comments or processing instructions) joined into one value;
//   - attribute values, except namespace declarations (xmlns, xmlns:*);
//   - the content of a processing instruction other than the leading XML
//     declaration, rebuilt as "<?php ...?>" when its target is php in any
//     case;
//   - for an element a browser would render (local name script in any
//     ASCII case, or an element in the XHTML or SVG namespace), its start
//     tag rebuilt as <name attr="value" ...>, which carries its attribute
//     values instead of reading them one by one.
//
// Element and attribute names, namespace declarations, comments,
// directives (a DOCTYPE) and the leading declaration are not read. A
// declared ASCII-compatible charset is read byte by byte (xmlCharset); a
// body declaring any other charset, or binding a prefix to "xmlns" or ""
// (confusingBinding), is treated as malformed.
//
// Values beyond MaxFields raise AEG-PROTO-010 once and are still read one
// by one. A tokenizer error (AEG-PROTO-020), nesting deeper than MaxDepth
// (AEG-PROTO-010), and the unexpected end of a body cut at the inspection
// limit (nothing reported) stop the walk; the raw body is then scanned in
// windows by every text detector, so nothing after that point goes unseen.
//
// Budget: per source byte, the XXE pass charges at most 2x, values at most
// 4x (2x for windows, 2x more where a Latin-1 byte becomes two UTF-8
// bytes; entities and character references only shrink), and the raw
// rescan 2x: at most 8x, as for JSON.
func (s *state) checkXML(body []byte, cut bool) {
	raw := string(body)
	s.scanWindowsWith(noTextDetectors, model.LocBody, "body", raw, detect.XXE, "")
	if s.stop || s.exhausted {
		return
	}
	switch s.walkXML(body, cut) {
	case xmlDone:
		return
	case xmlTooDeep:
		s.protoMatch(ruleLimit, model.LocBody, "body", "")
	case xmlMalformed:
		s.protoMatch(ruleMalformed, model.LocBody, "body", "")
	}
	s.scan(model.LocBody, "body", raw)
}

func noTextDetectors(string) []detect.Hit { return nil }

// walkXML tokenizes body and hands every value to xmlValue (see checkXML).
// It is linear in the body: character data is appended to one reused
// buffer and each value is built once.
func (s *state) walkXML(body []byte, cut bool) xmlEnd {
	n, enc, ok := leadingXMLDeclaration(body)
	if !ok {
		return xmlMalformed
	}
	rest := body[n:]
	if n == 0 {
		rest = bytes.TrimPrefix(rest, []byte("\ufeff"))
	}
	switch xmlCharset(enc) {
	case charsetUTF8:
		if cut {
			rest = trimPartialRune(rest)
		}
	case charsetBytes:
		rest = latin1ToUTF8(rest)
	default:
		return xmlMalformed
	}
	d := xml.NewDecoder(bytes.NewReader(rest))
	d.Strict = true
	// A later <?xml encoding="..."?> must not switch readers or fail: the
	// charset was settled by the leading declaration.
	d.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }

	w := xmlWalk{s: s}
	depth := 0
	for !s.stop && !s.exhausted {
		tok, err := d.Token()
		if err != nil {
			w.flush()
			switch {
			case err == io.EOF:
				return xmlDone
			case cut && unexpectedEOF(err):
				return xmlCut
			}
			return xmlMalformed
		}
		switch t := tok.(type) {
		case xml.CharData:
			w.text = append(w.text, t...)
		case xml.Comment:
			// Not read, and does not end the run of text around it.
		case xml.ProcInst:
			w.procInst(t)
		case xml.StartElement:
			w.flush()
			if depth++; depth > s.e.lim.MaxDepth {
				return xmlTooDeep
			}
			if confusingBinding(t) {
				return xmlMalformed
			}
			w.start(t)
		case xml.EndElement:
			w.flush()
			depth--
		case xml.Directive:
			w.flush()
		}
	}
	return xmlDone
}

// xmlWalk holds the reused buffers of one walk and its value count.
type xmlWalk struct {
	s      *state
	text   []byte // the current run of character data
	tag    []byte // a rebuilt start tag
	values int
}

// flush reads the current run of character data, unless it is blank.
func (w *xmlWalk) flush() {
	if !xmlBlank(w.text) {
		w.value(string(w.text))
	}
	w.text = w.text[:0]
}

// count counts one value; the first beyond MaxFields raises AEG-PROTO-010.
func (w *xmlWalk) count() {
	if w.values++; w.values == w.s.e.lim.MaxFields+1 {
		w.s.protoMatch(ruleLimit, model.LocBody, "body", "")
	}
}

func (w *xmlWalk) value(v string) {
	w.count()
	w.s.scan(model.LocBody, "body", v)
}

func (w *xmlWalk) procInst(p xml.ProcInst) {
	if xmlBlank(p.Inst) {
		return
	}
	if strings.EqualFold(p.Target, "php") {
		w.value("<?php " + string(p.Inst) + "?>")
		return
	}
	w.value(string(p.Inst))
}

// start reads the attribute values of an element, or its rebuilt start tag
// when a browser would render it.
func (w *xmlWalk) start(e xml.StartElement) {
	if !renderedElement(e.Name) {
		for _, a := range e.Attr {
			if !namespaceDeclaration(a.Name) && !xmlBlank([]byte(a.Value)) {
				w.value(a.Value)
			}
		}
		return
	}
	w.tag = append(append(w.tag[:0], '<'), e.Name.Local...)
	for _, a := range e.Attr {
		if namespaceDeclaration(a.Name) {
			continue
		}
		if !xmlBlank([]byte(a.Value)) {
			w.count()
		}
		q := byte('"')
		if strings.IndexByte(a.Value, '"') >= 0 && strings.IndexByte(a.Value, '\'') < 0 {
			q = '\''
		}
		w.tag = append(append(w.tag, ' '), a.Name.Local...)
		w.tag = append(w.tag, '=', q)
		w.tag = append(append(w.tag, a.Value...), q)
	}
	w.tag = append(w.tag, '>')
	w.s.scan(model.LocBody, "body", string(w.tag))
}

// renderedElement reports whether a browser would render an element of
// this name as markup: local name script in any ASCII case, or an element
// in the XHTML or SVG namespace.
func renderedElement(n xml.Name) bool {
	return strings.EqualFold(n.Local, "script") || n.Space == xhtmlNamespace || n.Space == svgNamespace
}

// confusingBinding reports whether an element binds a prefix to "xmlns" or
// to "": encoding/xml then translates an attribute in that prefix (q:x or
// q:xmlns) into a name namespaceDeclaration cannot tell from a
// declaration. Such a document is treated as malformed. Every binding is
// seen on the element that makes it, before any element in its scope, and
// no other translation yields those names: an unbound prefix stays as
// written and "xml" becomes the XML namespace URI.
func confusingBinding(e xml.StartElement) bool {
	for _, a := range e.Attr {
		if a.Name.Space == "xmlns" && (a.Value == "xmlns" || a.Value == "") {
			return true
		}
	}
	return false
}

// namespaceDeclaration reports whether an attribute declares a namespace
// (xmlns="..." or xmlns:p="...", as encoding/xml names them). It is exact
// only once confusingBinding has ruled out prefixes bound to "xmlns" or "".
func namespaceDeclaration(n xml.Name) bool {
	return n.Space == "xmlns" || (n.Space == "" && n.Local == "xmlns")
}

// xmlBlank reports whether b holds only XML white space.
func xmlBlank(b []byte) bool {
	for _, c := range b {
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
	}
	return true
}

// unexpectedEOF reports whether err is the tokenizer running out of input
// inside a token or an open element.
func unexpectedEOF(err error) bool {
	var se *xml.SyntaxError
	return errors.Is(err, io.ErrUnexpectedEOF) || (errors.As(err, &se) && se.Msg == "unexpected EOF")
}

// How a declared charset is read.
const (
	charsetOther = iota // not tokenized: the raw body is scanned instead
	charsetUTF8         // none declared, or UTF-8: read as sent
	charsetBytes        // ASCII-compatible: read byte by byte
)

// xmlCharset sorts a declared encoding name (any case). Tokenized are
// UTF-8 and these ASCII-compatible, stateless encodings, under their
// standard (WHATWG and IANA) names and aliases: US-ASCII, the ISO-8859
// parts and Latin-N names, Windows-874 (TIS-620) and Windows-1250 to 1258,
// KOI8-R and KOI8-U, Shift_JIS (Windows-31J), EUC-JP, EUC-KR (Windows-949),
// GB2312, GBK (Windows-936, EUC-CN), GB18030 and Big5. Each of them except
// UTF-8 is read byte by byte, each byte becoming the code point of the same
// value: ASCII bytes stay exact, and no byte of a multi-byte character in
// those encodings is one of the ASCII bytes XML markup is made of (<, >,
// &, quotes), so the markup is read as the application's parser reads it.
// Every other encoding (UTF-7, UTF-16, UTF-32, ISO-2022-JP, HZ, EBCDIC, an
// unknown name) could spell markup or an attack in bytes this read would
// not see, so it is not tokenized.
func xmlCharset(enc string) int {
	e := strings.ToLower(enc)
	if e == "" || utf8Names[e] {
		return charsetUTF8
	}
	if byteNames[e] || isoLatinName(e) || windowsName(e) {
		return charsetBytes
	}
	return charsetOther
}

var utf8Names = map[string]bool{
	"utf-8": true, "utf8": true, "unicode-1-1-utf-8": true, "unicode11utf8": true,
	"unicode20utf8": true, "x-unicode20utf8": true,
}

// byteNames are the aliases xmlCharset reads byte by byte that the
// patterns in isoLatinName and windowsName do not cover.
var byteNames = map[string]bool{
	// US-ASCII
	"us-ascii": true, "ascii": true, "us": true, "csascii": true, "ansi_x3.4-1968": true,
	"iso-ir-6": true, "iso646-us": true, "ibm367": true, "cp367": true,
	// ISO-8859-1
	"cp819": true, "ibm819": true, "iso-ir-100": true,
	// other ISO-8859 parts
	"iso-ir-101": true, "iso-ir-109": true, "iso-ir-110": true, "iso-ir-144": true,
	"iso-ir-127": true, "iso-ir-126": true, "iso-ir-138": true, "iso-ir-148": true,
	"cyrillic": true, "csisolatincyrillic": true, "arabic": true, "asmo-708": true,
	"ecma-114": true, "csisolatinarabic": true, "iso-8859-6-e": true, "iso-8859-6-i": true,
	"csiso88596e": true, "csiso88596i": true, "greek": true, "greek8": true,
	"ecma-118": true, "elot_928": true, "csisolatingreek": true, "hebrew": true,
	"csisolatinhebrew": true, "iso-8859-8-e": true, "iso-8859-8-i": true,
	"csiso88598e": true, "csiso88598i": true, "visual": true, "logical": true,
	"csisolatin9": true, "csiso885913": true, "csiso885914": true, "csiso885915": true,
	"csiso885916": true, "iso-ir-157": true, "iso-ir-226": true,
	// Windows-874
	"dos-874": true, "tis-620": true, "cp874": true,
	// KOI8
	"koi8-r": true, "koi8_r": true, "koi8": true, "koi": true, "cskoi8r": true,
	"koi8-u": true, "koi8-ru": true,
	// Shift_JIS
	"shift_jis": true, "shift-jis": true, "sjis": true, "x-sjis": true, "ms_kanji": true,
	"csshiftjis": true, "windows-31j": true, "cp932": true, "ms932": true,
	// EUC-JP
	"euc-jp": true, "eucjp": true, "x-euc-jp": true, "cseucpkdfmtjapanese": true, "ujis": true,
	// EUC-KR
	"euc-kr": true, "euckr": true, "cseuckr": true, "csksc56011987": true, "iso-ir-149": true,
	"korean": true, "ks_c_5601-1987": true, "ks_c_5601-1989": true, "ksc5601": true,
	"ksc_5601": true, "windows-949": true, "cp949": true, "uhc": true,
	// GBK, GB2312, GB18030
	"gbk": true, "x-gbk": true, "gb2312": true, "gb_2312": true, "gb_2312-80": true,
	"chinese": true, "csgb2312": true, "csiso58gb231280": true, "iso-ir-58": true,
	"cp936": true, "ms936": true, "windows-936": true, "euc-cn": true, "euccn": true,
	"gb18030": true,
	// Big5
	"big5": true, "big5-hkscs": true, "cn-big5": true, "csbig5": true, "x-x-big5": true,
}

// isoLatinName matches the ISO-8859 parts (1 to 11, 13 to 16) spelled
// iso-8859-N, iso8859-N, iso_8859-N or iso8859N, and the Latin names
// latinN, latin-N, lN and csisolatinN (N from 1 to 10).
func isoLatinName(e string) bool {
	for _, p := range [...]string{"iso-8859-", "iso8859-", "iso_8859-", "iso8859"} {
		if part, ok := strings.CutPrefix(e, p); ok && digits(part) {
			n, _ := strconv.Atoi(part)
			return n >= 1 && n <= 16 && n != 12
		}
	}
	for _, p := range [...]string{"latin-", "latin", "csisolatin", "l"} {
		if part, ok := strings.CutPrefix(e, p); ok && digits(part) {
			n, _ := strconv.Atoi(part)
			return n >= 1 && n <= 10
		}
	}
	return false
}

// windowsName matches windows-125N, cp125N and x-cp125N (N from 0 to 8)
// and windows-874.
func windowsName(e string) bool {
	if e == "windows-874" {
		return true
	}
	for _, p := range [...]string{"windows-125", "cp125", "x-cp125"} {
		if part, ok := strings.CutPrefix(e, p); ok && len(part) == 1 && part[0] >= '0' && part[0] <= '8' {
			return true
		}
	}
	return false
}

func digits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// latin1ToUTF8 turns each byte of b into the code point of the same value,
// UTF-8 encoded. b is returned unchanged when it is all ASCII.
func latin1ToUTF8(b []byte) []byte {
	high := 0
	for _, c := range b {
		if c >= utf8.RuneSelf {
			high++
		}
	}
	if high == 0 {
		return b
	}
	out := make([]byte, 0, len(b)+high)
	for _, c := range b {
		if c < utf8.RuneSelf {
			out = append(out, c)
		} else {
			out = utf8.AppendRune(out, rune(c))
		}
	}
	return out
}

// trimPartialRune drops an incomplete UTF-8 sequence at the end of b, left
// where a cut fell inside a character.
func trimPartialRune(b []byte) []byte {
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax; i-- {
		if utf8.RuneStart(b[i]) {
			if !utf8.FullRune(b[i:]) {
				return b[:i]
			}
			break
		}
	}
	return b
}

// leadingXMLDeclaration finds the XML declaration at the start of body,
// where a UTF-8 byte order mark and white space may precede it. It returns
// the length of what it skips (declaration included) and the declared
// encoding. Without a declaration it returns (0, "", true). A declaration
// that is not of the XML shape (version="1.<digits>", then optionally
// encoding, then optionally standalone="yes|no", each in matching quotes,
// with optional blanks around "=") returns ok false.
func leadingXMLDeclaration(body []byte) (n int, enc string, ok bool) {
	i := 0
	if bytes.HasPrefix(body, []byte("\ufeff")) {
		i = 3
	}
	for i < len(body) && (xmlSpace(body[i]) || body[i] == '\v' || body[i] == '\f') {
		i++
	}
	rest := body[i:]
	if !bytes.HasPrefix(rest, []byte("<?xml")) || len(rest) < 6 || !(xmlSpace(rest[5]) || rest[5] == '?') {
		return 0, "", true
	}
	end := bytes.Index(rest, []byte("?>"))
	if end < 0 {
		return 0, "", false
	}
	p := declParser{b: rest[5:end]}
	ver, ok := p.attr("version")
	if !ok || !versionNumber(ver) {
		return 0, "", false
	}
	if v, ok := p.attr("encoding"); ok {
		if !encodingName(v) {
			return 0, "", false
		}
		enc = v
	}
	if v, ok := p.attr("standalone"); ok && v != "yes" && v != "no" {
		return 0, "", false
	}
	p.space()
	if len(p.b) != 0 {
		return 0, "", false
	}
	return i + end + 2, enc, true
}

// declParser reads the pseudo-attributes of an XML declaration in order.
type declParser struct{ b []byte }

func xmlSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func (p *declParser) space() bool {
	n := 0
	for n < len(p.b) && xmlSpace(p.b[n]) {
		n++
	}
	p.b = p.b[n:]
	return n > 0
}

// attr reads ` name = "value"` (blank before the name required) and
// returns the value; on any mismatch it consumes nothing.
func (p *declParser) attr(name string) (string, bool) {
	save := p.b
	if !p.space() || !bytes.HasPrefix(p.b, []byte(name)) {
		p.b = save
		return "", false
	}
	p.b = p.b[len(name):]
	p.space()
	if len(p.b) == 0 || p.b[0] != '=' {
		p.b = save
		return "", false
	}
	p.b = p.b[1:]
	p.space()
	if len(p.b) == 0 || (p.b[0] != '"' && p.b[0] != '\'') {
		p.b = save
		return "", false
	}
	q := p.b[0]
	end := bytes.IndexByte(p.b[1:], q)
	if end < 0 {
		p.b = save
		return "", false
	}
	v := string(p.b[1 : 1+end])
	p.b = p.b[2+end:]
	return v, true
}

func versionNumber(v string) bool {
	if len(v) < 3 || v[:2] != "1." {
		return false
	}
	for i := 2; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return true
}

// encodingName reports whether v is an XML EncName: [A-Za-z][A-Za-z0-9._-]*.
func encodingName(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if !letter && (i == 0 || !(c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-')) {
			return false
		}
	}
	return v != ""
}
