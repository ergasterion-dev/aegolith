package normalize

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"

	"github.com/ergasterion-dev/aegolith/internal/model"
)

// Part is one multipart form part. File parts (those with a filename) are
// never read: IsFile is true and Value is empty.
type Part struct {
	Name   string
	IsFile bool
	Value  string
	// Truncated is true when a non-file value exceeded Limits.MaxValueLen
	// and was cut.
	Truncated bool
}

// ParseMultipart parses a multipart/* body. Parts are read the way
// net/http's ReadForm reads them (NextPart), so a quoted-printable
// Content-Transfer-Encoding is decoded before inspection. Each non-file part's value is
// capped at lim.MaxValueLen bytes; more than lim.MaxFields parts yields
// ErrLimit. Other failures are returned as wrapped errors; one that comes
// only from the input ending inside the last part (see incomplete) also
// wraps ErrIncomplete.
func ParseMultipart(body []byte, contentType string, lim model.Limits) ([]Part, error) {
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, fmt.Errorf("normalize: bad multipart content type: %w", err)
	}
	if len(mt) < 10 || mt[:10] != "multipart/" {
		return nil, fmt.Errorf("normalize: content type %q is not multipart", mt)
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil, errors.New("normalize: multipart boundary missing")
	}

	r := multipart.NewReader(bytes.NewReader(body), boundary)
	var parts []Part
	for {
		p, err := r.NextPart()
		if err == io.EOF {
			return parts, nil
		}
		if err != nil {
			return parts, malformedMultipart(err, body, boundary, len(parts))
		}
		if len(parts) >= lim.MaxFields {
			return parts, ErrLimit
		}
		part := Part{Name: p.FormName()}
		if p.FileName() != "" {
			part.IsFile = true
		} else {
			val, err := io.ReadAll(io.LimitReader(p, int64(lim.MaxValueLen)+1))
			if err != nil {
				return parts, malformedMultipart(err, body, boundary, len(parts))
			}
			if len(val) > lim.MaxValueLen {
				val = val[:lim.MaxValueLen]
				part.Truncated = true
			}
			part.Value = string(val)
		}
		parts = append(parts, part)
	}
}

// malformedMultipart wraps a parse error, adding ErrIncomplete when the
// failure comes only from the input ending inside its last part (failed is
// the index of the part being read when err occurred). mime/multipart
// reports an end inside a part's content as an unexpected EOF, but an end
// inside a part's header block as a malformed header ("missing colon" on
// the partial line), so that case is recognised by position: the failing
// part follows the body's last delimiter and the bytes after that
// delimiter hold no blank line, so its header block never ended. A real
// header error in an earlier part, or in a last part whose header block is
// complete, stays plain malformed.
func malformedMultipart(err error, body []byte, boundary string, failed int) error {
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return fmt.Errorf("normalize: malformed multipart: %w (%w)", err, ErrIncomplete)
	}
	delim := []byte("--" + boundary)
	last := bytes.LastIndex(body, append([]byte("\n"), delim...))
	switch {
	case last >= 0:
		last++ // skip the newline
	case bytes.HasPrefix(body, delim):
		last = 0
	default:
		return fmt.Errorf("normalize: malformed multipart: %w", err)
	}
	// Part i (0-based) follows delimiter i, so the part after the last
	// delimiter has index (number of delimiters - 1). Delimiters are the
	// "\n--boundary" lines plus a "--boundary" at the very start.
	n := bytes.Count(body, append([]byte("\n"), delim...))
	if !bytes.HasPrefix(body, delim) {
		n--
	}
	tail := body[last+len(delim):]
	if failed == n && !bytes.Contains(tail, []byte("\n\r\n")) && !bytes.Contains(tail, []byte("\n\n")) {
		return fmt.Errorf("normalize: malformed multipart: %w (%w)", err, ErrIncomplete)
	}
	return fmt.Errorf("normalize: malformed multipart: %w", err)
}
