package normalize

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"

	"github.com/ergasterion-dev/pylolith/internal/model"
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

// ParseMultipart parses a multipart/* body. Each non-file part's value is
// capped at lim.MaxValueLen bytes; more than lim.MaxFields parts yields
// ErrLimit. Other failures are returned as wrapped errors.
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
		p, err := r.NextRawPart()
		if err == io.EOF {
			return parts, nil
		}
		if err != nil {
			return parts, fmt.Errorf("normalize: malformed multipart: %w", err)
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
				return parts, fmt.Errorf("normalize: malformed multipart: %w", err)
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
