package normalize

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/ergasterion-dev/aegolith/internal/model"
)

// ErrLimit means a configured inspection limit was exceeded.
var ErrLimit = errors.New("normalize: limit exceeded")

// ErrMalformed means the JSON body has a syntax error.
var ErrMalformed = errors.New("normalize: malformed JSON")

// JSONValue is one string, number or boolean value (or one object key) found
// in a JSON document. Path is dotted with arrays as "[]" (for example
// "items[].sku"); Key is the last object key, empty for array elements. For
// an object key, IsKey is true, Value is the key itself and IsString is true.
// When an object or array starts, IsContainer is true, Path is the path of
// that value (before any "[]") and Value is empty; this lets a caller see a
// container where it expects a scalar, including an empty one.
type JSONValue struct {
	Path, Key, Value string
	IsString         bool
	IsKey            bool
	IsContainer      bool
}

type jsonFrame struct {
	isObj     bool
	expectKey bool   // objects: next string token is a key
	key       string // objects: current key
	base      int    // path length when this frame was entered
}

// WalkJSON streams body through a token decoder and calls fn for every
// string, number and boolean value, once per object key and once at the
// start of every object or array. Nesting beyond
// lim.MaxDepth or more than lim.MaxFields emitted items yields ErrLimit; a
// syntax error yields ErrMalformed. Values emitted before an error stay
// emitted. It uses an explicit stack, so depth cannot exhaust the call stack.
func WalkJSON(body []byte, lim model.Limits, fn func(JSONValue)) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()

	var (
		stack  []jsonFrame
		path   []byte
		count  int
		topSet bool // a complete top-level value has been read
	)

	emitValue := func(v JSONValue) error {
		if count >= lim.MaxFields {
			return ErrLimit
		}
		count++
		v.Path = string(path)
		fn(v)
		return nil
	}
	emit := func(key, val string, isString, isKey bool) error {
		return emitValue(JSONValue{Key: key, Value: val, IsString: isString, IsKey: isKey})
	}
	// valueDone marks the current value complete in its parent frame.
	valueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].isObj {
			stack[n-1].expectKey = true
		} else if n == 0 {
			topSet = true
		}
	}

	for {
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF && len(stack) == 0 && topSet {
				return nil
			}
			return ErrMalformed
		}
		if topSet && len(stack) == 0 {
			return ErrMalformed // trailing data after the top-level value
		}

		var top *jsonFrame
		if n := len(stack); n > 0 {
			top = &stack[n-1]
		}

		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				if len(stack)+1 > lim.MaxDepth {
					return ErrLimit
				}
				if err := emitValue(JSONValue{Key: curKey(top), IsContainer: true}); err != nil {
					return err
				}
				stack = append(stack, jsonFrame{isObj: v == '{', expectKey: v == '{', base: len(path)})
				if v == '[' {
					path = append(path, "[]"...)
				}
			default: // '}' or ']'
				f := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				path = path[:f.base]
				valueDone()
			}
		case string:
			if top != nil && top.isObj && top.expectKey {
				top.expectKey = false
				top.key = v
				path = path[:top.base]
				if top.base > 0 {
					path = append(path, '.')
				}
				path = append(path, v...)
				if err := emit(v, v, true, true); err != nil {
					return err
				}
				continue
			}
			if err := emit(curKey(top), v, true, false); err != nil {
				return err
			}
			valueDone()
		case json.Number:
			if err := emit(curKey(top), v.String(), false, false); err != nil {
				return err
			}
			valueDone()
		case bool:
			s := "false"
			if v {
				s = "true"
			}
			if err := emit(curKey(top), s, false, false); err != nil {
				return err
			}
			valueDone()
		case nil:
			valueDone()
		}
	}
}

func curKey(f *jsonFrame) string {
	if f != nil && f.isObj {
		return f.key
	}
	return ""
}
