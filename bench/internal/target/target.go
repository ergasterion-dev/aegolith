// Package target is the server the bench sends cases to: a backend that
// answers 200 to everything, wrapped by the Aegolith net/http middleware,
// with an access log and a decision log joined by the X-Request-Id header.
package target

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/ergasterion-dev/aegolith"
	"github.com/ergasterion-dev/aegolith/bench/internal/records"
	"github.com/ergasterion-dev/aegolith/httpwaf"
)

const requestIDHeader = "X-Request-Id"

// Bounds on what a record takes from a request.
const (
	// maxIDLen leaves room for a run prefix before a 64 character case ID.
	maxIDLen     = 128
	maxMethodLen = 64
	maxPathLen   = 256
	maxErrorLen  = 128
)

// maxEchoedIDLen is the longest request ID the middleware puts in its block
// answer.
const maxEchoedIDLen = 64

// inspectionFailed marks the decision record of a request blocked because
// inspecting it panicked.
const inspectionFailed = "inspection failed"

// Config configures the target.
type Config struct {
	// Mode is the firewall's mode. It overrides the mode in the policy file.
	Mode aegolith.Mode
	// PolicyPath is an Aegolith configuration file; empty means no routes.
	PolicyPath string
	// Access and Decisions receive the two logs. Both are required.
	Access, Decisions *records.Writer
}

// Handler returns the target. A request is recorded only if its X-Request-Id
// is 1 to 128 characters of A-Z, a-z, 0-9, ".", "_" and "-"; any other
// request is inspected and answered the same way but leaves no record.
//
// The decision record is written while the request is inspected and the access
// record after it has been answered, so an interrupted request never leaves an
// access record without its decision. If the decision record cannot be
// written, the access record is withheld too.
//
// If inspection itself panics, the middleware reports no decision. A firewall
// that fails closed blocks the request, which is recorded as a block with no
// rules and the error "inspection failed". A firewall that fails open (the
// default) passes it on, and nothing here can tell that apart from a clean
// allow: it leaves an access record and no decision.
func Handler(cfg Config) (http.Handler, error) {
	if cfg.Access == nil || cfg.Decisions == nil {
		return nil, errors.New("target: the access and decision writers are required")
	}
	var waf aegolith.Config
	if cfg.PolicyPath != "" {
		loaded, err := aegolith.LoadConfig(cfg.PolicyPath)
		if err != nil {
			return nil, fmt.Errorf("target: loading policy: %w", err)
		}
		waf = loaded
	}
	waf.Mode = cfg.Mode
	fw, err := aegolith.New(waf)
	if err != nil {
		return nil, fmt.Errorf("target: building firewall: %w", err)
	}
	s := &server{
		fw:         fw,
		unrecorded: httpwaf.Middleware(fw, httpwaf.Options{})(http.HandlerFunc(backend)),
		access:     cfg.Access,
		decisions:  cfg.Decisions,
	}
	return http.HandlerFunc(s.serve), nil
}

type server struct {
	fw                *aegolith.Firewall
	unrecorded        http.Handler // for a request that cannot be joined
	access, decisions *records.Writer
	// A failed Writer fails every later record, so only the first failure of
	// each log is reported.
	accessFailure, decisionFailure sync.Once
}

func (s *server) serve(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get(requestIDHeader)
	if !validID(id) {
		s.unrecorded.ServeHTTP(w, r)
		return
	}
	access := records.Access{
		ID:     id,
		Method: clip(r.Method, maxMethodLen),
		Path:   clip(r.URL.EscapedPath(), maxPathLen),
		Time:   time.Now().UTC(),
	}
	// The middleware options are bound to this request, so that a lost
	// decision record can withhold this request's access record.
	var decided, blocked, lost bool
	record := func(d records.Decision) {
		if err := s.decisions.Write(d); err != nil {
			lost = true
			report(&s.decisionFailure, "decision", err)
		}
	}
	waf := httpwaf.Middleware(s.fw, httpwaf.Options{
		OnDecision: func(_ *aegolith.Request, d aegolith.Decision) {
			decided = true
			record(decisionRecord(id, d))
		},
		BlockHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			blocked = true
			writeBlocked(w, id)
		}),
	})
	waf(http.HandlerFunc(backend)).ServeHTTP(w, r)
	// A block the hook never saw: inspection panicked and the firewall fails
	// closed. With no decision record it would read as passed.
	if blocked && !decided {
		record(records.Decision{
			ID:     id,
			Action: aegolith.ActionBlock.String(),
			Rules:  []string{},
			Error:  inspectionFailed,
		})
	}
	if lost {
		return
	}
	if err := s.access.Write(access); err != nil {
		report(&s.accessFailure, "access", err)
	}
}

func report(once *sync.Once, log string, err error) {
	once.Do(func() {
		slog.Error("target: records are being lost", "log", log, "error", err)
	})
}

// writeBlocked gives the answer of the middleware's default block handler,
// which a BlockHandler replaces and the library does not export: 403 with the
// request ID, or a random one if the ID is too long to echo.
func writeBlocked(w http.ResponseWriter, id string) {
	if len(id) > maxEchoedIDLen {
		var b [8]byte
		_, _ = rand.Read(b[:]) // crypto/rand.Read does not return an error
		id = hex.EncodeToString(b[:])
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	// The only failure left is a client that went away.
	_ = json.NewEncoder(w).Encode(struct {
		Error     string `json:"error"`
		RequestID string `json:"request_id"`
	}{"request blocked", id})
}

// backend stands for the protected application. It reads the body, as an
// application would, so that a client still sending one gets the answer.
func backend(w http.ResponseWriter, r *http.Request) {
	// A body that cannot be read changes nothing: the answer is always 200.
	_, _ = io.Copy(io.Discard, r.Body)
	w.WriteHeader(http.StatusOK)
}

// decisionRecord keeps the rule IDs of d and nothing taken from the request.
func decisionRecord(id string, d aegolith.Decision) records.Decision {
	rules := make([]string, 0, len(d.Matches))
	for _, m := range d.Matches {
		rules = append(rules, m.RuleID)
	}
	slices.Sort(rules)
	out := records.Decision{
		ID:        id,
		Action:    d.Action.String(),
		Monitored: d.Monitored,
		Rules:     slices.Compact(rules),
		Route:     d.Route,
		LatencyUS: d.Duration.Microseconds(),
	}
	if d.Err != nil {
		out.Error = clip(d.Err.Error(), maxErrorLen)
	}
	return out
}

func validID(s string) bool {
	if s == "" || len(s) > maxIDLen {
		return false
	}
	for i := range len(s) {
		switch c := s[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// AdminHandler serves GET /health and GET /memstats, the target's live heap
// and the memory it holds from the system, in bytes. It belongs on its own
// listener, where no firewall and no record is involved.
func AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /memstats", func(w http.ResponseWriter, _ *http.Request) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		w.Header().Set("Content-Type", "application/json")
		stats := struct {
			HeapAlloc uint64 `json:"heap_alloc"`
			Sys       uint64 `json:"sys"`
		}{m.HeapAlloc, m.Sys}
		// The only failure left is a client that went away.
		_ = json.NewEncoder(w).Encode(stats)
	})
	return mux
}
