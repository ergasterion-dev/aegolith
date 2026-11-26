// Package target is the server the bench sends cases to: a backend that
// answers 200 to everything, wrapped by the Aegolith net/http middleware,
// with an access log and a decision log joined by the X-Request-Id header.
package target

import (
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
	// A failed Writer fails every later record, so only the first failure is
	// reported.
	reportFailure sync.Once
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
	// The hook is bound to this request, so that a lost decision record can
	// withhold this request's access record.
	lost := false
	waf := httpwaf.Middleware(s.fw, httpwaf.Options{
		OnDecision: func(_ *aegolith.Request, d aegolith.Decision) {
			if err := s.decisions.Write(decisionRecord(id, d)); err != nil {
				lost = true
				s.report("decision", err)
			}
		},
	})
	waf(http.HandlerFunc(backend)).ServeHTTP(w, r)
	if lost {
		return
	}
	if err := s.access.Write(access); err != nil {
		s.report("access", err)
	}
}

func (s *server) report(log string, err error) {
	s.reportFailure.Do(func() {
		slog.Error("target: records are being lost", "log", log, "error", err)
	})
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
