package remote

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGuardCheck(t *testing.T) {
	t.Parallel()
	target := validTarget()
	e := target.Allow[1] // benign 200 and 201
	tests := []struct {
		status int
		benign bool
		stop   bool
		want   string
	}{
		{200, true, false, ""},
		{201, true, false, ""},
		{204, true, true, "204"},
		{403, true, true, "403"},
		{403, false, false, ""},
		{404, false, false, ""},
		{429, false, true, "429"},
		{500, false, true, "500"},
		{503, true, true, "503"},
		{0, true, true, "control"},
	}
	for _, tc := range tests {
		g := &Guard{Target: target}
		stop, reason := g.Check(tc.status, tc.benign, e)
		if stop != tc.stop || !strings.Contains(reason, tc.want) {
			t.Errorf("Check(%d, %v) = %v, %q", tc.status, tc.benign, stop, reason)
		}
	}
	g := &Guard{Target: target}
	for i, status := range []int{302, 0, 200, 301, 0, 307} {
		stop, reason := g.Check(status, false, e)
		if stop != (i == 5) {
			t.Errorf("request %d (%d): stop %v, %q", i, status, stop, reason)
		}
	}
}

func TestGuardExternal(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	g := &Guard{StopFile: filepath.Join(dir, "stop"), HeartbeatFile: filepath.Join(dir, "beat")}
	if stop, reason := g.External(now); !stop || !strings.Contains(reason, "heartbeat") {
		t.Errorf("missing heartbeat: %v, %q", stop, reason)
	}
	if err := os.WriteFile(g.HeartbeatFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for age, want := range map[time.Duration]bool{0: false, 30 * time.Second: false, 30*time.Second + time.Millisecond: true, time.Hour: true} {
		if err := os.Chtimes(g.HeartbeatFile, now, now.Add(-age)); err != nil {
			t.Fatal(err)
		}
		if stop, _ := g.External(now); stop != want {
			t.Errorf("heartbeat %s old: stop %v", age, stop)
		}
	}
	if err := os.Chtimes(g.HeartbeatFile, now, now); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(g.StopFile, 0o700); err != nil { // any kind of file
		t.Fatal(err)
	}
	if stop, reason := g.External(now); !stop || !strings.Contains(reason, "stop file") {
		t.Errorf("stop file: %v, %q", stop, reason)
	}
	none := &Guard{}
	if stop, reason := none.External(now); stop {
		t.Errorf("no files: %q", reason)
	}
}
