package app

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func TestRoutesApplySecurityAndNoStoreHeaders(t *testing.T) {
	t.Parallel()

	staticFS := fstest.MapFS{
		"static/index.html": &fstest.MapFile{Data: []byte("<!doctype html><html><body>ok</body></html>")},
	}
	svc, err := NewService(Options{
		StatePath:    filepath.Join(t.TempDir(), "state.json"),
		LogPath:      filepath.Join(t.TempDir(), "vpnproxi.log"),
		StaticFS:     fs.FS(staticFS),
		ApplyEnabled: false,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	svc.Routes().ServeHTTP(rec, req)

	if got := rec.Header().Get("Cache-Control"); got != "no-store, no-cache, must-revalidate" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy = %q", got)
	}
	if got := rec.Header().Get("Cross-Origin-Opener-Policy"); got != "same-origin" {
		t.Fatalf("Cross-Origin-Opener-Policy = %q", got)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("Content-Security-Policy = %q", csp)
	}
}
