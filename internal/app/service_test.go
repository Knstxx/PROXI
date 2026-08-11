package app

import (
	"bytes"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func TestLoginRateLimitUsesTrustedProxyClientIP(t *testing.T) {
	t.Parallel()

	authPath := filepath.Join(t.TempDir(), "admin.json")
	if err := WriteAuthFile(authPath, "admin", "correct-password"); err != nil {
		t.Fatal(err)
	}
	staticFS := fstest.MapFS{
		"static/index.html": &fstest.MapFile{Data: []byte("ok")},
	}
	svc, err := NewService(Options{
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		LogPath:   filepath.Join(t.TempDir(), "vpnproxi.log"),
		StaticFS:  fs.FS(staticFS),
		AuthPath:  authPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := svc.Routes()

	for attempt := 1; attempt <= loginAttemptLimit; attempt++ {
		req := httptest.NewRequest(http.MethodPost, "https://vpnproxi.test/api/login", bytes.NewBufferString(`{"username":"admin","password":"wrong"}`))
		req.RemoteAddr = "127.0.0.1:54321"
		req.Header.Set("X-Real-IP", "203.0.113.10")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want %d", attempt, rec.Code, http.StatusUnauthorized)
		}
	}

	blocked := httptest.NewRequest(http.MethodPost, "https://vpnproxi.test/api/login", bytes.NewBufferString(`{"username":"admin","password":"wrong"}`))
	blocked.RemoteAddr = "127.0.0.1:54321"
	blocked.Header.Set("X-Real-IP", "203.0.113.10")
	blockedRec := httptest.NewRecorder()
	handler.ServeHTTP(blockedRec, blocked)
	if blockedRec.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked status = %d, want %d", blockedRec.Code, http.StatusTooManyRequests)
	}
	if blockedRec.Header().Get("Retry-After") == "" {
		t.Fatal("rate-limited response is missing Retry-After")
	}

	otherClient := httptest.NewRequest(http.MethodPost, "https://vpnproxi.test/api/login", bytes.NewBufferString(`{"username":"admin","password":"correct-password"}`))
	otherClient.RemoteAddr = "127.0.0.1:54321"
	otherClient.Header.Set("X-Real-IP", "203.0.113.11")
	otherRec := httptest.NewRecorder()
	handler.ServeHTTP(otherRec, otherClient)
	if otherRec.Code != http.StatusOK {
		t.Fatalf("other client status = %d, want %d", otherRec.Code, http.StatusOK)
	}
}

func TestRequestClientIPOnlyTrustsLoopbackProxy(t *testing.T) {
	t.Parallel()

	proxied := httptest.NewRequest(http.MethodGet, "https://vpnproxi.test/", nil)
	proxied.RemoteAddr = "127.0.0.1:1234"
	proxied.Header.Set("X-Real-IP", "203.0.113.20")
	if got := requestClientIP(proxied); got != "203.0.113.20" {
		t.Fatalf("proxied client IP = %q", got)
	}

	direct := httptest.NewRequest(http.MethodGet, "https://vpnproxi.test/", nil)
	direct.RemoteAddr = "198.51.100.30:4321"
	direct.Header.Set("X-Real-IP", "203.0.113.99")
	if got := requestClientIP(direct); got != "198.51.100.30" {
		t.Fatalf("direct client IP = %q", got)
	}
}

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
