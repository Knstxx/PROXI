package app

import (
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestAuthStoreLoginSessionAndLogout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.json")
	if err := WriteAuthFile(path, "admin", "secret-password"); err != nil {
		t.Fatal(err)
	}

	store := NewAuthStore(path)
	loginReq := httptest.NewRequest("POST", "https://vpnproxi.test/api/login", nil)
	loginReq.Header.Set("X-Forwarded-Proto", "https")
	loginRes := httptest.NewRecorder()
	if err := store.Login(loginRes, loginReq, "admin", "secret-password"); err != nil {
		t.Fatal(err)
	}
	cookies := loginRes.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one session cookie, got %d", len(cookies))
	}
	if !cookies[0].HttpOnly {
		t.Fatal("session cookie must be HttpOnly")
	}
	if !cookies[0].Secure {
		t.Fatal("session cookie must be Secure behind HTTPS")
	}

	sessionReq := httptest.NewRequest("GET", "https://vpnproxi.test/api/state", nil)
	sessionReq.AddCookie(cookies[0])
	username, ok := store.AuthenticatedUsername(sessionReq)
	if !ok || username != "admin" {
		t.Fatalf("expected authenticated admin, got username=%q ok=%v", username, ok)
	}

	logoutReq := httptest.NewRequest("POST", "https://vpnproxi.test/api/logout", nil)
	logoutReq.Header.Set("X-Forwarded-Proto", "https")
	logoutRes := httptest.NewRecorder()
	store.Logout(logoutRes, logoutReq)
	logoutCookie := logoutRes.Result().Cookies()[0]
	if logoutCookie.MaxAge >= 0 {
		t.Fatalf("expected clearing cookie, got MaxAge=%d", logoutCookie.MaxAge)
	}
}
