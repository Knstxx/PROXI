package app

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookieName = "vpnproxi_session"
	sessionTTL        = 12 * time.Hour
)

type AuthStore struct {
	path string
}

type authFile struct {
	Username      string `json:"username"`
	PasswordHash  string `json:"passwordHash"`
	SessionSecret string `json:"sessionSecret"`
	UpdatedAt     string `json:"updatedAt"`
}

type authSession struct {
	Authenticated bool   `json:"authenticated"`
	Username      string `json:"username,omitempty"`
}

func NewAuthStore(path string) *AuthStore {
	return &AuthStore{path: path}
}

func (s *AuthStore) Login(w http.ResponseWriter, r *http.Request, username, password string) error {
	cfg, err := s.load()
	if err != nil {
		return err
	}
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return errors.New("username and password are required")
	}
	if subtle.ConstantTimeCompare([]byte(username), []byte(cfg.Username)) != 1 {
		return errors.New("invalid username or password")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(cfg.PasswordHash), []byte(password)); err != nil {
		return errors.New("invalid username or password")
	}
	expires := time.Now().UTC().Add(sessionTTL)
	cookie, err := s.signedCookie(cfg, username, expires)
	if err != nil {
		return err
	}
	http.SetCookie(w, cookieWithTransport(r, cookie))
	return nil
}

func (s *AuthStore) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, cookieWithTransport(r, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}))
}

func (s *AuthStore) Session(r *http.Request) authSession {
	username, ok := s.AuthenticatedUsername(r)
	return authSession{Authenticated: ok, Username: username}
}

func (s *AuthStore) AuthenticatedUsername(r *http.Request) (string, bool) {
	cfg, err := s.load()
	if err != nil {
		return "", false
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return "", false
	}
	payload, signature, ok := strings.Cut(cookie.Value, ".")
	if !ok {
		return "", false
	}
	expected := signSession(cfg.SessionSecret, payload)
	if subtle.ConstantTimeCompare([]byte(signature), []byte(expected)) != 1 {
		return "", false
	}
	rawPayload, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", false
	}
	parts := strings.Split(string(rawPayload), "|")
	if len(parts) != 3 {
		return "", false
	}
	expiresUnix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > expiresUnix {
		return "", false
	}
	if parts[0] != cfg.Username {
		return "", false
	}
	return parts[0], true
}

func (s *AuthStore) signedCookie(cfg authFile, username string, expires time.Time) (*http.Cookie, error) {
	nonce, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	rawPayload := fmt.Sprintf("%s|%d|%s", username, expires.Unix(), nonce)
	payload := base64.RawURLEncoding.EncodeToString([]byte(rawPayload))
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    payload + "." + signSession(cfg.SessionSecret, payload),
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}, nil
}

func (s *AuthStore) load() (authFile, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return authFile{}, err
	}
	var cfg authFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return authFile{}, err
	}
	if cfg.Username == "" || cfg.PasswordHash == "" || cfg.SessionSecret == "" {
		return authFile{}, errors.New("admin credentials are incomplete")
	}
	return cfg, nil
}

func WriteAuthFile(path, username, password string) error {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return errors.New("username and password are required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	secret, err := randomHex(32)
	if err != nil {
		return err
	}
	cfg := authFile{
		Username:      username,
		PasswordHash:  string(hash),
		SessionSecret: secret,
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func randomHex(bytesLen int) (string, error) {
	buf := make([]byte, bytesLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func signSession(secret, payload string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func cookieWithTransport(r *http.Request, cookie *http.Cookie) *http.Cookie {
	next := *cookie
	next.Secure = r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	return &next
}
