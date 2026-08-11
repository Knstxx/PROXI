package app

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	loginAttemptLimit  = 5
	loginAttemptWindow = 10 * time.Minute
	loginClientLimit   = 4096
)

type loginAttempt struct {
	count   int
	expires time.Time
}

type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]loginAttempt
	now      func() time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{attempts: make(map[string]loginAttempt), now: time.Now}
}

func (l *loginLimiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	for client, candidate := range l.attempts {
		if !now.Before(candidate.expires) {
			delete(l.attempts, client)
		}
	}
	if _, exists := l.attempts[key]; !exists && len(l.attempts) >= loginClientLimit {
		return false, loginAttemptWindow
	}
	attempt := l.attempts[key]
	if attempt.expires.IsZero() || !now.Before(attempt.expires) {
		attempt = loginAttempt{expires: now.Add(loginAttemptWindow)}
	}
	if attempt.count >= loginAttemptLimit {
		return false, attempt.expires.Sub(now)
	}
	attempt.count++
	l.attempts[key] = attempt
	return true, 0
}

func (l *loginLimiter) Reset(key string) {
	l.mu.Lock()
	delete(l.attempts, key)
	l.mu.Unlock()
}

func requestClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	remoteIP := net.ParseIP(host)
	if remoteIP != nil && remoteIP.IsLoopback() {
		if forwardedIP := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); forwardedIP != nil {
			return forwardedIP.String()
		}
	}
	if remoteIP != nil {
		return remoteIP.String()
	}
	if host != "" {
		return host
	}
	return "unknown"
}
