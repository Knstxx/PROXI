package app

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"vpnproxi/internal/link"
	"vpnproxi/internal/system"
)

type Options struct {
	StatePath    string
	LogPath      string
	TrafficPath  string
	StaticFS     fs.FS
	ApplyEnabled bool
	AdminToken   string
	AuthPath     string
}

type Service struct {
	store        *Store
	staticFS     fs.FS
	applyEnabled bool
	adminToken   string
	authStore    *AuthStore
	activityLog  *ActivityLog
	trafficStore *TrafficStore
	stopTraffic  chan struct{}
}

func NewService(opts Options) (*Service, error) {
	store := NewStore(opts.StatePath)
	if _, err := store.Load(); err != nil {
		return nil, err
	}
	staticFS, err := fs.Sub(opts.StaticFS, "static")
	if err == nil {
		opts.StaticFS = staticFS
	}
	var authStore *AuthStore
	if opts.AuthPath != "" {
		if _, err := os.Stat(opts.AuthPath); err == nil {
			authStore = NewAuthStore(opts.AuthPath)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		} else if opts.ApplyEnabled && opts.AdminToken == "" {
			return nil, errors.New("admin credentials are missing; create them with --create-admin or set VPNPROXI_ADMIN_TOKEN")
		}
	}
	svc := &Service{
		store: store, staticFS: opts.StaticFS, applyEnabled: opts.ApplyEnabled, adminToken: opts.AdminToken, authStore: authStore, activityLog: NewActivityLog(opts.LogPath),
		stopTraffic: make(chan struct{}),
	}
	if opts.ApplyEnabled && opts.TrafficPath != "" {
		svc.trafficStore = NewTrafficStore(opts.TrafficPath)
		go svc.trafficStore.Collect(5*time.Second, svc.stopTraffic)
	}
	return svc, nil
}

func (s *Service) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", s.loginHandler)
	mux.HandleFunc("/api/logout", s.logoutHandler)
	mux.HandleFunc("/api/session", s.sessionHandler)
	mux.HandleFunc("/api/state", s.requireAuth(s.stateHandler))
	mux.HandleFunc("/api/probe-link", s.requireAuth(s.probeLinkHandler))
	mux.HandleFunc("/api/apply", s.requireAuth(s.applyHandler))
	mux.HandleFunc("/api/reset-traffic", s.requireAuth(s.resetTrafficHandler))
	mux.HandleFunc("/api/status", s.requireAuth(s.statusHandler))
	mux.HandleFunc("/api/logs", s.requireAuth(s.logsHandler))
	mux.Handle("/", http.FileServer(http.FS(s.staticFS)))
	return secureHeaders(noStore(mux))
}

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || r.Method == http.MethodGet || r.Method == http.MethodHead {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		}
		next.ServeHTTP(w, r)
	})
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'")
		next.ServeHTTP(w, r)
	})
}

func (s *Service) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.authStore == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("password login is not configured"))
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.authStore.Login(w, r, body.Username, body.Password); err != nil {
		s.activityLog.Event("auth.login.failed", "admin login failed", map[string]any{"username": body.Username, "remote": r.RemoteAddr})
		writeError(w, http.StatusUnauthorized, errors.New("invalid username or password"))
		return
	}
	s.activityLog.Event("auth.login", "admin logged in", map[string]any{"username": strings.TrimSpace(body.Username), "remote": r.RemoteAddr})
	writeJSON(w, map[string]any{"ok": true, "username": strings.TrimSpace(body.Username)}, nil)
}

func (s *Service) logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.authStore != nil {
		s.authStore.Logout(w, r)
	}
	writeJSON(w, map[string]any{"ok": true}, nil)
}

func (s *Service) sessionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.authStore == nil && s.adminToken == "" {
		writeJSON(w, map[string]any{"authenticated": true, "username": "local"}, nil)
		return
	}
	if s.authStore == nil {
		writeJSON(w, map[string]any{"authenticated": false}, nil)
		return
	}
	writeJSON(w, s.authStore.Session(r), nil)
}

func (s *Service) stateHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		state, err := s.store.Load()
		s.activityLog.Event("state.read", "state loaded", nil)
		writeJSON(w, state, err)
	case http.MethodPut:
		var state State
		if err := json.NewDecoder(r.Body).Decode(&state); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		state = normalizeState(state)
		if state.Outbound != nil {
			state.Outbound.Tag = "proxy-primary"
		}
		if state.Outbound != nil {
			if err := ValidateState(state); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
		}
		err := s.store.Save(state)
		s.activityLog.Event("state.write", "state saved", map[string]any{"hasOutbound": state.Outbound != nil, "users": len(state.Server.Users)})
		writeJSON(w, map[string]any{"ok": true}, err)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Service) probeLinkHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Link string `json:"link"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(body.Link) > 32_768 {
		writeError(w, http.StatusBadRequest, errors.New("link is too large"))
		return
	}
	out, err := link.Parse(body.Link)
	if err != nil {
		s.activityLog.Event("link.parse.error", "share link parse failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadRequest, err)
		return
	}
	probe := link.Probe(out, 4*time.Second)
	fields := map[string]any{
		"protocol": out.Protocol,
		"tag":      out.Tag,
		"network":  probe.Network,
		"host":     probe.Host,
		"port":     probe.Port,
		"ok":       probe.OK,
	}
	if probe.Error != "" {
		fields["error"] = probe.Error
		s.activityLog.Event("link.probe.failed", "external route check failed", fields)
	} else {
		s.activityLog.Event("link.probe", "external route checked", fields)
	}
	writeJSON(w, map[string]any{"outbound": out, "probe": probe}, nil)
}

func (s *Service) applyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.applyEnabled {
		writeError(w, http.StatusForbidden, errors.New("apply disabled"))
		return
	}
	state, err := s.store.Load()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := ValidateState(state); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := system.Apply(state)
	if err == nil {
		s.activityLog.Event("apply", "host apply completed", map[string]any{"changedFiles": len(result.ChangedFiles), "warnings": len(result.Warnings)})
	} else {
		s.activityLog.Event("apply.error", "host apply failed", map[string]any{"error": err.Error()})
	}
	writeJSON(w, result, err)
}

func (s *Service) statusHandler(w http.ResponseWriter, r *http.Request) {
	status := system.Status()
	status["applyEnabled"] = s.applyEnabled
	if state, err := s.store.Load(); err == nil {
		status["routingMode"] = state.Routes.Mode
		for key, value := range system.GeodataStatus(state) {
			status[key] = value
		}
		if s.trafficStore != nil {
			if stats, err := s.trafficStore.Update(stringValue(status["xrayStats"]), stringValue(status["forwardCounters"])); err == nil {
				status["xrayStats"] = stats
			}
		}
	}
	writeJSON(w, status, nil)
}

func (s *Service) resetTrafficHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := system.ResetTraffic(); err != nil {
		s.activityLog.Event("traffic.reset.failed", "client traffic counters reset failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if s.trafficStore != nil {
		if err := s.trafficStore.Reset(); err != nil {
			s.activityLog.Event("traffic.reset.failed", "persistent traffic counters reset failed", map[string]any{"error": err.Error()})
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	s.activityLog.Event("traffic.reset", "client traffic counters reset", nil)
	writeJSON(w, map[string]any{"ok": true}, nil)
}

func (s *Service) logsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]any{"lines": s.activityLog.Tail(240)}, nil)
}

func (s *Service) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authStore == nil && s.adminToken == "" {
			next(w, r)
			return
		}
		if s.authStore != nil {
			if _, ok := s.authStore.AuthenticatedUsername(r); ok {
				next(w, r)
				return
			}
		}
		token := r.Header.Get("X-Admin-Token")
		if token == "" {
			token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if s.adminToken == "" || token != s.adminToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("401\n"))
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any, err error) {
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func stringValue(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	default:
		return ""
	}
}
