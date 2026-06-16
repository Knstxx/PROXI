package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Store struct {
	path string
	mu   sync.Mutex
}

func NewStore(path string) *Store {
	return &Store{path: path}
}

func (s *Store) Load() (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *Store) Save(next State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next.UpdatedAt = time.Now().UTC()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) loadLocked() (State, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		state := DefaultState()
		return state, nil
	}
	if err != nil {
		return State{}, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, err
	}
	return normalizeState(state), nil
}

func normalizeState(state State) State {
	def := DefaultState()
	if state.Server.VPNSubnet == "" {
		state.Server.VPNSubnet = def.Server.VPNSubnet
	}
	if len(state.Server.VPNDNSServers) == 0 {
		state.Server.VPNDNSServers = def.Server.VPNDNSServers
	}
	if state.Server.CertFile == "" {
		state.Server.CertFile = def.Server.CertFile
	}
	if state.Server.KeyFile == "" {
		state.Server.KeyFile = def.Server.KeyFile
	}
	if state.Server.CAFile == "" {
		state.Server.CAFile = def.Server.CAFile
	}
	if state.Server.XrayConfigPath == "" {
		state.Server.XrayConfigPath = def.Server.XrayConfigPath
	}
	if state.Server.SwanctlPath == "" {
		state.Server.SwanctlPath = def.Server.SwanctlPath
	}
	if state.Server.UpdownPath == "" {
		state.Server.UpdownPath = def.Server.UpdownPath
	}
	if state.Server.GeodataDir == "" {
		state.Server.GeodataDir = def.Server.GeodataDir
	}
	if state.Server.TProxyPort == 0 {
		state.Server.TProxyPort = def.Server.TProxyPort
	}
	if state.Server.TProxyMark == "" {
		state.Server.TProxyMark = def.Server.TProxyMark
	}
	if state.Server.TProxyTable == 0 {
		state.Server.TProxyTable = def.Server.TProxyTable
	}
	if state.Server.UsersCSVPath == "" {
		state.Server.UsersCSVPath = def.Server.UsersCSVPath
	}
	if len(state.Server.Users) == 0 {
		state.Server.Users = def.Server.Users
	}
	if state.Routes.Mode == "" {
		state.Routes.Mode = def.Routes.Mode
	}
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = time.Now().UTC()
	}
	return state
}
