package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpnproxi/internal/system"
)

type TrafficStore struct {
	path string
	mu   sync.Mutex
}

type trafficData struct {
	Last      map[string]uint64 `json:"last"`
	Total     map[string]uint64 `json:"total"`
	UpdatedAt time.Time         `json:"updatedAt"`
}

type xrayStatItem struct {
	Name  string `json:"name"`
	Value uint64 `json:"value"`
}

func NewTrafficStore(path string) *TrafficStore {
	return &TrafficStore{path: path}
}

func (s *TrafficStore) Update(rawXray, rawForward string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.loadLocked()
	if err != nil {
		return "", err
	}
	current := parseTrafficCounters(rawXray)
	for name, value := range parseForwardCounters(rawForward) {
		current[name] += value
	}
	if data.Last == nil {
		data.Last = map[string]uint64{}
	}
	if data.Total == nil {
		data.Total = map[string]uint64{}
	}
	for name, value := range current {
		last := data.Last[name]
		if value >= last {
			data.Total[name] += value - last
		} else {
			data.Total[name] += value
		}
		data.Last[name] = value
	}
	data.UpdatedAt = time.Now().UTC()
	if err := s.saveLocked(data); err != nil {
		return "", err
	}
	return encodeTrafficStats(data.Total), nil
}

func (s *TrafficStore) Snapshot() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.loadLocked()
	if err != nil {
		return "", err
	}
	return encodeTrafficStats(data.Total), nil
}

func (s *TrafficStore) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked(trafficData{
		Last:      map[string]uint64{},
		Total:     map[string]uint64{},
		UpdatedAt: time.Now().UTC(),
	})
}

func (s *TrafficStore) Collect(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			snapshot := system.TrafficSnapshot()
			_, _ = s.Update(snapshot["xrayStats"], snapshot["forwardCounters"])
		case <-stop:
			return
		}
	}
}

func (s *TrafficStore) loadLocked() (trafficData, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return trafficData{Last: map[string]uint64{}, Total: map[string]uint64{}}, nil
	}
	if err != nil {
		return trafficData{}, err
	}
	var state trafficData
	if err := json.Unmarshal(data, &state); err != nil {
		return trafficData{}, err
	}
	if state.Last == nil {
		state.Last = map[string]uint64{}
	}
	if state.Total == nil {
		state.Total = map[string]uint64{}
	}
	return state, nil
}

func (s *TrafficStore) saveLocked(data trafficData) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func parseTrafficCounters(raw string) map[string]uint64 {
	items := readTrafficStatItems(raw)
	out := make(map[string]uint64, len(items))
	for _, item := range items {
		if !strings.HasPrefix(item.Name, "outbound>>>") {
			continue
		}
		out[item.Name] += item.Value
	}
	return out
}

func readTrafficStatItems(raw string) []xrayStatItem {
	text := strings.TrimSpace(raw)
	if text == "" {
		return nil
	}
	var parsed struct {
		Stat []xrayStatItem `json:"stat"`
	}
	if err := json.Unmarshal([]byte(text), &parsed); err == nil {
		return parsed.Stat
	}
	matches := regexp.MustCompile(`name:\s*"([^"]+)"\s+value:\s*(\d+)`).FindAllStringSubmatch(text, -1)
	items := make([]xrayStatItem, 0, len(matches))
	for _, match := range matches {
		value, _ := strconv.ParseUint(match[2], 10, 64)
		items = append(items, xrayStatItem{Name: match[1], Value: value})
	}
	return items
}

func parseForwardCounters(raw string) map[string]uint64 {
	out := map[string]uint64{}
	re := regexp.MustCompile(`^\[\d+:(\d+)\].*--comment "vpnproxi user=([^"]+) direct-(upload|download)"`)
	for _, line := range strings.Split(raw, "\n") {
		match := re.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		bytes, _ := strconv.ParseUint(match[1], 10, 64)
		direction := "uplink"
		if match[3] == "download" {
			direction = "downlink"
		}
		name := "outbound>>>direct-" + safeTrafficTag(match[2]) + ">>>traffic>>>" + direction
		out[name] += bytes
	}
	return out
}

func encodeTrafficStats(values map[string]uint64) string {
	items := make([]xrayStatItem, 0, len(values))
	for name, value := range values {
		items = append(items, xrayStatItem{Name: name, Value: value})
	}
	raw, err := json.Marshal(map[string]any{"stat": items})
	if err != nil {
		return `{"stat":[]}`
	}
	return string(raw)
}

func safeTrafficTag(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('_')
	}
	if b.Len() == 0 {
		return "user"
	}
	return b.String()
}
