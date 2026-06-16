package app

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	maxLogBytes = 5 * 1024 * 1024
	maxLogFiles = 5
)

type ActivityLog struct {
	path string
	mu   sync.Mutex
	out  io.Writer
}

func NewActivityLog(path string) *ActivityLog {
	if path == "" {
		return &ActivityLog{out: os.Stderr}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		log.Printf("activity log disabled: %v", err)
		return &ActivityLog{out: os.Stderr}
	}
	return &ActivityLog{path: path}
}

func (l *ActivityLog) Event(kind, message string, fields map[string]any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.path != "" {
		l.rotateLocked()
	}
	line := fmt.Sprintf("%s kind=%s msg=%q", time.Now().UTC().Format(time.RFC3339), kind, message)
	for k, v := range fields {
		line += fmt.Sprintf(" %s=%q", sanitizeLogKey(k), fmt.Sprint(v))
	}
	line += "\n"
	if l.path == "" {
		_, _ = l.out.Write([]byte(line))
		return
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		log.Printf("activity log write failed: %v", err)
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line)
}

func (l *ActivityLog) Tail(limit int) []string {
	if limit <= 0 {
		limit = 200
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.path == "" {
		return []string{}
	}
	f, err := os.Open(l.path)
	if err != nil {
		return []string{}
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > limit {
			copy(lines, lines[len(lines)-limit:])
			lines = lines[:limit]
		}
	}
	return lines
}

func (l *ActivityLog) rotateLocked() {
	info, err := os.Stat(l.path)
	if err != nil || info.Size() < maxLogBytes {
		return
	}
	_ = os.Remove(fmt.Sprintf("%s.%d", l.path, maxLogFiles))
	for i := maxLogFiles - 1; i >= 1; i-- {
		old := fmt.Sprintf("%s.%d", l.path, i)
		next := fmt.Sprintf("%s.%d", l.path, i+1)
		if _, err := os.Stat(old); err == nil {
			_ = os.Rename(old, next)
		}
	}
	_ = os.Rename(l.path, l.path+".1")
}

func sanitizeLogKey(v string) string {
	v = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, v)
	if v == "" {
		return "field"
	}
	return v
}
