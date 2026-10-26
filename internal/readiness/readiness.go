// Package readiness aggregates subsystem health checks for /readyz (FR-D.50).
//
// /healthz answers as soon as the process is alive; /readyz only flips to 200
// once every registered Checker reports nil. This package keeps the contract
// simple and dependency-free so any subsystem (DB, migrations, config) can
// plug in.
package readiness

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Checker is a named readiness check.
type Checker interface {
	Name() string
	Check(ctx context.Context) error
}

// Set is a collection of Checkers that can serve /readyz.
type Set struct {
	mu       sync.RWMutex
	checkers []Checker
}

// New returns an empty Set.
func New(initial ...Checker) *Set { return &Set{checkers: append([]Checker(nil), initial...)} }

// Add registers a Checker.
func (s *Set) Add(c Checker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkers = append(s.checkers, c)
}

// Status is the JSON body returned by /readyz.
type Status struct {
	Status     string            `json:"status"` // "ok" or "degraded"
	Subsystems map[string]string `json:"subsystems"`
}

// Handler returns an http.HandlerFunc serving /readyz. The handler runs all
// checks in parallel with the given per-check timeout.
func (s *Set) Handler(perCheckTimeout time.Duration) http.HandlerFunc {
	if perCheckTimeout <= 0 {
		perCheckTimeout = 2 * time.Second
	}
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		checkers := append([]Checker(nil), s.checkers...)
		s.mu.RUnlock()

		result := Status{Status: "ok", Subsystems: make(map[string]string, len(checkers))}

		var wg sync.WaitGroup
		var mu sync.Mutex
		for _, c := range checkers {
			wg.Add(1)
			go func(c Checker) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(r.Context(), perCheckTimeout)
				defer cancel()
				err := c.Check(ctx)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					// The error text (DB user, host:port, database name)
					// goes to the log, not to the unauthenticated caller.
					slog.Warn("readiness check failed", "subsystem", c.Name(), "err", err)
					result.Status = "degraded"
					result.Subsystems[c.Name()] = "unavailable"
				} else {
					result.Subsystems[c.Name()] = "ok"
				}
			}(c)
		}
		wg.Wait()

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if result.Status == "ok" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(result)
	}
}
