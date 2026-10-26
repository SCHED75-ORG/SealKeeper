// Package mailcapture stores outgoing mail in memory when SealKeeper runs in
// evaluation mode (FR-H.17) or as a public demo (FR-H.79). It backs the
// /__captured_mail debug endpoint that the smoke tests exercise and the
// admin console's captured-mail page.
//
// In eval mode the whole queue is visible: the evaluator is the only user.
// A public demo is shared by strangers, so each mail is tagged with an
// opaque owner handle (one per browser) and only ever shown to that owner.
package mailcapture

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Mail is a captured outbound message.
type Mail struct {
	ID        string    `json:"id"`
	To        string    `json:"to"`
	Subject   string    `json:"subject"`
	Body      string    `json:"body"`
	Timestamp time.Time `json:"timestamp"`

	// Owner is the opaque handle of the browser that caused this mail
	// (public demo). Never serialised; empty when the mail is unowned.
	Owner string `json:"-"`
}

// Store is a small thread-safe ring buffer holding the most recent N mails.
type Store struct {
	mu     sync.RWMutex
	items  []Mail
	max    int
	nextID int
}

// NewStore returns a Store retaining at most max messages.
func NewStore(max int) *Store {
	if max <= 0 {
		max = 100
	}
	return &Store{max: max, items: make([]Mail, 0, max)}
}

// Capture records an unowned mail and returns its assigned id.
func (s *Store) Capture(to, subject, body string) string {
	return s.CaptureFor("", to, subject, body)
}

// CaptureFor records a mail tagged with owner and returns its assigned id.
// Only SnapshotFor(owner) hands it to a public-demo visitor.
func (s *Store) CaptureFor(owner, to, subject, body string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	m := Mail{
		ID:        formatID(s.nextID),
		To:        to,
		Subject:   subject,
		Body:      body,
		Timestamp: time.Now().UTC(),
		Owner:     owner,
	}
	if len(s.items) >= s.max {
		copy(s.items, s.items[1:])
		s.items[len(s.items)-1] = m
	} else {
		s.items = append(s.items, m)
	}
	return m.ID
}

// Snapshot returns a copy of the current items.
func (s *Store) Snapshot() []Mail {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Mail, len(s.items))
	copy(out, s.items)
	return out
}

// SnapshotFor returns a copy of the mails tagged with owner. An empty
// owner matches nothing: unowned mail is never handed to a demo visitor.
func (s *Store) SnapshotFor(owner string) []Mail {
	out := []Mail{}
	if owner == "" {
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, m := range s.items {
		if subtle.ConstantTimeCompare([]byte(m.Owner), []byte(owner)) == 1 {
			out = append(out, m)
		}
	}
	return out
}

// Reset drops every captured mail (public-demo daily purge, FR-H.79).
func (s *Store) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.items)
	s.items = s.items[:0]
}

// PruneBefore drops the mails captured before cutoff (retention of
// captured mail, FR-I.32) and returns how many were dropped.
func (s *Store) PruneBefore(cutoff time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.items[:0]
	for _, m := range s.items {
		if !m.Timestamp.Before(cutoff) {
			kept = append(kept, m)
		}
	}
	n := len(s.items) - len(kept)
	clear(s.items[len(kept):])
	s.items = kept
	return n
}

// Handler serves the whole captured queue as JSON (eval mode only).
func (s *Store) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeItems(w, s.Snapshot())
	}
}

// ScopedHandler serves only the mails owned by the caller, as resolved by
// owner (public demo). A caller without a handle gets an empty list.
func (s *Store) ScopedHandler(owner func(*http.Request) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeItems(w, s.SnapshotFor(owner(r)))
	}
}

func writeItems(w http.ResponseWriter, items []Mail) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(struct {
		Items []Mail `json:"items"`
	}{Items: items})
}

func formatID(n int) string {
	const hex = "0123456789abcdef"
	if n == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = hex[n&0xF]
		n >>= 4
	}
	return string(buf[i:])
}
