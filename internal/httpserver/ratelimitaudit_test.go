package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sched75/sealkeeper/internal/audit"
	"github.com/sched75/sealkeeper/internal/config"
)

// rateHitsMetric scrapes sealkeeper_rate_limit_hits_total{dimension=dim}.
func rateHitsMetric(t *testing.T, s *Server, dim string) string {
	t.Helper()
	w := httptest.NewRecorder()
	s.metricsHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	prefix := `sealkeeper_rate_limit_hits_total{dimension="` + dim + `"} `
	for _, line := range strings.Split(w.Body.String(), "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	return "0"
}

// summaryRows returns the actor and decoded details of every summary row.
func summaryRows(t *testing.T, db *sql.DB) (actors []string, details []map[string]any) {
	t.Helper()
	rows, err := db.QueryContext(context.Background(),
		`SELECT COALESCE(actor, ''), details_json FROM audit_log WHERE event_type = '`+audit.EventRateLimitedSummary+`' ORDER BY sequence_no`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var actor, raw string
		if err := rows.Scan(&actor, &raw); err != nil {
			t.Fatal(err)
		}
		var d map[string]any
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			t.Fatal(err)
		}
		actors = append(actors, actor)
		details = append(details, d)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return actors, details
}

// Regression (SK-05): every throttled POST /api/v1/request appended its own
// request.rate_limited row, so an unauthenticated flood grew the immutable
// audit chain (and every SIEM sink) without limit. The first hit of a key
// is still audited in full; the rest fold into one summary row per window.
func TestRateLimitedFloodFoldsIntoOneSummaryPerWindow(t *testing.T) {
	t.Parallel()
	s, _, db := newModeServer(t, config.ModeProduction, false)
	s.requestFloor = 0
	h := s.Router()
	limit := s.cfg.RateLimitIPPerHour
	const flood = 200
	for i := 0; i < limit+flood; i++ {
		postRequest(h, "203.0.113.50:1", fmt.Sprintf("u%d@example.org", i))
	}
	if n := countAudit(t, db, audit.EventRateLimited); n != 1 {
		t.Fatalf("request.rate_limited rows after %d throttled hits = %d, want 1", flood, n)
	}
	if got := rateHitsMetric(t, s, "ip"); got != fmt.Sprint(flood) {
		t.Fatalf("rate_limit_hits_total{ip} = %s, want %d (metric must stay exact)", got, flood)
	}

	ctx := context.Background()
	s.flushRateAudit(ctx)
	actors, details := summaryRows(t, db)
	if len(details) != 1 {
		t.Fatalf("summary rows = %d, want 1", len(details))
	}
	d := details[0]
	if d["suppressed"] != float64(flood-1) || d["distinct_emails"] != float64(rateAuditMaxPeers) ||
		d["distinct_emails_capped"] != true || d["overflow"] != false || d["ip_hash"] != s.hashShort("203.0.113.50") {
		t.Fatalf("summary details = %v", d)
	}
	if actors[0] != "" {
		t.Fatalf("ip summary actor = %q, want empty", actors[0])
	}

	// Nothing new since the flush: no row. A whole quiet window forgets
	// the key, so the next hit is audited in full again.
	s.flushRateAudit(ctx)
	if _, details := summaryRows(t, db); len(details) != 1 {
		t.Fatalf("empty flush wrote a summary: %d rows", len(details))
	}
	postRequest(h, "203.0.113.50:1", "late@example.org")
	if n := countAudit(t, db, audit.EventRateLimited); n != 2 {
		t.Fatalf("hit after a quiet window: %d full rows, want 2", n)
	}
	if bad, err := audit.NewRepo(db, make([]byte, audit.KeySize)).VerifyChain(ctx); err != nil || bad != 0 {
		t.Fatalf("VerifyChain = %d, %v", bad, err)
	}
}

// The email dimension keys on the targeted mailbox: a distributed flood
// against one victim yields one summary naming it and counting the IPs.
func TestRateLimitedEmailDimensionSummaryNamesTheMailbox(t *testing.T) {
	t.Parallel()
	s, _, db := newModeServer(t, config.ModeProduction, false)
	s.requestFloor = 0
	h := s.Router()
	limit := s.cfg.RateLimitEmailPerHour
	const flood = 20
	for i := 0; i < limit+flood; i++ {
		postRequest(h, fmt.Sprintf("198.51.100.%d:1", i+1), "victim+t"+fmt.Sprint(i)+"@example.org")
	}
	if n := countAudit(t, db, audit.EventRateLimited); n != 1 {
		t.Fatalf("request.rate_limited rows = %d, want 1", n)
	}
	if got := rateHitsMetric(t, s, "email"); got != fmt.Sprint(flood) {
		t.Fatalf("rate_limit_hits_total{email} = %s, want %d", got, flood)
	}
	s.flushRateAudit(context.Background())
	actors, details := summaryRows(t, db)
	if len(details) != 1 || actors[0] != "victim@example.org" ||
		details[0]["suppressed"] != float64(flood-1) || details[0]["distinct_ip_hashes"] != float64(flood-1) {
		t.Fatalf("summary actors=%v details=%v", actors, details)
	}
}

// Concurrent throttled hits: exactly one full row, the rest counted, and
// the Prometheus counter matches the number of requests exactly.
func TestRateLimitedAuditUnderConcurrency(t *testing.T) {
	t.Parallel()
	s, _, db := newModeServer(t, config.ModeProduction, false)
	s.requestFloor = 0
	h := s.Router()
	for i := 0; i < s.cfg.RateLimitIPPerHour; i++ {
		postRequest(h, "203.0.113.60:1", fmt.Sprintf("warm%d@example.org", i))
	}
	const workers, each = 32, 10
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				postRequest(h, "203.0.113.60:1", fmt.Sprintf("c%d-%d@example.org", w, i))
			}
		}()
	}
	wg.Wait()
	if got := rateHitsMetric(t, s, "ip"); got != fmt.Sprint(workers*each) {
		t.Fatalf("rate_limit_hits_total{ip} = %s, want %d", got, workers*each)
	}
	if n := countAudit(t, db, audit.EventRateLimited); n != 1 {
		t.Fatalf("request.rate_limited rows = %d, want 1", n)
	}
	s.flushRateAudit(context.Background())
	_, details := summaryRows(t, db)
	if len(details) != 1 || details[0]["suppressed"] != float64(workers*each-1) {
		t.Fatalf("summary = %v, want one with suppressed=%d", details, workers*each-1)
	}
}

// Shutdown must not lose the hits counted since the last periodic flush.
func TestRateAuditFlusherStopFlushesPendingHits(t *testing.T) {
	t.Parallel()
	s, _, db := newModeServer(t, config.ModeProduction, false)
	s.requestFloor = 0
	stop := s.startRateAuditFlusher()
	h := s.Router()
	for i := 0; i < s.cfg.RateLimitIPPerHour+3; i++ {
		postRequest(h, "203.0.113.70:1", fmt.Sprintf("s%d@example.org", i))
	}
	stop(context.Background())
	if _, details := summaryRows(t, db); len(details) != 1 || details[0]["suppressed"] != float64(2) {
		t.Fatalf("summary after stop = %v, want one with suppressed=2", details)
	}
}

// The aggregator never tracks more than maxKeys keys (+ one overflow
// bucket per dimension), however many distinct keys a flood brings, and
// still accounts for every hit.
func TestRateAuditAggIsBounded(t *testing.T) {
	t.Parallel()
	a := newRateAuditAgg(4, 2)
	var wg sync.WaitGroup
	var mu sync.Mutex
	opened := 0
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			first := a.observe(rateAuditHit{dimension: "ip", subject: fmt.Sprint("k", i), peer: fmt.Sprint("p", i)})
			if first {
				mu.Lock()
				opened++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(a.entries) != 5 || opened != 5 {
		t.Fatalf("entries=%d opened=%d, want 5 (4 keys + overflow)", len(a.entries), opened)
	}
	sums := a.drain()
	if len(sums) != 1 || sums[0].key.subject != rateAuditOverflow || sums[0].suppressed != 95 ||
		sums[0].peers != 2 || !sums[0].peersCapped {
		t.Fatalf("drain = %+v, want one overflow summary of 95 hits", sums)
	}
	// Keys idle for a whole window are forgotten; the overflow bucket that
	// counted hits stays until its own quiet window.
	if len(a.entries) != 1 {
		t.Fatalf("entries after drain = %d, want 1", len(a.entries))
	}
	if a.drain(); len(a.entries) != 0 {
		t.Fatalf("entries after a quiet window = %d, want 0", len(a.entries))
	}
}
