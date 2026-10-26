package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/audit"
	"github.com/sched75/sealkeeper/internal/tokens"
)

// auditRow is one audit_log row as the opening-attempt tests see it.
type auditRow struct {
	event, actor, target string
	details              map[string]any
}

// auditEvents lists the audit_log rows in sequence order.
func auditEvents(t *testing.T, db *sql.DB) []auditRow {
	t.Helper()
	rows, err := db.QueryContext(context.Background(),
		"SELECT event_type, COALESCE(actor, ''), COALESCE(target, ''), details_json FROM audit_log ORDER BY sequence_no")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var e auditRow
		var details string
		if err := rows.Scan(&e.event, &e.actor, &e.target, &details); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(details), &e.details); err != nil {
			t.Fatalf("details %q: %v", details, err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func openAttemptServer(t *testing.T) (*Server, *tokens.Repo, *sql.DB) {
	t.Helper()
	s, repo := newAdminServer(t)
	db := repo.DB()
	tr := tokens.NewRepo(db)
	s.SetTokens(tr)
	s.SetAudit(audit.NewRepo(db, make([]byte, audit.KeySize)))
	return s, tr, db
}

// Regression (FR-B.38): every opening attempt is audit-logged, reuses
// included. Only the successful consume used to write a row; a replayed,
// expired or unknown link left no trace in the chain or the SIEM feed.
func TestRefusedOpeningAttemptsAreAudited(t *testing.T) {
	t.Parallel()
	s, tr, db := openAttemptServer(t)
	h := s.Router()
	ctx := context.Background()

	tok, err := tr.Issue(ctx, tokens.IssueOptions{Email: "user@example.test", Domain: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	old, err := tr.WithClock(func() time.Time { return time.Now().Add(-2 * time.Hour) }).
		Issue(ctx, tokens.IssueOptions{Email: "late@example.test", Domain: "example.test"})
	if err != nil {
		t.Fatal(err)
	}

	if w := postPolicy(h, tok.Token); w.Code != http.StatusOK {
		t.Fatalf("first POST: status=%d", w.Code)
	}
	if w := postPolicy(h, tok.Token); w.Code != http.StatusGone {
		t.Fatalf("replay: status=%d, want 410", w.Code)
	}
	if w := postPolicy(h, old.Token); w.Code != http.StatusGone {
		t.Fatalf("expired: status=%d, want 410", w.Code)
	}
	if w := postPolicy(h, "no-such-token"); w.Code != http.StatusNotFound {
		t.Fatalf("unknown: status=%d, want 404", w.Code)
	}
	for _, tk := range []string{tok.Token, old.Token, "no-such-token"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/reveal/"+tk, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("reveal page %s: status=%d", tk, w.Code)
		}
	}

	type want struct{ event, actor, target, surface string }
	wants := []want{
		{audit.EventTokenConsumed, "user@example.test", tokenRef(tok.Token), ""},
		{audit.EventTokenReuseAttempt, "user@example.test", tokenRef(tok.Token), surfacePolicyAPI},
		{audit.EventTokenExpiredAttempt, "late@example.test", tokenRef(old.Token), surfacePolicyAPI},
		{audit.EventTokenUnknownAttempt, "", tokenRef("no-such-token"), surfacePolicyAPI},
		{audit.EventTokenReuseAttempt, "user@example.test", tokenRef(tok.Token), surfaceRevealPage},
		{audit.EventTokenExpiredAttempt, "late@example.test", tokenRef(old.Token), surfaceRevealPage},
		{audit.EventTokenUnknownAttempt, "", tokenRef("no-such-token"), surfaceRevealPage},
	}
	got := auditEvents(t, db)
	if len(got) != len(wants) {
		var names []string
		for _, e := range got {
			names = append(names, e.event)
		}
		t.Fatalf("audit events = %v, want %d rows", names, len(wants))
	}
	for i, w := range wants {
		e := got[i]
		if e.event != w.event || e.actor != w.actor || e.target != w.target {
			t.Errorf("row %d = (%s, %q, %q), want (%s, %q, %q)", i, e.event, e.actor, e.target, w.event, w.actor, w.target)
		}
		if w.surface != "" && e.details["surface"] != w.surface {
			t.Errorf("row %d details %v: surface != %s", i, e.details, w.surface)
		}
		if e.details["ip_hash"] == nil || e.details["ua_hash"] == nil {
			t.Errorf("row %d details %v lack ip_hash / ua_hash", i, e.details)
		}
		if raw, _ := json.Marshal(e.details); strings.Contains(string(raw), tok.Token) || strings.Contains(string(raw), old.Token) {
			t.Errorf("row %d details leak a raw token: %s", i, raw)
		}
	}
}

// Unknown-token probes are throttled per client before they reach the
// audit log: one IP brute-forcing the token space must not be able to
// flood the hash chain and the SIEM feed.
func TestUnknownTokenAttemptsCannotFloodAudit(t *testing.T) {
	t.Parallel()
	s, _, db := openAttemptServer(t)
	h := s.Router()
	for i := 0; i < tokenLookupPerIPWindow; i++ {
		if w := postPolicy(h, "probe-"+strings.Repeat("x", i)); w.Code != http.StatusNotFound {
			t.Fatalf("probe %d: status=%d, want 404", i, w.Code)
		}
	}
	got := 0
	for _, e := range auditEvents(t, db) {
		if e.event == audit.EventTokenUnknownAttempt {
			got++
		}
	}
	if got != unknownAttemptAuditPerIPWindow {
		t.Fatalf("%d token.unknown_attempt rows for %d probes, want %d", got, tokenLookupPerIPWindow, unknownAttemptAuditPerIPWindow)
	}
}
