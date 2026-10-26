package httpserver

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sched75/sealkeeper/internal/config"
	"github.com/sched75/sealkeeper/internal/domains"
)

// Regression (SK-37): an empty allowlist accepted every domain in
// production too, so a fresh instance minted reveal links — and sent mail
// through its relay — for any address on the Internet. Production must
// fail closed; eval and demo (capture sender, nothing leaves the box)
// stay zero-config.
func TestEmptyAllowlistByMode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mode   config.Mode
		demo   bool
		issued int
	}{
		{"production fails closed", config.ModeProduction, false, 0},
		{"eval stays open", config.ModeEval, false, 1},
		{"demo stays open", config.ModeProduction, true, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s, _, db := newModeServer(t, c.mode, c.demo)
			s.requestFloor = 0
			w := postRequest(s.Router(), "192.0.2.60:1000", "anyone@internet.test")
			// FR-B.13: the answer is identical whatever the outcome (eval
			// adds its debug_reveal_url on purpose).
			if w.Code != http.StatusAccepted || (!c.demo && c.mode != config.ModeEval && w.Body.String() != "{\"status\":\"accepted\"}\n") {
				t.Fatalf("status %d body %q", w.Code, w.Body.String())
			}
			if n := countAudit(t, db, "token.issued"); n != c.issued {
				t.Errorf("token.issued = %d, want %d", n, c.issued)
			}
			var blocked int
			if err := db.QueryRowContext(context.Background(),
				`SELECT COUNT(*) FROM audit_log WHERE event_type = 'request.domain_blocked'
				 AND details_json LIKE '%allowlist_empty%'`).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if want := 1 - c.issued; blocked != want {
				t.Errorf("request.domain_blocked(allowlist_empty) = %d, want %d", blocked, want)
			}
		})
	}
}

// Once a domain is listed, production admits it and still refuses the rest.
func TestProductionAllowlistAdmitsListedDomain(t *testing.T) {
	t.Parallel()
	s, _, db := newModeServer(t, config.ModeProduction, false)
	s.requestFloor = 0
	if _, err := domains.NewRepo(db).Create(context.Background(), "corp.test", "", true, nil); err != nil {
		t.Fatal(err)
	}
	h := s.Router()
	postRequest(h, "192.0.2.61:1000", "user@corp.test")
	postRequest(h, "192.0.2.62:1000", "user@internet.test")
	if n := countAudit(t, db, "token.issued"); n != 1 {
		t.Errorf("token.issued = %d, want 1", n)
	}
	if n := countAudit(t, db, "request.domain_blocked"); n != 1 {
		t.Errorf("request.domain_blocked = %d, want 1", n)
	}
}

// The dashboard tells the operator why nothing goes out in production,
// and that eval's open door does not survive the switch.
func TestDashboardSurfacesEmptyAllowlist(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mode config.Mode
		want string
		not  string
	}{
		{"production", config.ModeProduction, "every public request is refused", "every domain is accepted"},
		{"eval", config.ModeEval, "every domain is accepted", "every public request is refused"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s, repo, db := newModeServer(t, c.mode, false)
			sess := adminSessionFor(t, repo, db)
			h := s.Router()
			body := getDashboard(t, h, sess.Token)
			if !strings.Contains(body, c.want) || strings.Contains(body, c.not) {
				t.Fatalf("dashboard missing %q (or showing %q)", c.want, c.not)
			}
			if _, err := domains.NewRepo(db).Create(context.Background(), "corp.test", "", true, nil); err != nil {
				t.Fatal(err)
			}
			body = getDashboard(t, h, sess.Token)
			if strings.Contains(body, c.want) {
				t.Fatalf("dashboard still warns with a populated allowlist")
			}
		})
	}
}

// allowDomain lists `name` so a production-mode test server issues tokens
// for it — an empty allowlist refuses everything there (SK-37).
func allowDomain(t *testing.T, db *sql.DB, name string) {
	t.Helper()
	if _, err := domains.NewRepo(db).Create(context.Background(), name, "", true, nil); err != nil {
		t.Fatal(err)
	}
}

func getDashboard(t *testing.T, h http.Handler, token string) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/admin/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: cookieAdminSession, Value: token})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin/dashboard: %d", w.Code)
	}
	return w.Body.String()
}
