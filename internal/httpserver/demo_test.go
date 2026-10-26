package httpserver

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/admin"
	"github.com/sched75/sealkeeper/internal/audit"
	"github.com/sched75/sealkeeper/internal/branding"
	"github.com/sched75/sealkeeper/internal/config"
	"github.com/sched75/sealkeeper/internal/cryptobox"
	"github.com/sched75/sealkeeper/internal/domains"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
	"github.com/sched75/sealkeeper/internal/tokens"
)

// newModeServer builds a fully wired server for the given run mode.
func newModeServer(t *testing.T, mode config.Mode, demo bool) (*Server, *admin.Repo, *sql.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := storage.Open(ctx, storage.Options{DSN: storagetest.DSN(t)})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	if err := st.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	box, err := cryptobox.New(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Mode = mode
	cfg.DemoMode = demo
	cfg.BaseURL = "http://sk.test"
	cfg.InstanceDomain = "sk.test"
	s := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	db := st.DB()
	repo := admin.NewRepo(db, box)
	s.SetAdmin(repo, "test")
	s.SetTokens(tokens.NewRepo(db))
	s.SetAudit(audit.NewRepo(db))
	s.SetBranding(branding.NewRepo(db))
	s.SetDomains(domains.NewRepo(db))
	return s, repo, db
}

// adminSessionFor creates an admin that has completed setup and a session.
func adminSessionFor(t *testing.T, repo *admin.Repo, db *sql.DB) admin.Session {
	t.Helper()
	ctx := context.Background()
	a, err := repo.Create(ctx, "ops@example.test", "supersecret-12chars")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, storage.Rebind(db,
		`UPDATE admins SET force_password_change = ?, force_totp_enroll = ? WHERE id = ?`), false, false, a.ID); err != nil {
		t.Fatal(err)
	}
	sess, err := repo.CreateSession(ctx, a.ID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

func adminPOST(h http.Handler, sess admin.Session, path string, form url.Values) *httptest.ResponseRecorder {
	form.Set("csrf_token", sess.CSRFToken)
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: cookieAdminSession, Value: sess.Token})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// Regression (SK-24): in demo mode the account, admins, branding and
// security-key mutations were accepted and survived the 24h reset.
func TestDemoRefusesAdminMutationsOutsideTheDemoStory(t *testing.T) {
	t.Parallel()
	s, repo, db := newModeServer(t, config.ModeProduction, true)
	sess := adminSessionFor(t, repo, db)
	h := s.Router()

	refused := []struct {
		path string
		form url.Values
	}{
		{"/admin/branding/save", url.Values{"instance_name": {"HACKED demo"}, "primary_color": {"#000000"}, "secondary_color": {"#000000"}, "tertiary_color": {"#000000"}}},
		{"/admin/branding/logo/clear", url.Values{}},
		{"/admin/account/password", url.Values{"current_password": {"supersecret-12chars"}, "new_password": {"x"}}},
		{"/admin/account/email", url.Values{"email": {"evil@example.test"}}},
		{"/admin/admins/1/toggle", url.Values{}},
		{"/admin/admins/1/delete", url.Values{}},
		{"/admin/security/1/delete", url.Values{}},
		{"/admin/smtp/test", url.Values{}},
		{"/admin/libraries/1/delete", url.Values{}},
		{"/admin/integrations/1/test", url.Values{}},
	}
	for _, c := range refused {
		w := adminPOST(h, sess, c.path, c.form)
		section, _, _ := strings.Cut(strings.TrimPrefix(c.path, "/admin/"), "/")
		want := "/admin/" + section + "?err=demo_readonly"
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != want {
			t.Errorf("POST %s: %d %q, want 303 %q", c.path, w.Code, w.Header().Get("Location"), want)
		}
	}
	if w := adminPOST(h, sess, "/admin/security/begin", url.Values{}); w.Code != http.StatusForbidden {
		t.Errorf("POST /admin/security/begin: %d, want 403", w.Code)
	}

	b, err := branding.NewRepo(db).Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if b.InstanceName == "HACKED demo" {
		t.Error("branding changed on the public demo")
	}

	// The demo story itself stays writable.
	w := adminPOST(h, sess, "/admin/domains/add", url.Values{"name": {"example.test"}, "active": {"on"}})
	if strings.Contains(w.Header().Get("Location"), "demo_readonly") || w.Code != http.StatusSeeOther {
		t.Errorf("POST /admin/domains/add on demo: %d %q, want it accepted", w.Code, w.Header().Get("Location"))
	}
}

func TestDemoGuardIsNoOpOutsideDemo(t *testing.T) {
	t.Parallel()
	s, repo, db := newModeServer(t, config.ModeProduction, false)
	sess := adminSessionFor(t, repo, db)
	w := adminPOST(s.Router(), sess, "/admin/branding/save", url.Values{
		"instance_name": {"Renamed"}, "primary_color": {"#7A1F2B"}, "secondary_color": {"#C9A961"}, "tertiary_color": {"#1A1814"},
	})
	if loc := w.Header().Get("Location"); loc != "/admin/branding?ok=saved" {
		t.Fatalf("branding save outside demo: %d %q", w.Code, loc)
	}
}

type capturedItems struct {
	Items []struct {
		To   string `json:"to"`
		Body string `json:"body"`
	} `json:"items"`
}

func postRequest(h http.Handler, remote, email string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/request", strings.NewReader(`{"email":"`+email+`"}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = remote
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func getCaptured(t *testing.T, h http.Handler, cookies ...*http.Cookie) (int, capturedItems) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/__captured_mail", nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out capturedItems
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, w.Body.String())
		}
	}
	return w.Code, out
}

func captureCookie(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieDemoCapture {
			return c
		}
	}
	t.Fatalf("no %s cookie on the response", cookieDemoCapture)
	return nil
}

// Regression (SK-24): /__captured_mail handed every requester's address
// and live reveal link to any anonymous caller, also with SK_MODE=production
// when the demo flag was on.
func TestDemoCapturedMailIsScopedToTheRequester(t *testing.T) {
	t.Parallel()
	s, _, _ := newModeServer(t, config.ModeProduction, true)
	s.requestFloor = 0
	h := s.Router()

	alice := postRequest(h, "192.0.2.1:1000", "alice@example.test")
	if alice.Code != http.StatusAccepted {
		t.Fatalf("alice request: %d", alice.Code)
	}
	aliceCookie := captureCookie(t, alice)
	if !aliceCookie.HttpOnly {
		t.Error("capture cookie is readable by scripts")
	}
	bob := postRequest(h, "192.0.2.2:1000", "bob@example.test")
	bobCookie := captureCookie(t, bob)

	if code, got := getCaptured(t, h); code != http.StatusOK || len(got.Items) != 0 {
		t.Fatalf("anonymous caller: %d, %d items (want 200, none)", code, len(got.Items))
	}
	_, got := getCaptured(t, h, aliceCookie)
	if len(got.Items) != 1 || got.Items[0].To != "alice@example.test" || !strings.Contains(got.Items[0].Body, "/reveal/") {
		t.Fatalf("alice sees %+v, want only her own reveal mail", got.Items)
	}
	_, got = getCaptured(t, h, bobCookie)
	if len(got.Items) != 1 || got.Items[0].To != "bob@example.test" {
		t.Fatalf("bob sees %+v, want only his own mail", got.Items)
	}

	// A returning browser keeps its handle.
	again := postRequest(h, "192.0.2.3:1000", "alice2@example.test", aliceCookie)
	if c := captureCookie(t, again); c.Value != aliceCookie.Value {
		t.Error("capture handle rotated for a returning browser")
	}
}

func TestCapturedMailExposure(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		mode     config.Mode
		demo     bool
		wantCode int
	}{
		{"production", config.ModeProduction, false, http.StatusNotFound},
		{"eval", config.ModeEval, false, http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s, _, _ := newModeServer(t, c.mode, c.demo)
			s.requestFloor = 0
			h := s.Router()
			postRequest(h, "192.0.2.1:1000", "eve@example.test")
			code, got := getCaptured(t, h)
			if code != c.wantCode {
				t.Fatalf("GET /__captured_mail: %d, want %d", code, c.wantCode)
			}
			if c.mode == config.ModeEval && len(got.Items) != 1 {
				t.Fatalf("eval queue: %d items, want the full queue (1)", len(got.Items))
			}
		})
	}
}
